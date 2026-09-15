import os, sqlite3, secrets, hashlib, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import jwt, requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from passlib.context import CryptContext

BASE = Path(__file__).resolve().parent.parent
DB = Path(os.getenv('NOVATRADE_DB', str(BASE / 'novatrade.db')))
JWT_SECRET = os.getenv('JWT_SECRET', 'change-this-in-production-' + secrets.token_urlsafe(24))
UPSTOX_CLIENT_ID = os.getenv('UPSTOX_CLIENT_ID', '')
UPSTOX_CLIENT_SECRET = os.getenv('UPSTOX_CLIENT_SECRET', '')
UPSTOX_REDIRECT_URI = os.getenv('UPSTOX_REDIRECT_URI', '')
LIVE_TRADING_ENABLED = os.getenv('LIVE_TRADING_ENABLED', 'false').lower() == 'true'

pwd = CryptContext(schemes=['bcrypt'], deprecated='auto')
app = FastAPI(title='NovaTrade', version='2.0')
app.mount('/static', StaticFiles(directory=str(BASE / 'frontend')), name='static')

STOCKS = {
    'RELIANCE': {'name':'Reliance Industries', 'exchange':'NSE', 'price':1428.0},
    'TCS': {'name':'Tata Consultancy Services', 'exchange':'NSE', 'price':3125.0},
    'INFY': {'name':'Infosys', 'exchange':'NSE', 'price':1510.0},
    'HDFCBANK': {'name':'HDFC Bank', 'exchange':'NSE', 'price':962.0},
    'ICICIBANK': {'name':'ICICI Bank', 'exchange':'NSE', 'price':1385.0},
    'SBIN': {'name':'State Bank of India', 'exchange':'NSE', 'price':820.0},
    'ITC': {'name':'ITC', 'exchange':'NSE', 'price':411.0},
    'BHARTIARTL': {'name':'Bharti Airtel', 'exchange':'NSE', 'price':1812.0},
    'WIPRO': {'name':'Wipro', 'exchange':'NSE', 'price':246.0},
    'LT': {'name':'Larsen & Toubro', 'exchange':'NSE', 'price':3890.0},
}


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS portfolios(user_id INTEGER PRIMARY KEY, cash REAL NOT NULL DEFAULT 100000, starting_cash REAL NOT NULL DEFAULT 100000);
    CREATE TABLE IF NOT EXISTS holdings(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, symbol TEXT NOT NULL, qty INTEGER NOT NULL, avg_price REAL NOT NULL, UNIQUE(user_id,symbol));
    CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, symbol TEXT NOT NULL, side TEXT NOT NULL, qty INTEGER NOT NULL, order_type TEXT NOT NULL, price REAL NOT NULL, status TEXT NOT NULL, broker_order_id TEXT, mode TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS broker_tokens(user_id INTEGER PRIMARY KEY, access_token TEXT NOT NULL, expires_at TEXT, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS bot(user_id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, symbol TEXT NOT NULL DEFAULT 'RELIANCE', risk_pct REAL NOT NULL DEFAULT 1.0, stop_pct REAL NOT NULL DEFAULT 2.0, target_pct REAL NOT NULL DEFAULT 4.0, mode TEXT NOT NULL DEFAULT 'paper');
    ''')
    return con


def token_for(user_id):
    return jwt.encode({'sub': user_id, 'exp': datetime.now(timezone.utc)+timedelta(hours=24)}, JWT_SECRET, algorithm='HS256')

def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(401, 'Login required')
    try:
        p = jwt.decode(authorization.split(' ',1)[1], JWT_SECRET, algorithms=['HS256'])
        return int(p['sub'])
    except Exception:
        raise HTTPException(401, 'Invalid or expired session')

def price(symbol):
    s = symbol.upper()
    if s not in STOCKS: raise HTTPException(404, 'Unknown symbol')
    # Deterministic small movement for a stable demo; broker integration is used for live execution.
    base = STOCKS[s]['price']
    tick = ((int(time.time()) // 5) % 21 - 10) / 1000
    return round(base * (1 + tick), 2)

def portfolio(con, uid):
    p = con.execute('SELECT * FROM portfolios WHERE user_id=?',(uid,)).fetchone()
    hs = con.execute('SELECT * FROM holdings WHERE user_id=?',(uid,)).fetchall()
    value = sum(h['qty']*price(h['symbol']) for h in hs)
    return {'cash':round(p['cash'],2),'holdings_value':round(value,2),'equity':round(p['cash']+value,2),'starting_cash':p['starting_cash']}

class Auth(BaseModel):
    email: str
    password: str = Field(min_length=6)
    name: str = 'Trader'
class Order(BaseModel):
    symbol: str
    side: str
    qty: int = Field(gt=0)
    order_type: str = 'MARKET'
    limit_price: Optional[float] = None
    mode: str = 'paper'
class BotConfig(BaseModel):
    enabled: bool
    symbol: str = 'RELIANCE'
    risk_pct: float = Field(default=1.0, ge=0.1, le=5)
    stop_pct: float = Field(default=2.0, ge=0.5, le=20)
    target_pct: float = Field(default=4.0, ge=0.5, le=50)
    mode: str = 'paper'

@app.get('/')
def root(): return FileResponse(BASE/'frontend'/'index.html')
@app.get('/api/health')
def health(): return {'ok':True,'service':'NovaTrade','live_trading_enabled':LIVE_TRADING_ENABLED}

@app.post('/api/auth/signup')
def signup(a: Auth):
    con=db()
    try:
        cur=con.execute('INSERT INTO users(email,password,name,created_at) VALUES(?,?,?,?)',(a.email.lower().strip(),pwd.hash(a.password),a.name.strip() or 'Trader',datetime.now(timezone.utc).isoformat()))
        uid=cur.lastrowid
        con.execute('INSERT INTO portfolios(user_id) VALUES(?)',(uid,)); con.execute('INSERT INTO bot(user_id) VALUES(?)',(uid,)); con.commit()
    except sqlite3.IntegrityError: raise HTTPException(409,'Email already registered')
    return {'token':token_for(uid),'user':{'id':uid,'email':a.email.lower(),'name':a.name}}

@app.post('/api/auth/login')
def login(a: Auth):
    con=db(); u=con.execute('SELECT * FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
    if not u or not pwd.verify(a.password,u['password']): raise HTTPException(401,'Invalid email or password')
    return {'token':token_for(u['id']),'user':{'id':u['id'],'email':u['email'],'name':u['name']}}

@app.get('/api/me')
def me(uid:int=Depends(current_user)):
    con=db(); u=con.execute('SELECT id,email,name FROM users WHERE id=?',(uid,)).fetchone(); return dict(u)

@app.get('/api/stocks')
def stocks(q:str=''):
    q=q.upper(); out=[]
    for sym,v in STOCKS.items():
        if not q or q in sym or q in v['name'].upper(): out.append({'symbol':sym,**v,'price':price(sym)})
    return out

@app.get('/api/stock/{symbol}')
def stock(symbol:str):
    s=symbol.upper(); v=STOCKS.get(s)
    if not v: raise HTTPException(404,'Unknown symbol')
    p=price(s); return {'symbol':s,**v,'price':p,'change':round(p-v['price'],2),'change_pct':round((p/v['price']-1)*100,2)}

@app.get('/api/portfolio')
def get_portfolio(uid:int=Depends(current_user)):
    con=db(); x=portfolio(con,uid); hs=con.execute('SELECT symbol,qty,avg_price FROM holdings WHERE user_id=?',(uid,)).fetchall();
    x['pnl']=round(x['equity']-x['starting_cash'],2); x['holdings']=[{**dict(h),'price':price(h['symbol']),'value':round(h['qty']*price(h['symbol']),2)} for h in hs]; return x

@app.get('/api/orders')
def orders(uid:int=Depends(current_user)):
    con=db(); return [dict(x) for x in con.execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100',(uid,)).fetchall()]

def paper_order(con,uid,o):
    s=o.symbol.upper(); p=price(s); exec_price=o.limit_price if o.order_type.upper()=='LIMIT' and o.limit_price else p
    side=o.side.upper();
    if side not in ('BUY','SELL'): raise HTTPException(400,'Side must be BUY or SELL')
    port=con.execute('SELECT * FROM portfolios WHERE user_id=?',(uid,)).fetchone(); h=con.execute('SELECT * FROM holdings WHERE user_id=? AND symbol=?',(uid,s)).fetchone()
    cost=exec_price*o.qty
    if side=='BUY':
        if port['cash']<cost: raise HTTPException(400,'Insufficient paper cash')
        if h:
            newqty=h['qty']+o.qty; avg=(h['qty']*h['avg_price']+cost)/newqty; con.execute('UPDATE holdings SET qty=?,avg_price=? WHERE id=?',(newqty,avg,h['id']))
        else: con.execute('INSERT INTO holdings(user_id,symbol,qty,avg_price) VALUES(?,?,?,?)',(uid,s,o.qty,exec_price))
        con.execute('UPDATE portfolios SET cash=cash-? WHERE user_id=?',(cost,uid))
    else:
        if not h or h['qty']<o.qty: raise HTTPException(400,'Insufficient shares')
        rem=h['qty']-o.qty
        if rem: con.execute('UPDATE holdings SET qty=? WHERE id=?',(rem,h['id']))
        else: con.execute('DELETE FROM holdings WHERE id=?',(h['id'],))
        con.execute('UPDATE portfolios SET cash=cash+? WHERE user_id=?',(cost,uid))
    con.execute('INSERT INTO orders(user_id,symbol,side,qty,order_type,price,status,mode,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(uid,s,side,o.qty,o.order_type.upper(),exec_price,'FILLED','paper',datetime.now(timezone.utc).isoformat()))
    con.commit(); return {'status':'FILLED','price':exec_price,'mode':'paper'}

def upstox_order(uid,o):
    con=db(); row=con.execute('SELECT access_token FROM broker_tokens WHERE user_id=?',(uid,)).fetchone()
    if not row: raise HTTPException(400,'Connect your Upstox account first')
    # Instrument lookup is broker-specific. This build accepts an instrument token through symbol syntax: TOKEN:<token>.
    if not o.symbol.startswith('TOKEN:'): raise HTTPException(400,'For live orders, use TOKEN:<Upstox instrument_token> or add an instrument master mapping.')
    instrument=o.symbol[6:]; payload={'quantity':o.qty,'product':'D','validity':'DAY','price':o.limit_price or 0,'tag':'novatrade','instrument_token':instrument,'order_type':o.order_type.upper(),'transaction_type':o.side.upper(),'disclosed_quantity':0,'trigger_price':0,'is_amo':False,'market_protection':-1}
    r=requests.post('https://api-hft.upstox.com/v2/order/place',json=payload,headers={'Authorization':'Bearer '+row['access_token'],'Accept':'application/json','Content-Type':'application/json'},timeout=15)
    if r.status_code>=400: raise HTTPException(r.status_code, 'Broker rejected order: '+r.text[:300])
    data=r.json(); oid=str(data.get('data',{}).get('order_id',''))
    con.execute('INSERT INTO orders(user_id,symbol,side,qty,order_type,price,status,broker_order_id,mode,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(uid,o.symbol,o.side.upper(),o.qty,o.order_type.upper(),o.limit_price or 0,'SUBMITTED',oid,'live',datetime.now(timezone.utc).isoformat())); con.commit(); return {'status':'SUBMITTED','broker_order_id':oid,'mode':'live'}

@app.post('/api/orders')
def create_order(o:Order,uid:int=Depends(current_user)):
    if o.mode=='live':
        if not LIVE_TRADING_ENABLED: raise HTTPException(403,'Live trading is disabled on this deployment')
        return upstox_order(uid,o)
    con=db(); return paper_order(con,uid,o)

@app.get('/api/bot')
def get_bot(uid:int=Depends(current_user)):
    con=db(); return dict(con.execute('SELECT * FROM bot WHERE user_id=?',(uid,)).fetchone())
@app.post('/api/bot')
def set_bot(b:BotConfig,uid:int=Depends(current_user)):
    if b.mode=='live' and not LIVE_TRADING_ENABLED: raise HTTPException(403,'Live bot is disabled')
    con=db(); con.execute('UPDATE bot SET enabled=?,symbol=?,risk_pct=?,stop_pct=?,target_pct=?,mode=? WHERE user_id=?',(int(b.enabled),b.symbol.upper(),b.risk_pct,b.stop_pct,b.target_pct,b.mode,uid)); con.commit(); return get_bot(uid)

@app.get('/api/broker/upstox/connect')
def connect_upstox(uid:int=Depends(current_user)):
    if not UPSTOX_CLIENT_ID or not UPSTOX_REDIRECT_URI: raise HTTPException(503,'Upstox credentials are not configured')
    state=token_for(uid); url='https://api.upstox.com/v2/login/authorization/dialog?response_type=code&client_id='+requests.utils.quote(UPSTOX_CLIENT_ID)+'&redirect_uri='+requests.utils.quote(UPSTOX_REDIRECT_URI)+'&state='+requests.utils.quote(state)
    return {'url':url}

@app.get('/api/broker/upstox/callback')
def upstox_callback(code:str,state:str):
    try: uid=int(jwt.decode(state,JWT_SECRET,algorithms=['HS256'])['sub'])
    except Exception: raise HTTPException(400,'Invalid OAuth state')
    r=requests.post('https://api.upstox.com/v2/login/authorization/token',data={'code':code,'client_id':UPSTOX_CLIENT_ID,'client_secret':UPSTOX_CLIENT_SECRET,'redirect_uri':UPSTOX_REDIRECT_URI,'grant_type':'authorization_code'},timeout=15)
    if r.status_code>=400: raise HTTPException(r.status_code,'Upstox authorization failed')
    access=r.json().get('access_token'); con=db(); con.execute('INSERT OR REPLACE INTO broker_tokens(user_id,access_token,expires_at,updated_at) VALUES(?,?,?,?)',(uid,access,None,datetime.now(timezone.utc).isoformat())); con.commit()
    return RedirectResponse('/')

@app.get('/api/broker/status')
def broker_status(uid:int=Depends(current_user)):
    con=db(); x=con.execute('SELECT updated_at FROM broker_tokens WHERE user_id=?',(uid,)).fetchone(); return {'connected':bool(x),'updated_at':x['updated_at'] if x else None,'live_enabled':LIVE_TRADING_ENABLED}

@app.post('/api/reset-paper')
def reset_paper(uid:int=Depends(current_user)):
    con=db(); con.execute('UPDATE portfolios SET cash=starting_cash WHERE user_id=?',(uid,)); con.execute('DELETE FROM holdings WHERE user_id=?',(uid,)); con.execute("DELETE FROM orders WHERE user_id=? AND mode='paper'",(uid,)); con.commit(); return {'ok':True}
