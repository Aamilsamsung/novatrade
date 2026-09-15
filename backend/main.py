import os, sqlite3, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
import jwt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from passlib.context import CryptContext

ROOT=Path(__file__).resolve().parent.parent
DB=Path(os.getenv('NOVATRADE_DB',str(ROOT/'novatrade.db')))
SECRET=os.getenv('JWT_SECRET','novatrade-demo-secret-change-me')
pwd=CryptContext(schemes=['bcrypt'],deprecated='auto')
app=FastAPI(title='NovaTrade',version='3.0')
app.mount('/static',StaticFiles(directory=str(ROOT/'frontend')),name='static')
STOCKS={'RELIANCE':('Reliance Industries',1428),'TCS':('Tata Consultancy Services',3125),'INFY':('Infosys',1510),'HDFCBANK':('HDFC Bank',962),'ICICIBANK':('ICICI Bank',1385),'SBIN':('State Bank of India',820),'ITC':('ITC',411),'BHARTIARTL':('Bharti Airtel',1812),'WIPRO':('Wipro',246),'LT':('Larsen & Toubro',3890)}

def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,name TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS portfolios(user_id INTEGER PRIMARY KEY,cash REAL,starting_cash REAL);CREATE TABLE IF NOT EXISTS holdings(user_id INTEGER,symbol TEXT,qty INTEGER,avg_price REAL,PRIMARY KEY(user_id,symbol));CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id INTEGER,symbol TEXT,side TEXT,qty INTEGER,price REAL,status TEXT,mode TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS bots(user_id INTEGER PRIMARY KEY,enabled INTEGER,symbol TEXT,risk REAL,stop REAL,target REAL);''');return c

def token(uid): return jwt.encode({'sub':uid,'exp':datetime.now(timezone.utc)+timedelta(days=1)},SECRET,algorithm='HS256')
def uid(auth:Optional[str]=Header(None)):
 if not auth or not auth.lower().startswith('bearer '): raise HTTPException(401,'Login required')
 try:return int(jwt.decode(auth.split(' ',1)[1],SECRET,algorithms=['HS256'])['sub'])
 except:raise HTTPException(401,'Invalid session')
def px(s):
 s=s.upper()
 if s not in STOCKS: raise HTTPException(404,'Unknown stock')
 base=STOCKS[s][1]; move=((int(time.time())//5)%21-10)/1000;return round(base*(1+move),2)
class Auth(BaseModel): email:str;password:str=Field(min_length=6);name:str='Trader'
class Order(BaseModel):symbol:str;side:str;qty:int=Field(gt=0);mode:str='paper'
class Bot(BaseModel):enabled:bool;symbol:str='RELIANCE';risk:float=Field(1,ge=.1,le=5);stop:float=Field(2,ge=.5,le=20);target:float=Field(4,ge=.5,le=50)
@app.get('/')
def home():return FileResponse(ROOT/'frontend'/'index.html')
@app.get('/api/health')
def health():return {'ok':True,'service':'NovaTrade','mode':'paper'}
@app.post('/api/auth/signup')
def signup(a:Auth):
 c=db()
 try:
  cur=c.execute('INSERT INTO users(email,password,name,created_at) VALUES(?,?,?,?)',(a.email.lower().strip(),pwd.hash(a.password),a.name.strip() or 'Trader',datetime.now(timezone.utc).isoformat()));u=cur.lastrowid;c.execute('INSERT INTO portfolios VALUES(?,?,?)',(u,100000,100000));c.execute('INSERT INTO bots VALUES(?,?,?,?,?,?)',(u,0,'RELIANCE',1,2,4));c.commit();return {'token':token(u),'user':{'id':u,'name':a.name}}
 except sqlite3.IntegrityError:raise HTTPException(409,'Email already registered')
@app.post('/api/auth/login')
def login(a:Auth):
 c=db();r=c.execute('SELECT * FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
 if not r or not pwd.verify(a.password,r['password']):raise HTTPException(401,'Invalid email or password')
 return {'token':token(r['id']),'user':{'id':r['id'],'name':r['name']}}
@app.get('/api/me')
def me(u:int=Depends(uid)):
 r=db().execute('SELECT id,email,name FROM users WHERE id=?',(u,)).fetchone();return dict(r)
@app.get('/api/stocks')
def stocks(q:str=''):
 q=q.upper();return [{'symbol':s,'name':v[0],'exchange':'NSE','price':px(s)} for s,v in STOCKS.items() if not q or q in s or q in v[0].upper()]
@app.get('/api/portfolio')
def portfolio(u:int=Depends(uid)):
 c=db();p=c.execute('SELECT * FROM portfolios WHERE user_id=?',(u,)).fetchone();hs=c.execute('SELECT * FROM holdings WHERE user_id=?',(u,)).fetchall();iv=sum(h['qty']*px(h['symbol']) for h in hs);eq=p['cash']+iv;return {'cash':round(p['cash'],2),'holdings_value':round(iv,2),'equity':round(eq,2),'pnl':round(eq-p['starting_cash'],2),'holdings':[{'symbol':h['symbol'],'qty':h['qty'],'avg_price':h['avg_price'],'price':px(h['symbol'])} for h in hs]}
@app.get('/api/orders')
def orders(u:int=Depends(uid)):return [dict(r) for r in db().execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100',(u,)).fetchall()]
@app.post('/api/orders')
def order(o:Order,u:int=Depends(uid)):
 if o.mode!='paper':raise HTTPException(403,'Live trading is disabled. NovaTrade is paper-only.')
 s=o.symbol.upper();p=px(s);side=o.side.upper();c=db();port=c.execute('SELECT * FROM portfolios WHERE user_id=?',(u,)).fetchone();h=c.execute('SELECT * FROM holdings WHERE user_id=? AND symbol=?',(u,s)).fetchone();cost=p*o.qty
 if side=='BUY':
  if port['cash']<cost:raise HTTPException(400,'Insufficient paper cash')
  if h:
   nq=h['qty']+o.qty;c.execute('UPDATE holdings SET qty=?,avg_price=? WHERE user_id=? AND symbol=?',(nq,(h['qty']*h['avg_price']+cost)/nq,u,s))
  else:c.execute('INSERT INTO holdings VALUES(?,?,?,?)',(u,s,o.qty,p))
  c.execute('UPDATE portfolios SET cash=cash-? WHERE user_id=?',(cost,u))
 elif side=='SELL':
  if not h or h['qty']<o.qty:raise HTTPException(400,'Insufficient shares')
  nq=h['qty']-o.qty
  if nq:c.execute('UPDATE holdings SET qty=? WHERE user_id=? AND symbol=?',(nq,u,s))
  else:c.execute('DELETE FROM holdings WHERE user_id=? AND symbol=?',(u,s))
  c.execute('UPDATE portfolios SET cash=cash+? WHERE user_id=?',(cost,u))
 else:raise HTTPException(400,'Side must be BUY or SELL')
 c.execute('INSERT INTO orders(user_id,symbol,side,qty,price,status,mode,created_at) VALUES(?,?,?,?,?,?,?,?)',(u,s,side,o.qty,p,'FILLED','paper',datetime.now(timezone.utc).isoformat()));c.commit();return {'status':'FILLED','price':p,'mode':'paper'}
@app.get('/api/bot')
def getbot(u:int=Depends(uid)):return dict(db().execute('SELECT * FROM bots WHERE user_id=?',(u,)).fetchone())
@app.post('/api/bot')
def setbot(b:Bot,u:int=Depends(uid)):
 c=db();s=b.symbol.upper();
 if s not in STOCKS:raise HTTPException(400,'Unknown bot symbol')
 c.execute('UPDATE bots SET enabled=?,symbol=?,risk=?,stop=?,target=? WHERE user_id=?',(int(b.enabled),s,b.risk,b.stop,b.target,u));c.commit();return getbot(u)
@app.post('/api/reset-paper')
def reset(u:int=Depends(uid)):
 c=db();c.execute('UPDATE portfolios SET cash=starting_cash WHERE user_id=?',(u,));c.execute('DELETE FROM holdings WHERE user_id=?',(u,));c.execute("DELETE FROM orders WHERE user_id=? AND mode='paper'",(u,));c.commit();return {'ok':True}
