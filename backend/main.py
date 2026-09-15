import os,sqlite3,time,hashlib,secrets,smtplib
from pathlib import Path
from datetime import datetime,timezone,timedelta
from email.message import EmailMessage
from typing import Optional
import requests,jwt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi import FastAPI,HTTPException,Depends,Header
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field,EmailStr
from passlib.context import CryptContext
ROOT=Path(__file__).resolve().parent.parent;DB=Path(os.getenv('NOVATRADE_DB',str(ROOT/'novatrade.db')));SECRET=os.getenv('JWT_SECRET','novatrade-demo-secret-change-me');BASE_URL=os.getenv('APP_BASE_URL','https://novatrade-p49i.onrender.com').rstrip('/');GOOGLE_CLIENT_ID=os.getenv('GOOGLE_CLIENT_ID','').strip();pwd=CryptContext(schemes=['bcrypt'],deprecated='auto');app=FastAPI(title='NovaTrade',version='6.1');app.mount('/static',StaticFiles(directory=str(ROOT/'frontend')),name='static');STOCKS={'RELIANCE':('Reliance Industries',1428),'TCS':('Tata Consultancy Services',3125),'INFY':('Infosys',1510),'HDFCBANK':('HDFC Bank',962),'ICICIBANK':('ICICI Bank',1385),'SBIN':('State Bank of India',820),'ITC':('ITC',411),'BHARTIARTL':('Bharti Airtel',1812),'WIPRO':('Wipro',246),'LT':('Larsen & Toubro',3890)}
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,name TEXT,created_at TEXT,verified INTEGER DEFAULT 0,google_sub TEXT UNIQUE);CREATE TABLE IF NOT EXISTS portfolios(user_id INTEGER PRIMARY KEY,cash REAL,starting_cash REAL);CREATE TABLE IF NOT EXISTS holdings(user_id INTEGER,symbol TEXT,qty INTEGER,avg_price REAL,PRIMARY KEY(user_id,symbol));CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id INTEGER,symbol TEXT,side TEXT,qty INTEGER,price REAL,status TEXT,mode TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS bots(user_id INTEGER PRIMARY KEY,enabled INTEGER,symbol TEXT,risk REAL,stop REAL,target REAL);CREATE TABLE IF NOT EXISTS auth_tokens(id INTEGER PRIMARY KEY,user_id INTEGER,token_hash TEXT UNIQUE,kind TEXT,expires_at TEXT,used INTEGER DEFAULT 0,created_at TEXT);CREATE TABLE IF NOT EXISTS settings(user_id INTEGER PRIMARY KEY,notifications INTEGER DEFAULT 1,trade_alerts INTEGER DEFAULT 1);CREATE TABLE IF NOT EXISTS funding(id INTEGER PRIMARY KEY,user_id INTEGER,kind TEXT,amount REAL,method TEXT,note TEXT,created_at TEXT);""");c.commit();return c
def token(u):return jwt.encode({'sub':str(u),'exp':datetime.now(timezone.utc)+timedelta(days=1)},SECRET,algorithm='HS256')
def uid(auth:Optional[str]=Header(None)):
 if not auth or not auth.lower().startswith('bearer '):raise HTTPException(401,'Login required')
 try:return int(jwt.decode(auth.split(' ',1)[1],SECRET,algorithms=['HS256'])['sub'])
 except Exception:raise HTTPException(401,'Invalid session')
def px(s):
 s=s.upper()
 if s not in STOCKS:raise HTTPException(404,'Unknown stock')
 return round(STOCKS[s][1]*(1+((int(time.time())//5)%21-10)/1000),2)
def htok(v):return hashlib.sha256(v.encode()).hexdigest()
def email_configured():return bool(os.getenv('RESEND_API_KEY') or(os.getenv('SMTP_HOST')and os.getenv('SMTP_USER')and os.getenv('SMTP_PASSWORD')))
def send_email(to,subject,html):
 frm=os.getenv('EMAIL_FROM','NovaTrade <onboarding@resend.dev>');key=os.getenv('RESEND_API_KEY')
 if key:
  r=requests.post('https://api.resend.com/emails',headers={'Authorization':f'Bearer {key}','Content-Type':'application/json'},json={'from':frm,'to':[to],'subject':subject,'html':html},timeout=15)
  if r.status_code>=400:raise RuntimeError('Email provider rejected the message')
  return
 host=os.getenv('SMTP_HOST');user=os.getenv('SMTP_USER');pw=os.getenv('SMTP_PASSWORD')
 if not(host and user and pw):raise RuntimeError('Email service is not configured')
 m=EmailMessage();m['From']=frm;m['To']=to;m['Subject']=subject;m.set_content('Open NovaTrade to continue.');m.add_alternative(html,subtype='html')
 with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=15)as s:s.starttls();s.login(user,pw);s.send_message(m)
def make_token(c,u,k,mins):
 raw=secrets.token_urlsafe(32);c.execute('INSERT INTO auth_tokens(user_id,token_hash,kind,expires_at,created_at)VALUES(?,?,?,?,?)',(u,htok(raw),k,(datetime.now(timezone.utc)+timedelta(minutes=mins)).isoformat(),datetime.now(timezone.utc).isoformat()));return raw
def consume(c,raw,k):
 r=c.execute('SELECT * FROM auth_tokens WHERE token_hash=? AND kind=? AND used=0',(htok(raw),k)).fetchone()
 if not r or datetime.fromisoformat(r['expires_at'])<datetime.now(timezone.utc):raise HTTPException(400,'This link is invalid or has expired')
 c.execute('UPDATE auth_tokens SET used=1 WHERE id=?',(r['id'],));return r['user_id']
class Auth(BaseModel):email:EmailStr;password:str=Field(min_length=6);name:str='Trader'
class Login(BaseModel):email:EmailStr;password:str
class GoogleLogin(BaseModel):credential:str
class Verify(BaseModel):token:str
class Forgot(BaseModel):email:EmailStr
class Reset(BaseModel):token:str;password:str=Field(min_length=6)
class Order(BaseModel):symbol:str;side:str;qty:int=Field(gt=0);mode:str='paper'
class Bot(BaseModel):enabled:bool;symbol:str='RELIANCE';risk:float=Field(1,ge=.1,le=5);stop:float=Field(2,ge=.5,le=20);target:float=Field(4,ge=.5,le=50)
class Settings(BaseModel):name:str=Field(min_length=1,max_length=80);notifications:bool=True;trade_alerts:bool=True
class PasswordChange(BaseModel):current_password:str;new_password:str=Field(min_length=6)
class Funding(BaseModel):amount:float=Field(gt=0);method:str='virtual';note:str=''
def init_user(c,u):c.execute('INSERT OR IGNORE INTO portfolios VALUES(?,?,?)',(u,100000,100000));c.execute("INSERT OR IGNORE INTO bots VALUES(?,?,?,?,?,?)",(u,0,'RELIANCE',1,2,4));c.execute('INSERT OR IGNORE INTO settings(user_id)VALUES(?)',(u,))
@app.get('/')
def home():
 html=(ROOT/'frontend'/'index.html').read_text(encoding='utf-8')
 if GOOGLE_CLIENT_ID:
  script=f'''<script>window.addEventListener('load',function(){{var wait=setInterval(function(){{if(window.google&&google.accounts&&google.accounts.id){{clearInterval(wait);var b=document.getElementById('googleBtn');if(b&&!b.dataset.ready){{google.accounts.id.initialize({{client_id:{GOOGLE_CLIENT_ID!r},callback:async function(r){{try{{var x=await fetch('/api/auth/google',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{credential:r.credential}})}});var d=await x.json();if(!x.ok)throw Error(d.detail||'Google sign-in failed');localStorage.setItem('nt',d.token);location.reload()}}catch(e){{var m=document.getElementById('authMsg');if(m){{m.textContent=e.message;m.className='msg err';m.style.display='block'}}}}}}}});google.accounts.id.renderButton(b,{{theme:'outline',size:'large',shape:'rectangular',width:330,text:'signin_with'}});b.dataset.ready='1'}}}},100);setTimeout(function(){{clearInterval(wait)}},10000)}});</script>'''
  html=html.replace('</body>',script+'</body>')
 return HTMLResponse(html)
@app.get('/api/health')
def health():return {'ok':True,'service':'NovaTrade','mode':'paper','email_configured':email_configured(),'google_configured':bool(GOOGLE_CLIENT_ID)}
@app.get('/api/auth/google-config')
def google_config():return {'enabled':bool(GOOGLE_CLIENT_ID)}
@app.post('/api/auth/google')
def google(a:GoogleLogin):
 if not GOOGLE_CLIENT_ID:raise HTTPException(503,'Google Sign-In is not configured yet.')
 try:i=id_token.verify_oauth2_token(a.credential,google_requests.Request(),GOOGLE_CLIENT_ID)
 except Exception:raise HTTPException(401,'Invalid Google credential')
 if i.get('iss') not in('accounts.google.com','https://accounts.google.com')or not i.get('email_verified'):raise HTTPException(401,'Google account email could not be verified')
 email=str(i.get('email','')).lower().strip();name=str(i.get('name')or i.get('given_name')or'Trader').strip()or'Trader';sub=str(i.get('sub','')).strip()
 if not email or not sub:raise HTTPException(400,'Google did not return a usable account')
 c=db();r=c.execute('SELECT * FROM users WHERE google_sub=? OR email=?',(sub,email)).fetchone()
 if r:c.execute('UPDATE users SET verified=1,google_sub=?,name=? WHERE id=?',(sub,name,r['id']));init_user(c,r['id']);c.commit();return {'token':token(r['id']),'user':{'id':r['id'],'name':name}}
 u=c.execute('INSERT INTO users(email,password,name,created_at,verified,google_sub)VALUES(?,?,?,?,1,?)',(email,pwd.hash(secrets.token_urlsafe(24)),name,datetime.now(timezone.utc).isoformat(),sub)).lastrowid;init_user(c,u);c.commit();return {'token':token(u),'user':{'id':u,'name':name}}
@app.post('/api/auth/signup')
def signup(a:Auth):
 c=db()
 try:
  u=c.execute('INSERT INTO users(email,password,name,created_at,verified)VALUES(?,?,?,?,0)',(a.email.lower().strip(),pwd.hash(a.password),a.name.strip()or'Trader',datetime.now(timezone.utc).isoformat())).lastrowid;init_user(c,u)
  if not email_configured():c.rollback();raise HTTPException(503,'Email service is not configured yet.')
  raw=make_token(c,u,'verify',1440);c.commit()
  try:send_email(a.email.lower().strip(),'Confirm your NovaTrade account',f"<h2>Welcome to NovaTrade</h2><p><a href='{BASE_URL}/?verify={raw}'>Confirm email</a></p>")
  except Exception:raise HTTPException(503,'We could not send the confirmation email.')
  return {'ok':True,'message':'Account created. Check your email to confirm your account.'}
 except sqlite3.IntegrityError:raise HTTPException(409,'Email already registered')
@app.post('/api/auth/verify')
def verify(a:Verify):c=db();u=consume(c,a.token,'verify');c.execute('UPDATE users SET verified=1 WHERE id=?',(u,));c.commit();return {'ok':True,'message':'Email confirmed. You can now sign in.'}
@app.post('/api/auth/resend-verification')
def resend(a:Forgot):
 c=db();r=c.execute('SELECT id FROM users WHERE email=? AND verified=0',(a.email.lower().strip(),)).fetchone()
 if r and email_configured():
  raw=make_token(c,r['id'],'verify',1440);c.commit()
  try:send_email(a.email.lower().strip(),'Confirm your NovaTrade account',f"<p><a href='{BASE_URL}/?verify={raw}'>Confirm email</a></p>")
  except Exception:pass
 return {'ok':True,'message':'If the account needs confirmation, a new email has been sent.'}
@app.post('/api/auth/login')
def login(a:Login):
 r=db().execute('SELECT * FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
 if not r or not pwd.verify(a.password,r['password']):raise HTTPException(401,'Invalid email or password')
 if not r['verified']:raise HTTPException(403,'Please confirm your email before signing in')
 return {'token':token(r['id']),'user':{'id':r['id'],'name':r['name']}}
@app.post('/api/auth/forgot-password')
def forgot(a:Forgot):
 c=db();r=c.execute('SELECT id FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
 if r and email_configured():
  raw=make_token(c,r['id'],'reset',30);c.commit()
  try:send_email(a.email.lower().strip(),'Reset your NovaTrade password',f"<p><a href='{BASE_URL}/?reset={raw}'>Reset password</a></p>")
  except Exception:pass
 return {'ok':True,'message':'If an account exists for that email, a password-reset link has been sent.'}
@app.post('/api/auth/reset-password')
def reset(a:Reset):c=db();u=consume(c,a.token,'reset');c.execute('UPDATE users SET password=? WHERE id=?',(pwd.hash(a.password),u));c.execute("UPDATE auth_tokens SET used=1 WHERE user_id=? AND kind='reset'",(u,));c.commit();return {'ok':True,'message':'Password changed. You can now sign in.'}
@app.get('/api/me')
def me(u:int=Depends(uid)):return dict(db().execute('SELECT id,email,name,verified,google_sub FROM users WHERE id=?',(u,)).fetchone())
@app.post('/api/change-password')
def change_password(a:PasswordChange,u:int=Depends(uid)):
 c=db();r=c.execute('SELECT password FROM users WHERE id=?',(u,)).fetchone()
 if not r or not r['password'] or not pwd.verify(a.current_password,r['password']):raise HTTPException(400,'Current password is incorrect')
 c.execute('UPDATE users SET password=? WHERE id=?',(pwd.hash(a.new_password),u));c.commit();return {'ok':True}
@app.get('/api/settings')
def get_settings(u:int=Depends(uid)):
 c=db();r=c.execute('SELECT id,email,name,verified,google_sub FROM users WHERE id=?',(u,)).fetchone();c.execute('INSERT OR IGNORE INTO settings(user_id)VALUES(?)',(u,));s=c.execute('SELECT * FROM settings WHERE user_id=?',(u,)).fetchone();return {'account':dict(r),'preferences':dict(s)}
@app.post('/api/settings')
def save_settings(a:Settings,u:int=Depends(uid)):
 c=db();c.execute('UPDATE users SET name=? WHERE id=?',(a.name.strip(),u));c.execute('INSERT INTO settings(user_id,notifications,trade_alerts)VALUES(?,?,?) ON CONFLICT(user_id)DO UPDATE SET notifications=excluded.notifications,trade_alerts=excluded.trade_alerts',(u,int(a.notifications),int(a.trade_alerts)));c.commit();return {'ok':True}
@app.get('/api/funding')
def funding(u:int=Depends(uid)):
 c=db();p=c.execute('SELECT cash FROM portfolios WHERE user_id=?',(u,)).fetchone();rows=c.execute('SELECT * FROM funding WHERE user_id=? ORDER BY id DESC LIMIT 30',(u,)).fetchall();return {'cash':p['cash'],'transactions':[dict(x)for x in rows]}
@app.post('/api/funding/deposit-paper')
def deposit(a:Funding,u:int=Depends(uid)):
 if a.method!='virtual':raise HTTPException(400,'Real-money funding is not enabled in paper mode')
 c=db();c.execute('UPDATE portfolios SET cash=cash+? WHERE user_id=?',(a.amount,u));c.execute('INSERT INTO funding(user_id,kind,amount,method,note,created_at)VALUES(?,?,?,?,?,?)',(u,'deposit',a.amount,'virtual',a.note,datetime.now(timezone.utc).isoformat()));c.commit();return {'ok':True}
@app.post('/api/funding/withdraw-paper')
def withdraw(a:Funding,u:int=Depends(uid)):
 if a.method!='virtual':raise HTTPException(400,'Real-money withdrawals are not enabled in paper mode')
 c=db();p=c.execute('SELECT cash FROM portfolios WHERE user_id=?',(u,)).fetchone()
 if a.amount>p['cash']:raise HTTPException(400,'Withdrawal exceeds available virtual cash')
 c.execute('UPDATE portfolios SET cash=cash-? WHERE user_id=?',(a.amount,u));c.execute('INSERT INTO funding(user_id,kind,amount,method,note,created_at)VALUES(?,?,?,?,?,?)',(u,'withdraw',a.amount,'virtual',a.note,datetime.now(timezone.utc).isoformat()));c.commit();return {'ok':True}
@app.get('/api/stocks')
def stocks(q:str=''):
 q=q.upper();return[{'symbol':s,'name':v[0],'exchange':'NSE','price':px(s)}for s,v in STOCKS.items()if not q or q in s or q in v[0].upper()]
@app.get('/api/portfolio')
def portfolio(u:int=Depends(uid)):
 c=db();p=c.execute('SELECT * FROM portfolios WHERE user_id=?',(u,)).fetchone();hs=c.execute('SELECT * FROM holdings WHERE user_id=?',(u,)).fetchall();value=p['cash'];out=[]
 for h in hs:
  price=px(h['symbol']);value+=h['qty']*price;out.append({'symbol':h['symbol'],'qty':h['qty'],'avg_price':h['avg_price'],'price':price,'value':h['qty']*price})
 return {'cash':p['cash'],'starting_cash':p['starting_cash'],'equity':value,'pnl':value-p['starting_cash'],'holdings':out}
@app.post('/api/orders')
def order(a:Order,u:int=Depends(uid)):
 if a.mode!='paper':raise HTTPException(400,'Live trading is disabled')
 s=a.symbol.upper();side=a.side.upper();price=px(s);c=db();p=c.execute('SELECT cash FROM portfolios WHERE user_id=?',(u,)).fetchone();h=c.execute('SELECT * FROM holdings WHERE user_id=? AND symbol=?',(u,s)).fetchone()
 if side=='BUY':
  cost=price*a.qty
  if cost>p['cash']:raise HTTPException(400,'Insufficient virtual cash')
  nq=(h['qty']if h else 0)+a.qty;avg=((h['qty']*h['avg_price'])if h else 0)+cost;avg/=nq;c.execute('UPDATE portfolios SET cash=cash-? WHERE user_id=?',(cost,u));c.execute('INSERT INTO holdings(user_id,symbol,qty,avg_price)VALUES(?,?,?,?) ON CONFLICT(user_id,symbol)DO UPDATE SET qty=excluded.qty,avg_price=excluded.avg_price',(u,s,nq,avg))
 elif side=='SELL':
  if not h or h['qty']<a.qty:raise HTTPException(400,'Not enough holdings')
  nq=h['qty']-a.qty;c.execute('UPDATE portfolios SET cash=cash+? WHERE user_id=?',(price*a.qty,u));c.execute('UPDATE holdings SET qty=? WHERE user_id=? AND symbol=?',(nq,u,s)) if nq else c.execute('DELETE FROM holdings WHERE user_id=? AND symbol=?',(u,s))
 else:raise HTTPException(400,'Side must be BUY or SELL')
 c.execute('INSERT INTO orders(user_id,symbol,side,qty,price,status,mode,created_at)VALUES(?,?,?,?,?,?,?,?)',(u,s,side,a.qty,price,'FILLED','paper',datetime.now(timezone.utc).isoformat()));c.commit();return {'ok':True,'price':price}
@app.get('/api/orders')
def orders(u:int=Depends(uid)):return[dict(x)for x in db().execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100',(u,)).fetchall()]
@app.post('/api/reset-paper')
def reset_paper(u:int=Depends(uid)):
 c=db();c.execute('UPDATE portfolios SET cash=starting_cash WHERE user_id=?',(u,));c.execute('DELETE FROM holdings WHERE user_id=?',(u,));c.execute('DELETE FROM orders WHERE user_id=?',(u,));c.commit();return {'ok':True}
@app.get('/api/bot')
def get_bot(u:int=Depends(uid)):return dict(db().execute('SELECT enabled,symbol,risk,stop,target FROM bots WHERE user_id=?',(u,)).fetchone())
@app.post('/api/bot')
def save_bot(a:Bot,u:int=Depends(uid)):
 c=db();c.execute('INSERT INTO bots(user_id,enabled,symbol,risk,stop,target)VALUES(?,?,?,?,?,?) ON CONFLICT(user_id)DO UPDATE SET enabled=excluded.enabled,symbol=excluded.symbol,risk=excluded.risk,stop=excluded.stop,target=excluded.target',(u,int(a.enabled),a.symbol.upper(),a.risk,a.stop,a.target));c.commit();return {'ok':True}
