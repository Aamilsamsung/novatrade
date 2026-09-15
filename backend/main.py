import os, sqlite3, time, hashlib, secrets, smtplib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from typing import Optional
import requests
import jwt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, EmailStr
from passlib.context import CryptContext

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.getenv('NOVATRADE_DB', str(ROOT / 'novatrade.db')))
SECRET = os.getenv('JWT_SECRET', 'novatrade-demo-secret-change-me')
BASE_URL = os.getenv('APP_BASE_URL', 'https://novatrade-p49i.onrender.com').rstrip('/')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '').strip()
pwd = CryptContext(schemes=['bcrypt'], deprecated='auto')
app = FastAPI(title='NovaTrade', version='5.0')
app.mount('/static', StaticFiles(directory=str(ROOT / 'frontend')), name='static')
STOCKS = {'RELIANCE': ('Reliance Industries', 1428), 'TCS': ('Tata Consultancy Services', 3125), 'INFY': ('Infosys', 1510), 'HDFCBANK': ('HDFC Bank', 962), 'ICICIBANK': ('ICICI Bank', 1385), 'SBIN': ('State Bank of India', 820), 'ITC': ('ITC', 411), 'BHARTIARTL': ('Bharti Airtel', 1812), 'WIPRO': ('Wipro', 246), 'LT': ('Larsen & Toubro', 3890)}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,name TEXT,created_at TEXT,verified INTEGER DEFAULT 0,google_sub TEXT UNIQUE);
    CREATE TABLE IF NOT EXISTS portfolios(user_id INTEGER PRIMARY KEY,cash REAL,starting_cash REAL);
    CREATE TABLE IF NOT EXISTS holdings(user_id INTEGER,symbol TEXT,qty INTEGER,avg_price REAL,PRIMARY KEY(user_id,symbol));
    CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id INTEGER,symbol TEXT,side TEXT,qty INTEGER,price REAL,status TEXT,mode TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS bots(user_id INTEGER PRIMARY KEY,enabled INTEGER,symbol TEXT,risk REAL,stop REAL,target REAL);
    CREATE TABLE IF NOT EXISTS auth_tokens(id INTEGER PRIMARY KEY,user_id INTEGER,token_hash TEXT UNIQUE,kind TEXT,expires_at TEXT,used INTEGER DEFAULT 0,created_at TEXT);
    ''')
    cols=[r['name'] for r in c.execute('PRAGMA table_info(users)').fetchall()]
    if 'verified' not in cols: c.execute('ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0')
    if 'google_sub' not in cols: c.execute('ALTER TABLE users ADD COLUMN google_sub TEXT')
    c.commit(); return c

def token(uid):
    # JWT subject must be a string for strict PyJWT versions.
    return jwt.encode({'sub':str(uid),'exp':datetime.now(timezone.utc)+timedelta(days=1)},SECRET,algorithm='HS256')

def uid(auth: Optional[str]=Header(None)):
    if not auth or not auth.lower().startswith('bearer '): raise HTTPException(401,'Login required')
    try: return int(jwt.decode(auth.split(' ',1)[1],SECRET,algorithms=['HS256'])['sub'])
    except Exception: raise HTTPException(401,'Invalid session')

def px(s):
    s=s.upper()
    if s not in STOCKS: raise HTTPException(404,'Unknown stock')
    base=STOCKS[s][1]; move=((int(time.time())//5)%21-10)/1000
    return round(base*(1+move),2)

def hash_token(value): return hashlib.sha256(value.encode()).hexdigest()
def email_configured(): return bool(os.getenv('RESEND_API_KEY') or (os.getenv('SMTP_HOST') and os.getenv('SMTP_USER') and os.getenv('SMTP_PASSWORD')))

def send_email(to,subject,html):
    from_addr=os.getenv('EMAIL_FROM','NovaTrade <onboarding@resend.dev>'); resend=os.getenv('RESEND_API_KEY')
    if resend:
        r=requests.post('https://api.resend.com/emails',headers={'Authorization':f'Bearer {resend}','Content-Type':'application/json'},json={'from':from_addr,'to':[to],'subject':subject,'html':html},timeout=15)
        if r.status_code>=400: raise RuntimeError('Email provider rejected the message')
        return
    host=os.getenv('SMTP_HOST'); user=os.getenv('SMTP_USER'); password=os.getenv('SMTP_PASSWORD')
    if not(host and user and password): raise RuntimeError('Email service is not configured')
    msg=EmailMessage(); msg['From']=from_addr; msg['To']=to; msg['Subject']=subject; msg.set_content('Open NovaTrade to continue.'); msg.add_alternative(html,subtype='html')
    with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=15) as server: server.starttls(); server.login(user,password); server.send_message(msg)

def create_auth_token(c,user_id,kind,minutes=60):
    raw=secrets.token_urlsafe(32); c.execute('INSERT INTO auth_tokens(user_id,token_hash,kind,expires_at,created_at) VALUES(?,?,?,?,?)',(user_id,hash_token(raw),kind,(datetime.now(timezone.utc)+timedelta(minutes=minutes)).isoformat(),datetime.now(timezone.utc).isoformat())); return raw

def consume_auth_token(c,raw,kind):
    r=c.execute('SELECT * FROM auth_tokens WHERE token_hash=? AND kind=? AND used=0',(hash_token(raw),kind)).fetchone()
    if not r or datetime.fromisoformat(r['expires_at'])<datetime.now(timezone.utc): raise HTTPException(400,'This link is invalid or has expired')
    c.execute('UPDATE auth_tokens SET used=1 WHERE id=?',(r['id'],)); return r['user_id']

class Auth(BaseModel): email: EmailStr; password: str=Field(min_length=6); name: str='Trader'
class Login(BaseModel): email: EmailStr; password: str
class GoogleLogin(BaseModel): credential: str
class VerifyRequest(BaseModel): token: str
class ForgotRequest(BaseModel): email: EmailStr
class ResetRequest(BaseModel): token: str; password: str=Field(min_length=6)
class Order(BaseModel): symbol: str; side: str; qty: int=Field(gt=0); mode: str='paper'
class Bot(BaseModel): enabled: bool; symbol: str='RELIANCE'; risk: float=Field(1,ge=.1,le=5); stop: float=Field(2,ge=.5,le=20); target: float=Field(4,ge=.5,le=50)

@app.get('/')
def home():
    html=(ROOT/'frontend'/'index.html').read_text(encoding='utf-8')
    if GOOGLE_CLIENT_ID:
        inject='''
<style>
.google-login-wrap{margin-top:14px;text-align:center}.google-or{display:flex;align-items:center;gap:10px;margin:13px 0;color:#8a9893;font-size:12px}.google-or:before,.google-or:after{content:"";height:1px;background:#e0ece7;flex:1}.google-login-btn{display:flex;justify-content:center}
</style>
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script>
window.handleNovaGoogle = async function(response){
  try{
    const r=await fetch('/api/auth/google',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:response.credential})});
    const d=await r.json();
    if(!r.ok) throw Error(d.detail||'Google sign-in failed');
    localStorage.setItem('nt',d.token);
    if(typeof boot==='function') await boot(); else location.reload();
  }catch(e){
    const m=document.getElementById('authMsg'); if(m){m.textContent=e.message;m.style.display='block';}
  }
};
window.addEventListener('load',function(){
  const btn=document.getElementById('authBtn'); if(!btn) return;
  const wrap=document.createElement('div'); wrap.className='google-login-wrap';
  wrap.innerHTML='<div class="google-or"><span>or continue with</span></div><div class="google-login-btn" id="googleBtn"></div>';
  btn.parentNode.insertBefore(wrap,btn.nextSibling);
  const wait=setInterval(function(){
    if(window.google&&google.accounts&&google.accounts.id){
      clearInterval(wait);
      google.accounts.id.initialize({client_id:''' + repr(GOOGLE_CLIENT_ID) + ''',callback:window.handleNovaGoogle});
      google.accounts.id.renderButton(document.getElementById('googleBtn'),{theme:'outline',size:'large',shape:'rectangular',width:330,text:'signin_with'});
    }
  },100);
  setTimeout(()=>clearInterval(wait),10000);
});
</script>
'''
        html=html.replace('</body>',inject+'</body>')
    return HTMLResponse(html)

@app.get('/api/health')
def health(): return {'ok':True,'service':'NovaTrade','mode':'paper','email_configured':email_configured(),'google_configured':bool(GOOGLE_CLIENT_ID)}
@app.get('/api/auth/google-config')
def google_config(): return {'enabled':bool(GOOGLE_CLIENT_ID)}

@app.post('/api/auth/google')
def google_login(a: GoogleLogin):
    if not GOOGLE_CLIENT_ID: raise HTTPException(503,'Google Sign-In is not configured yet. Add GOOGLE_CLIENT_ID in Render.')
    try: info=id_token.verify_oauth2_token(a.credential,google_requests.Request(),GOOGLE_CLIENT_ID)
    except Exception: raise HTTPException(401,'Invalid Google credential')
    if info.get('iss') not in ('accounts.google.com','https://accounts.google.com') or not info.get('email_verified'): raise HTTPException(401,'Google account email could not be verified')
    email=str(info.get('email','')).lower().strip(); name=str(info.get('name') or info.get('given_name') or 'Trader').strip() or 'Trader'; sub=str(info.get('sub','')).strip()
    if not email or not sub: raise HTTPException(400,'Google did not return a usable account')
    c=db(); r=c.execute('SELECT * FROM users WHERE google_sub=? OR email=?',(sub,email)).fetchone()
    if r:
        c.execute('UPDATE users SET verified=1,google_sub=?,name=? WHERE id=?',(sub,name,r['id'])); c.commit(); return {'token':token(r['id']),'user':{'id':r['id'],'name':name}}
    cur=c.execute('INSERT INTO users(email,password,name,created_at,verified,google_sub) VALUES(?,?,?,?,1,?)',(email,pwd.hash(secrets.token_urlsafe(24)),name,datetime.now(timezone.utc).isoformat(),sub)); u=cur.lastrowid
    c.execute('INSERT INTO portfolios VALUES(?,?,?)',(u,100000,100000)); c.execute('INSERT INTO bots VALUES(?,?,?,?,?,?)',(u,0,'RELIANCE',1,2,4)); c.commit()
    return {'token':token(u),'user':{'id':u,'name':name}}

@app.post('/api/auth/signup')
def signup(a: Auth):
    c=db(); email=a.email.lower().strip()
    try:
        cur=c.execute('INSERT INTO users(email,password,name,created_at,verified) VALUES(?,?,?,?,0)',(email,pwd.hash(a.password),a.name.strip() or 'Trader',datetime.now(timezone.utc).isoformat())); u=cur.lastrowid
        c.execute('INSERT INTO portfolios VALUES(?,?,?)',(u,100000,100000)); c.execute('INSERT INTO bots VALUES(?,?,?,?,?,?)',(u,0,'RELIANCE',1,2,4))
        if not email_configured(): c.rollback(); raise HTTPException(503,'Email service is not configured yet. Add RESEND_API_KEY or SMTP settings in Render.')
        raw=create_auth_token(c,u,'verify',1440); c.commit(); link=f'{BASE_URL}/?verify={raw}'
        try: send_email(email,'Confirm your NovaTrade account',f'<div style="font-family:Arial"><h2>Welcome to NovaTrade</h2><p>Confirm your email to activate your account.</p><p><a href="{link}" style="background:#08a66b;color:white;padding:12px 18px;border-radius:8px;text-decoration:none">Confirm email</a></p><p>This link expires in 24 hours.</p></div>')
        except Exception:
            c.execute('DELETE FROM auth_tokens WHERE user_id=?',(u,)); c.execute('DELETE FROM bots WHERE user_id=?',(u,)); c.execute('DELETE FROM portfolios WHERE user_id=?',(u,)); c.execute('DELETE FROM users WHERE id=?',(u,)); c.commit(); raise HTTPException(503,'We could not send the confirmation email. Please try again later.')
        return {'ok':True,'message':'Account created. Check your email to confirm your account.'}
    except sqlite3.IntegrityError: raise HTTPException(409,'Email already registered')

@app.post('/api/auth/verify')
def verify_email(v: VerifyRequest):
    c=db(); u=consume_auth_token(c,v.token,'verify'); c.execute('UPDATE users SET verified=1 WHERE id=?',(u,)); c.commit(); return {'ok':True,'message':'Email confirmed. You can now sign in.'}
@app.post('/api/auth/resend-verification')
def resend_verification(a: ForgotRequest):
    c=db(); r=c.execute('SELECT id,name,verified FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
    if r and not r['verified'] and email_configured():
        raw=create_auth_token(c,r['id'],'verify',1440); c.commit(); link=f'{BASE_URL}/?verify={raw}'
        try: send_email(a.email.lower().strip(),'Confirm your NovaTrade account',f'<div style="font-family:Arial"><h2>Confirm your NovaTrade email</h2><p><a href="{link}" style="background:#08a66b;color:white;padding:12px 18px;border-radius:8px;text-decoration:none">Confirm email</a></p></div>')
        except Exception: pass
    return {'ok':True,'message':'If the account exists and needs confirmation, a new email has been sent.'}
@app.post('/api/auth/login')
def login(a: Login):
    c=db(); r=c.execute('SELECT * FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
    if not r or not pwd.verify(a.password,r['password']): raise HTTPException(401,'Invalid email or password')
    if not r['verified']: raise HTTPException(403,'Please confirm your email before signing in')
    return {'token':token(r['id']),'user':{'id':r['id'],'name':r['name']}}
@app.post('/api/auth/forgot-password')
def forgot_password(a: ForgotRequest):
    c=db(); r=c.execute('SELECT id FROM users WHERE email=?',(a.email.lower().strip(),)).fetchone()
    if r and email_configured():
        raw=create_auth_token(c,r['id'],'reset',30); c.commit(); link=f'{BASE_URL}/?reset={raw}'
        try: send_email(a.email.lower().strip(),'Reset your NovaTrade password',f'<div style="font-family:Arial"><h2>Password reset</h2><p>Use the button below to choose a new password.</p><p><a href="{link}" style="background:#08a66b;color:white;padding:12px 18px;border-radius:8px;text-decoration:none">Reset password</a></p><p>This link expires in 30 minutes.</p></div>')
        except Exception: pass
    return {'ok':True,'message':'If an account exists for that email, a password-reset link has been sent.'}
@app.post('/api/auth/reset-password')
def reset_password(rq: ResetRequest):
    c=db(); u=consume_auth_token(c,rq.token,'reset'); c.execute('UPDATE users SET password=? WHERE id=?',(pwd.hash(rq.password),u)); c.execute("UPDATE auth_tokens SET used=1 WHERE user_id=? AND kind='reset'",(u,)); c.commit(); return {'ok':True,'message':'Password changed. You can now sign in.'}
@app.get('/api/me')
def me(u: int=Depends(uid)):
    r=db().execute('SELECT id,email,name,verified FROM users WHERE id=?',(u,)).fetchone(); return dict(r)
@app.get('/api/stocks')
def stocks(q: str=''):
    q=q.upper(); return [{'symbol':s,'name':v[0],'exchange':'NSE','price':px(s)} for s,v in STOCKS.items() if not q or q in s or q in v[0].upper()]
@app.get('/api/portfolio')
def portfolio(u: int=Depends(uid)):
    c=db(); p=c.execute('SELECT * FROM portfolios WHERE user_id=?',(u,)).fetchone(); hs=c.execute('SELECT * FROM holdings WHERE user_id=?',(u,)).fetchall(); iv=sum(h['qty']*px(h['symbol']) for h in hs); eq=p['cash']+iv
    return {'cash':round(p['cash'],2),'holdings_value':round(iv,2),'equity':round(eq,2),'pnl':round(eq-p['starting_cash'],2),'starting_cash':p['starting_cash'],'holdings':[{'symbol':h['symbol'],'qty':h['qty'],'avg_price':h['avg_price'],'price':px(h['symbol'])} for h in hs]}
@app.get('/api/orders')
def orders(u: int=Depends(uid)): return [dict(r) for r in db().execute('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100',(u,)).fetchall()]
@app.post('/api/orders')
def order(o: Order,u: int=Depends(uid)):
    if o.mode!='paper': raise HTTPException(403,'Live trading is disabled. NovaTrade is paper-only.')
    s=o.symbol.upper(); p=px(s); side=o.side.upper(); c=db(); port=c.execute('SELECT * FROM portfolios WHERE user_id=?',(u,)).fetchone(); h=c.execute('SELECT * FROM holdings WHERE user_id=? AND symbol=?',(u,s)).fetchone(); cost=p*o.qty
    if side=='BUY':
        if port['cash']<cost: raise HTTPException(400,'Insufficient paper cash')
        if h:
            nq=h['qty']+o.qty; c.execute('UPDATE holdings SET qty=?,avg_price=? WHERE user_id=? AND symbol=?',(nq,(h['qty']*h['avg_price']+cost)/nq,u,s))
        else: c.execute('INSERT INTO holdings VALUES(?,?,?,?)',(u,s,o.qty,p))
        c.execute('UPDATE portfolios SET cash=cash-? WHERE user_id=?',(cost,u))
    elif side=='SELL':
        if not h or h['qty']<o.qty: raise HTTPException(400,'Insufficient shares')
        nq=h['qty']-o.qty
        if nq: c.execute('UPDATE holdings SET qty=? WHERE user_id=? AND symbol=?',(nq,u,s))
        else: c.execute('DELETE FROM holdings WHERE user_id=? AND symbol=?',(u,s))
        c.execute('UPDATE portfolios SET cash=cash+? WHERE user_id=?',(cost,u))
    else: raise HTTPException(400,'Side must be BUY or SELL')
    c.execute('INSERT INTO orders(user_id,symbol,side,qty,price,status,mode,created_at) VALUES(?,?,?,?,?,?,?,?)',(u,s,side,o.qty,p,'FILLED','paper',datetime.now(timezone.utc).isoformat())); c.commit(); return {'status':'FILLED','price':p,'mode':'paper'}
@app.get('/api/bot')
def getbot(u: int=Depends(uid)): return dict(db().execute('SELECT * FROM bots WHERE user_id=?',(u,)).fetchone())
@app.post('/api/bot')
def setbot(b: Bot,u: int=Depends(uid)):
    c=db(); s=b.symbol.upper()
    if s not in STOCKS: raise HTTPException(400,'Unknown bot symbol')
    c.execute('UPDATE bots SET enabled=?,symbol=?,risk=?,stop=?,target=? WHERE user_id=?',(int(b.enabled),s,b.risk,b.stop,b.target,u)); c.commit(); return getbot(u)
@app.post('/api/reset-paper')
def reset(u: int=Depends(uid)):
    c=db(); c.execute('UPDATE portfolios SET cash=starting_cash WHERE user_id=?',(u,)); c.execute('DELETE FROM holdings WHERE user_id=?',(u,)); c.execute("DELETE FROM orders WHERE user_id=? AND mode='paper'",(u,)); c.commit(); return {'ok':True}
