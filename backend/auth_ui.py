import os
from fastapi import Request
from fastapi.responses import Response, JSONResponse
from .app import app

AUTH_FIX = r'''<style>
.authbox.nt-redone{width:min(460px,100%);padding:34px 32px 28px;border-radius:26px}
.nt-auth-head{margin-bottom:22px}.nt-auth-kicker{font-size:11px;font-weight:900;letter-spacing:.12em;color:#087b58;text-transform:uppercase}.nt-auth-title{font-size:30px!important;margin:8px 0 6px!important}.nt-auth-sub{line-height:1.55;margin:0}
.nt-google-wrap{min-height:48px;border:1px solid #dfe9e4;border-radius:12px;display:flex;align-items:center;justify-content:center;background:#fff;overflow:hidden}.nt-google-wrap>div{max-width:100%}
.nt-auth-links{display:flex;justify-content:space-between;align-items:center;margin-top:10px}.nt-auth-foot{margin-top:20px;padding-top:16px;border-top:1px solid #edf2ef;font-size:11px;text-align:center}
#ntOtpBox{margin-top:14px;padding:14px;background:#f7fbf9;border:1px solid #dfece6;border-radius:13px}.nt-otp-label{font-weight:800;font-size:12px;margin-bottom:7px}.nt-otp-hint{font-size:11px;color:#71817a;margin-top:7px}.nt-otp-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:9px}.nt-otp-actions button{width:100%}
.nt-spinner{display:inline-block;width:14px;height:14px;border:2px solid #ffffff66;border-top-color:#fff;border-radius:50%;animation:ntspin .7s linear infinite;vertical-align:-2px;margin-right:7px}@keyframes ntspin{to{transform:rotate(360deg)}}
@media(max-width:520px){.authbox.nt-redone{padding:26px 20px}.nt-otp-actions{grid-template-columns:1fr}}
</style><script>
(function(){
'use strict';
const $=id=>document.getElementById(id);let mode='login',busy=false,purpose='verify',googleStarted=false;
function msg(t,error=false){const m=$('authMsg');if(!m)return;m.textContent=t;m.className='msg'+(error?' err':'');m.style.display='block'}
function clearMsg(){const m=$('authMsg');if(m)m.style.display='none'}
function post(url,data){return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(async r=>{let d={};try{d=await r.json()}catch{}if(!r.ok){const e=new Error(d.detail||'Request failed');e.status=r.status;throw e}return d})}
function busyButton(on){const b=$('authBtn');if(!b)return;b.disabled=on;b.innerHTML=on?'<span class="nt-spinner"></span>Please wait…':(mode==='signup'?'Create account':'Sign in')}
function otpBox(kind){purpose=kind;let box=$('ntOtpBox');if(!box){box=document.createElement('div');box.id='ntOtpBox';box.innerHTML='<div class="nt-otp-label">6-digit verification code</div><input id="otpCode" class="field" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Enter OTP"><div class="nt-otp-actions"><button id="verifyOtpBtn" class="btn primary">Verify OTP</button><button id="resendOtpBtn" class="btn outline">Resend OTP</button></div><div class="nt-otp-hint">The code expires in 10 minutes. A new code can be requested after 60 seconds.</div>';const anchor=$('authMsg');anchor.parentNode.insertBefore(box,anchor)}else box.style.display='block';$('otpCode').focus();$('verifyOtpBtn').onclick=kind==='reset'?verifyReset:verifyVerify;$('resendOtpBtn').onclick=resendOtp}
function clearOtp(){const b=$('ntOtpBox');if(b)b.remove();$('authBtn').style.display='';$('pass').placeholder='Password'}
function setMode(next){mode=next;clearMsg();clearOtp();$('authTitle').textContent=next==='signup'?'Create your NovaTrade account':'Welcome back';$('ntAuthKicker').textContent=next==='signup'?'GET STARTED':'SECURE SIGN IN';$('name').style.display=next==='signup'?'block':'none';$('name').required=next==='signup';$('pass').autocomplete=next==='signup'?'new-password':'current-password';$('forgotBtn').style.display=next==='signup'?'none':'';$('authBtn').style.display='';$('switchBtn').textContent=next==='signup'?'Back to sign in':'Create account';$('guestBtn').style.display='none';setTimeout(initGoogle,50)}
async function signup(){if(busy)return;const name=$('name').value.trim(),email=$('email').value.trim(),password=$('pass').value;if(!name||!email||password.length<6){msg('Enter your name, a valid email and a password of at least 6 characters.',true);return}busy=true;busyButton(true);try{const d=await post('/api/auth/signup-otp',{name,email,password});msg(d.message);otpBox('verify')}catch(e){msg(e.message,true);if(e.status===409&&/not verified/i.test(e.message)){otpBox('verify')}}finally{busy=false;busyButton(false)}}
async function login(){if(busy)return;const email=$('email').value.trim(),password=$('pass').value;if(!email||!password){msg('Enter your email and password.',true);return}busy=true;busyButton(true);try{const d=await post('/api/auth/login',{email,password});localStorage.setItem('nt',d.token);location.reload()}catch(e){if(e.status===403){try{const d=await post('/api/auth/otp-send',{email,purpose:'verify'});msg('Your email is not verified. '+d.message);otpBox('verify')}catch(x){msg(x.message,true)}}else msg(e.message,true)}finally{busy=false;busyButton(false)}}
async function verifyVerify(){const email=$('email').value.trim(),code=$('otpCode').value.trim();if(!/^\d{6}$/.test(code)){msg('Enter the 6-digit OTP.',true);return}try{const d=await post('/api/auth/otp-verify',{email,code});localStorage.setItem('nt',d.token);msg('Verified. Signing you in…');setTimeout(()=>location.reload(),250)}catch(e){msg(e.message,true)}}
async function resendOtp(){const email=$('email').value.trim();if(!email){msg('Enter your email first.',true);return}try{const d=await post('/api/auth/otp-send',{email,purpose});msg(d.message)}catch(e){msg(e.message,true)}}
async function forgot(){const email=$('email').value.trim();if(!email){msg('Enter your email first.',true);return}try{const d=await post('/api/auth/otp-send',{email,purpose:'reset'});$('pass').value='';$('pass').placeholder='New password (min 6 characters)';$('authBtn').style.display='none';msg(d.message+' Enter the OTP and your new password.');otpBox('reset')}catch(e){msg(e.message,true)}}
async function verifyReset(){const email=$('email').value.trim(),code=$('otpCode').value.trim(),password=$('pass').value;if(!/^\d{6}$/.test(code)){msg('Enter the 6-digit OTP.',true);return}if(password.length<6){msg('New password must be at least 6 characters.',true);return}try{const d=await post('/api/auth/otp-reset',{email,code,password});localStorage.setItem('nt',d.token);msg('Password reset. Signing you in…');setTimeout(()=>location.reload(),250)}catch(e){msg(e.message,true)}}
function googleCallback(r){post('/api/auth/google',{credential:r.credential}).then(d=>{localStorage.setItem('nt',d.token);location.reload()}).catch(e=>msg(e.message,true))}
function initGoogle(){if(googleStarted)return;const host=$('googleBtn');if(!host)return;if(!window.google||!google.accounts||!google.accounts.id){setTimeout(initGoogle,250);return}fetch('/api/auth/google-config-public').then(r=>r.json()).then(c=>{if(!c.enabled){host.innerHTML='<span style="font-size:12px;color:#71817a">Google Sign-In is not configured</span>';return}google.accounts.id.initialize({client_id:c.client_id,callback:googleCallback,auto_select:false,cancel_on_tap_outside:true});host.innerHTML='';google.accounts.id.renderButton(host,{theme:'outline',size:'large',shape:'rectangular',width:360,text:'signin_with',logo_alignment:'left'});googleStarted=true}).catch(()=>{host.innerHTML='<span style="font-size:12px;color:#9d3441">Google Sign-In unavailable</span>'})}
function rebuild(){const box=document.querySelector('#auth .authbox');if(!box)return;box.classList.add('nt-redone');box.innerHTML='<div class="brand"><div class="logo">N</div>NovaTrade</div><div class="nt-auth-head"><div id="ntAuthKicker" class="nt-auth-kicker">SECURE SIGN IN</div><h1 id="authTitle" class="nt-auth-title">Welcome back</h1><p class="muted nt-auth-sub">Sign in to your paper-trading workspace. Your account and virtual portfolio stay synced.</p></div><input id="name" class="field" placeholder="Full name" autocomplete="name" style="display:none"><input id="email" class="field" type="email" autocomplete="email" placeholder="Email address"><input id="pass" class="field" type="password" autocomplete="current-password" placeholder="Password"><button id="authBtn" class="btn primary" style="width:100%;margin-top:11px">Sign in</button><div class="or"><span>or continue with</span></div><div id="googleBtn" class="google nt-google-wrap"><span style="font-size:12px;color:#71817a">Loading Google Sign-In…</span></div><div class="nt-auth-links"><button id="forgotBtn" class="link">Forgot password?</button><button id="switchBtn" class="link">Create account</button></div><div id="authMsg" class="msg"></div><div class="nt-auth-foot muted">Email OTP verification • 10-minute expiry • 5 attempts<br>Paper trading only • no real-money deposits or withdrawals</div>';$('authBtn').onclick=()=>mode==='signup'?signup():login;$('switchBtn').onclick=()=>setMode(mode==='signup'?'login':'signup');$('forgotBtn').onclick=forgot;setMode('login')}
window.addEventListener('load',()=>setTimeout(rebuild,50));
})();</script>'''

@app.get('/api/auth/google-config-public')
def google_config_public():
    client_id=os.getenv('GOOGLE_CLIENT_ID','').strip()
    return {'enabled':bool(client_id),'client_id':client_id}

@app.middleware('http')
async def inject_auth_fix(request: Request, call_next):
    response=await call_next(request)
    if request.url.path=='/' and response.headers.get('content-type','').startswith('text/html'):
        body=response.body
        if body and b'id="auth"' in body:
            body=body.replace(b'</body>',AUTH_FIX.encode('utf-8')+b'</body>')
            headers=dict(response.headers);headers.pop('content-length',None)
            return Response(content=body,status_code=response.status_code,headers=headers,media_type='text/html')
    return response
