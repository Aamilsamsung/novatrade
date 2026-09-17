from fastapi import Request
from fastapi.responses import Response

from .app import app


AUTH_FIX = r'''<style>
#otpBox{margin-top:12px}#otpCode{letter-spacing:6px;text-align:center;font-size:20px;font-weight:800}#otpActions{display:flex;gap:8px;margin-top:8px}#otpActions button{flex:1}
</style><script>
(function(){
  const E=id=>document.getElementById(id);
  let purpose='verify', busy=false;
  function show(text,error){const m=E('authMsg');if(!m)return;m.textContent=text;m.className='msg'+(error?' err':'');m.style.display='block'}
  function setOtpUI(on,kind){
    let box=E('otpBox');
    if(!on){if(box)box.remove();return}
    if(!box){box=document.createElement('div');box.id='otpBox';box.innerHTML='<input id="otpCode" class="field" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Enter 6-digit OTP"><div id="otpActions"><button id="verifyOtpBtn" class="btn primary">Verify OTP</button><button id="resendOtpBtn" class="btn outline">Resend OTP</button></div>';E('authMsg').after(box);}
    purpose=kind;E('otpCode').focus();
    E('verifyOtpBtn').onclick=verifyOtp;E('resendOtpBtn').onclick=resendOtp;
  }
  async function post(url,data){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});let d={};try{d=await r.json()}catch{}if(!r.ok){const e=new Error(d.detail||'Request failed');e.status=r.status;throw e}return d}
  async function signup(){if(busy)return;busy=true;try{const email=E('email').value.trim(),name=E('name').value.trim(),password=E('pass').value;if(!name||!email||!password)return show('Enter your name, email and password.',true);const d=await post('/api/auth/signup-otp',{name,email,password});show(d.message,false);setOtpUI(true,'verify')}catch(e){show(e.message,true)}finally{busy=false}}
  async function login(){if(busy)return;busy=true;try{const email=E('email').value.trim(),password=E('pass').value;if(!email||!password)return show('Enter your email and password.',true);const d=await post('/api/auth/login',{email,password});localStorage.setItem('nt',d.token);location.reload()}catch(e){if(e.status===403){try{const d=await post('/api/auth/otp-send',{email:E('email').value.trim(),purpose:'verify'});show('Your email is not verified. '+d.message,false);setOtpUI(true,'verify')}catch(x){show(x.message,true)}}else show(e.message,true)}finally{busy=false}}
  async function verifyOtp(){try{const email=E('email').value.trim(),code=E('otpCode').value.trim();if(!/^\d{6}$/.test(code))return show('Enter the 6-digit OTP.',true);const d=await post('/api/auth/otp-verify',{email,code});localStorage.setItem('nt',d.token);show('Email verified. Signing you in…',false);setTimeout(()=>location.reload(),300)}catch(e){show(e.message,true)}}
  async function resendOtp(){try{const d=await post('/api/auth/otp-send',{email:E('email').value.trim(),purpose});show(d.message,false)}catch(e){show(e.message,true)}}
  async function forgot(){const email=E('email').value.trim();if(!email)return show('Enter your email first.',true);try{const d=await post('/api/auth/otp-send',{email,purpose:'reset'});show(d.message+' Enter the OTP below, then type your new password in the password field.',false);E('pass').value='';E('pass').placeholder='New password (min 6 characters)';setOtpUI(true,'reset');E('authBtn').style.display='none'}catch(e){show(e.message,true)}}
  async function verifyReset(){try{const email=E('email').value.trim(),code=E('otpCode').value.trim(),password=E('pass').value;if(password.length<6)return show('Enter your new password (at least 6 characters).',true);const d=await post('/api/auth/otp-reset',{email,code,password});localStorage.setItem('nt',d.token);show('Password reset successfully. Signing you in…',false);setTimeout(()=>location.reload(),300)}catch(e){show(e.message,true)}}
  function wire(){const btn=E('authBtn'),sw=E('switchBtn'),forgotBtn=E('forgotBtn'),resend=E('resendBtn');if(!btn||btn.dataset.otpWired)return;btn.dataset.otpWired='1';btn.onclick=()=>{const title=E('authTitle')?.textContent||'';if(title.toLowerCase().includes('create'))signup();else login()};if(sw)sw.onclick=()=>{setOtpUI(false);E('pass').placeholder='Password';setTimeout(wire,0)};if(forgotBtn)forgotBtn.onclick=forgot;if(resend)resend.onclick=resendOtp}
  window.addEventListener('load',()=>{wire();setTimeout(wire,150);setTimeout(wire,500);});
  document.addEventListener('click',e=>{if(e.target&&e.target.id==='verifyOtpBtn'&&purpose==='reset')e.target.onclick=verifyReset;});
})();
</script>'''


@app.middleware('http')
async def inject_auth_fix(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == '/' and response.headers.get('content-type','').startswith('text/html'):
        body = response.body
        if body and b'id="auth"' in body and b'id="authBtn"' in body:
            body = body.replace(b'</body>', AUTH_FIX.encode('utf-8') + b'</body>')
            headers = dict(response.headers)
            headers.pop('content-length', None)
            return Response(content=body, status_code=response.status_code, headers=headers, media_type='text/html')
    return response
