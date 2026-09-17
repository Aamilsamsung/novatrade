import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field

from . import main

app = main.app
OTP_TTL_MINUTES = 10
OTP_COOLDOWN_SECONDS = 60
MAX_OTP_ATTEMPTS = 5


def utcnow():
    return datetime.now(timezone.utc)


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def ensure_otp_table():
    c = main.db()
    c.execute('''CREATE TABLE IF NOT EXISTS otp_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        purpose TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        used INTEGER DEFAULT 0,
        sent_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    c.commit()
    c.close()


ensure_otp_table()


class SignupOTP(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    password: str = Field(min_length=6)


class OTPRequest(BaseModel):
    email: EmailStr
    purpose: str = 'verify'


class OTPVerify(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)


class OTPReset(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6)
    password: str = Field(min_length=6)


def find_user(c, email):
    return c.execute('SELECT * FROM users WHERE lower(email)=lower(?)', (email.lower().strip(),)).fetchone()


def send_otp(user_id: int, purpose: str):
    if purpose not in ('verify', 'reset'):
        raise HTTPException(400, 'Invalid OTP purpose')
    c = main.db()
    recent = c.execute(
        'SELECT sent_at FROM otp_codes WHERE user_id=? AND purpose=? ORDER BY id DESC LIMIT 1',
        (user_id, purpose),
    ).fetchone()
    if recent:
        try:
            elapsed = (utcnow() - datetime.fromisoformat(recent['sent_at'])).total_seconds()
            if elapsed < OTP_COOLDOWN_SECONDS:
                c.close()
                raise HTTPException(429, f'Please wait {int(OTP_COOLDOWN_SECONDS - elapsed)} seconds before requesting another OTP.')
        except ValueError:
            pass

    code = f'{secrets.randbelow(1_000_000):06d}'
    now = utcnow()
    expires = now + timedelta(minutes=OTP_TTL_MINUTES)
    c.execute('UPDATE otp_codes SET used=1 WHERE user_id=? AND purpose=? AND used=0', (user_id, purpose))
    c.execute(
        'INSERT INTO otp_codes(user_id,purpose,code_hash,expires_at,sent_at,created_at) VALUES(?,?,?,?,?,?)',
        (user_id, purpose, h(code), expires.isoformat(), now.isoformat(), now.isoformat()),
    )
    c.commit()
    c.close()

    u = main.db().execute('SELECT email,name FROM users WHERE id=?', (user_id,)).fetchone()
    subject = 'Your NovaTrade verification OTP' if purpose == 'verify' else 'Your NovaTrade password reset OTP'
    action = 'verify your email address' if purpose == 'verify' else 'reset your NovaTrade password'
    html = f'''<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px">
      <h2 style="color:#063d2f">NovaTrade</h2>
      <p>Hello {u['name']},</p>
      <p>Use this one-time code to {action}:</p>
      <div style="font-size:32px;font-weight:800;letter-spacing:8px;padding:18px 0">{code}</div>
      <p>This code expires in {OTP_TTL_MINUTES} minutes and can be used once.</p>
      <p>If you did not request this code, you can safely ignore this email.</p>
    </div>'''
    try:
        main.send_email(u['email'], subject, html)
    except Exception as exc:
        c = main.db()
        c.execute('UPDATE otp_codes SET used=1 WHERE user_id=? AND purpose=? AND code_hash=?', (user_id, purpose, h(code)))
        c.commit()
        c.close()
        raise HTTPException(503, 'We could not send the OTP right now. Please try again in a moment.') from exc
    return True


@app.post('/api/auth/signup-otp')
def signup_otp(data: SignupOTP):
    c = main.db()
    existing = find_user(c, str(data.email))
    if existing:
        c.close()
        if existing['verified']:
            raise HTTPException(409, 'Email already registered. Please sign in instead.')
        send_otp(existing['id'], 'verify')
        raise HTTPException(409, 'This email is registered but not verified. A new OTP was sent.')
    try:
        cur = c.execute(
            'INSERT INTO users(email,password,name,created_at,verified) VALUES(?,?,?,?,0)',
            (str(data.email).lower().strip(), main.pwd.hash(data.password), data.name.strip(), utcnow().isoformat()),
        )
        user_id = cur.lastrowid
        main.init_user(c, user_id)
        c.commit()
    except sqlite3.IntegrityError:
        c.close()
        raise HTTPException(409, 'Email already registered. Please sign in instead.')
    c.close()
    send_otp(user_id, 'verify')
    return {'ok': True, 'message': 'Account created. Enter the 6-digit OTP sent to your email.'}


@app.post('/api/auth/otp-send')
def otp_send(data: OTPRequest):
    purpose = data.purpose
    c = main.db()
    u = find_user(c, str(data.email))
    c.close()
    if not u:
        # Avoid revealing whether an email is registered for password-reset requests.
        if purpose == 'reset':
            return {'ok': True, 'message': 'If the account exists, a reset OTP has been sent.'}
        raise HTTPException(404, 'No account found for this email.')
    if purpose == 'verify' and u['verified']:
        return {'ok': True, 'message': 'Your email is already verified. You can sign in.'}
    send_otp(u['id'], purpose)
    return {'ok': True, 'message': 'A new OTP has been sent to your email.'}


@app.post('/api/auth/otp-verify')
def otp_verify(data: OTPVerify):
    c = main.db()
    u = find_user(c, str(data.email))
    if not u:
        c.close()
        raise HTTPException(404, 'Account not found.')
    row = c.execute(
        'SELECT * FROM otp_codes WHERE user_id=? AND purpose="verify" AND used=0 ORDER BY id DESC LIMIT 1',
        (u['id'],),
    ).fetchone()
    if not row:
        c.close()
        raise HTTPException(400, 'No active OTP. Request a new code.')
    if datetime.fromisoformat(row['expires_at']) < utcnow():
        c.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],)); c.commit(); c.close()
        raise HTTPException(400, 'OTP expired. Request a new code.')
    if row['attempts'] >= MAX_OTP_ATTEMPTS:
        c.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],)); c.commit(); c.close()
        raise HTTPException(400, 'Too many incorrect attempts. Request a new OTP.')
    if h(data.code) != row['code_hash']:
        c.execute('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?', (row['id'],)); c.commit(); c.close()
        raise HTTPException(400, 'Incorrect OTP.')
    c.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],))
    c.execute('UPDATE users SET verified=1 WHERE id=?', (u['id'],))
    c.commit(); c.close()
    return {'ok': True, 'token': main.token(u['id']), 'message': 'Email verified successfully.'}


@app.post('/api/auth/otp-reset')
def otp_reset(data: OTPReset):
    c = main.db()
    u = find_user(c, str(data.email))
    if not u:
        c.close(); raise HTTPException(400, 'Invalid reset request.')
    row = c.execute(
        'SELECT * FROM otp_codes WHERE user_id=? AND purpose="reset" AND used=0 ORDER BY id DESC LIMIT 1',
        (u['id'],),
    ).fetchone()
    if not row:
        c.close(); raise HTTPException(400, 'No active reset OTP. Request a new code.')
    if datetime.fromisoformat(row['expires_at']) < utcnow():
        c.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],)); c.commit(); c.close(); raise HTTPException(400, 'OTP expired. Request a new code.')
    if row['attempts'] >= MAX_OTP_ATTEMPTS:
        c.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],)); c.commit(); c.close(); raise HTTPException(400, 'Too many incorrect attempts. Request a new OTP.')
    if h(data.code) != row['code_hash']:
        c.execute('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?', (row['id'],)); c.commit(); c.close(); raise HTTPException(400, 'Incorrect OTP.')
    c.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],))
    c.execute('UPDATE users SET password=?,verified=1 WHERE id=?', (main.pwd.hash(data.password), u['id']))
    c.commit(); c.close()
    return {'ok': True, 'token': main.token(u['id']), 'message': 'Password reset successfully.'}
