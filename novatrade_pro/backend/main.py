import os, time, secrets, hashlib, hmac
from typing import Optional
import httpx
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = FastAPI(title="NovaTrade", version="2.0")
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "frontend")), name="static")

SECRET = os.getenv("NOVATRADE_SECRET", "change-this-secret-in-production")
signer = URLSafeTimedSerializer(SECRET)
USERS = {}
SESSIONS = {}
BROKER = {"provider": None, "access_token": None}
STATE = {
    "cash": 1000.0, "starting_cash": 1000.0, "mode": "paper", "running": False,
    "symbol": "RELIANCE", "price": 1478.20, "position": 0, "avg_price": 0.0,
    "trades": [], "watchlist": ["RELIANCE", "TCS", "INFY", "HDFCBANK", "ICICIBANK"]
}

class Auth(BaseModel):
    email: str
    password: str

class Order(BaseModel):
    symbol: str
    side: str
    quantity: int
    order_type: str = "MARKET"
    price: Optional[float] = None

class BotControl(BaseModel):
    running: bool
    mode: str = "paper"


def hash_pw(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210000).hex()
    return salt + "$" + digest


def verify_pw(password: str, stored: str):
    salt, digest = stored.split("$", 1)
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210000).hex()
    return hmac.compare_digest(check, digest)


def token_for(email):
    return signer.dumps({"email": email})


def current_user(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Login required")
    try:
        data = signer.loads(authorization[7:], max_age=60 * 60 * 24 * 7)
        return data["email"]
    except (BadSignature, SignatureExpired):
        raise HTTPException(401, "Session expired")

@app.get("/")
def home():
    return FileResponse(os.path.join(BASE, "frontend", "index.html"))

@app.get("/api/health")
def health():
    return {"ok": True, "service": "NovaTrade", "mode": STATE["mode"]}

@app.post("/api/auth/register")
def register(body: Auth):
    email = body.email.lower().strip()
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if email in USERS:
        raise HTTPException(409, "Account already exists")
    USERS[email] = hash_pw(body.password)
    return {"token": token_for(email), "email": email}

@app.post("/api/auth/login")
def login(body: Auth):
    email = body.email.lower().strip()
    if email not in USERS or not verify_pw(body.password, USERS[email]):
        raise HTTPException(401, "Invalid email or password")
    return {"token": token_for(email), "email": email}

@app.get("/api/me")
def me(authorization: Optional[str] = Header(None)):
    email = current_user(authorization)
    return {"email": email, "broker_connected": bool(BROKER["access_token"]), "mode": STATE["mode"]}

@app.get("/api/state")
def state(authorization: Optional[str] = Header(None)):
    current_user(authorization)
    equity = STATE["cash"] + STATE["position"] * STATE["price"]
    pnl = equity - STATE["starting_cash"]
    return {**STATE, "equity": round(equity,2), "pnl": round(pnl,2)}

@app.post("/api/bot")
def bot(body: BotControl, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    if body.mode not in ("paper", "live"):
        raise HTTPException(400, "Invalid mode")
    if body.mode == "live" and not BROKER["access_token"]:
        raise HTTPException(400, "Connect a supported broker before enabling live trading")
    STATE["mode"] = body.mode
    STATE["running"] = body.running
    return {"running": STATE["running"], "mode": STATE["mode"]}

@app.post("/api/order")
async def order(body: Order, authorization: Optional[str] = Header(None)):
    current_user(authorization)
    if body.quantity <= 0 or body.side.upper() not in ("BUY", "SELL"):
        raise HTTPException(400, "Invalid order")
    side = body.side.upper()
    symbol = body.symbol.upper()
    if STATE["mode"] == "live":
        if not BROKER["access_token"]:
            raise HTTPException(400, "Broker not connected")
        # Live order routing intentionally requires a configured broker adapter.
        # This starter uses Upstox OAuth/token plumbing below; credentials remain server-side.
        raise HTTPException(501, "Live broker order adapter is not configured yet")
    px = float(body.price or STATE["price"])
    value = px * body.quantity
    if side == "BUY":
        if value > STATE["cash"]: raise HTTPException(400, "Insufficient paper cash")
        new_qty = STATE["position"] + body.quantity
        STATE["avg_price"] = ((STATE["avg_price"] * STATE["position"]) + value) / new_qty if new_qty else 0
        STATE["position"] = new_qty; STATE["cash"] -= value
    else:
        if body.quantity > STATE["position"]: raise HTTPException(400, "Insufficient paper position")
        STATE["position"] -= body.quantity; STATE["cash"] += value
        if STATE["position"] == 0: STATE["avg_price"] = 0
    STATE["trades"].insert(0, {"time": int(time.time()), "symbol": symbol, "side": side, "qty": body.quantity, "price": px, "mode": "paper"})
    return {"ok": True, "mode": "paper"}

@app.post("/api/reset")
def reset(authorization: Optional[str] = Header(None)):
    current_user(authorization)
    STATE.update(cash=1000.0, starting_cash=1000.0, mode="paper", running=False, position=0, avg_price=0.0, trades=[])
    return {"ok": True}

# ---- Upstox OAuth integration skeleton ----
@app.get("/api/broker/upstox/connect")
def upstox_connect(authorization: Optional[str] = Header(None)):
    email = current_user(authorization)
    client_id = os.getenv("UPSTOX_CLIENT_ID")
    redirect_uri = os.getenv("UPSTOX_REDIRECT_URI")
    if not client_id or not redirect_uri:
        raise HTTPException(503, "UPSTOX_CLIENT_ID and UPSTOX_REDIRECT_URI are not configured")
    state = signer.dumps({"email": email})
    url = ("https://api.upstox.com/v2/login/authorization/dialog?response_type=code"
           f"&client_id={client_id}&redirect_uri={redirect_uri}&state={state}")
    return {"url": url}

@app.get("/api/broker/upstox/callback")
async def upstox_callback(code: str, state: str):
    try: email = signer.loads(state, max_age=600)["email"]
    except Exception: raise HTTPException(400, "Invalid OAuth state")
    client_id, secret, redirect_uri = os.getenv("UPSTOX_CLIENT_ID"), os.getenv("UPSTOX_CLIENT_SECRET"), os.getenv("UPSTOX_REDIRECT_URI")
    if not all([client_id, secret, redirect_uri]): raise HTTPException(503, "Upstox environment variables are missing")
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post("https://api.upstox.com/v2/login/authorization/token", data={
            "code": code, "client_id": client_id, "client_secret": secret,
            "redirect_uri": redirect_uri, "grant_type": "authorization_code"
        }, headers={"Accept":"application/json"})
    if r.status_code >= 400: raise HTTPException(r.status_code, "Broker authorization failed")
    BROKER.update(provider="upstox", access_token=r.json().get("access_token"))
    return RedirectResponse(url="/?broker=connected")
