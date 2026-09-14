from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import random
from datetime import datetime, timezone

app=FastAPI(title="NovaTrade Paper Engine")
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
def home():
    return FileResponse("frontend/index.html")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

class Settings(BaseModel):
    amount: float=Field(1000,gt=0)
    risk_pct: float=Field(1,gt=0,le=5)
    stop_pct: float=Field(2,gt=0,le=20)
    target_pct: float=Field(4,gt=0,le=50)

s={"cash":1000.0,"start":1000.0,"price":100.0,"running":False,"position":None,"trades":[]}

def state():
    value=s["cash"]+(s["position"]["qty"]*s["price"] if s["position"] else 0)
    return {**s,"equity":round(value,2),"pnl":round(value-s["start"],2)}

@app.get("/api/health")
def health(): return {"ok":True}

@app.get("/api/state")
def get_state(): return state()

@app.post("/api/reset")
def reset(x:Settings):
    s.update(cash=x.amount,start=x.amount,price=100.0,running=False,position=None,trades=[])
    return state()

@app.post("/api/start")
def start(): s["running"]=True; return state()

@app.post("/api/stop")
def stop(): s["running"]=False; return state()

@app.post("/api/close")
def close():
    p=s["position"]
    if p:
        pnl=(s["price"]-p["entry"])*p["qty"]; s["cash"]+=p["qty"]*s["price"]
        s["trades"].append({"time":datetime.now(timezone.utc).isoformat(),"side":"SELL","qty":p["qty"],"price":round(s["price"],2),"pnl":round(pnl,2),"reason":"manual"})
        s["position"]=None
    return state()

@app.post("/api/tick")
def tick():
    s["price"]=max(1,s["price"]*(1+random.gauss(0,0.004)))
    p=s["position"]
    if p and (s["price"]<=p["stop"] or s["price"]>=p["target"]):
        reason="stop" if s["price"]<=p["stop"] else "target"
        pnl=(s["price"]-p["entry"])*p["qty"]; s["cash"]+=p["qty"]*s["price"]
        s["trades"].append({"time":datetime.now(timezone.utc).isoformat(),"side":"SELL","qty":p["qty"],"price":round(s["price"],2),"pnl":round(pnl,2),"reason":reason})
        s["position"]=None
    if s["running"] and s["position"] is None:
        qty=max(1,int((s["cash"]*0.25)/s["price"]))
        if qty*s["price"]<=s["cash"]:
            e=s["price"]; s["cash"]-=qty*e
            s["position"]={"qty":qty,"entry":e,"stop":e*.98,"target":e*1.04,"symbol":"DEMO"}
            s["trades"].append({"time":datetime.now(timezone.utc).isoformat(),"side":"BUY","qty":qty,"price":round(e,2),"pnl":0,"reason":"demo"})
    return state()
