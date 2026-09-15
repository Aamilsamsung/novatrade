# NovaTrade

Professional paper-trading dashboard with portfolio tracking, NSE demo market data, paper orders, authentication, and Bot Trading controls.

## Render
Build: `pip install -r backend/requirements.txt`
Start: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

The repository root intentionally contains `backend/`, `frontend/`, and `render.yaml` so Render can deploy with an empty Root Directory.

## Safety
This deployment is paper-only. Live trading is disabled in the application. Demo prices are simulated and are not real-time market prices. Paper results do not guarantee future returns.
