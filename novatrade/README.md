# NovaTrade

A professional trading workspace with account authentication, portfolio tracking, paper orders, configurable Nova Bot settings, stock watchlists, and an optional Upstox OAuth/live-order connector.

## Deploy on Render

Repository root must contain `backend/`, `frontend/`, `render.yaml`, and `README.md`.

Build: `pip install -r backend/requirements.txt`
Start: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

## Required production environment variables

- `JWT_SECRET` — long random secret.
- `UPSTOX_CLIENT_ID` — your Upstox developer app client ID.
- `UPSTOX_CLIENT_SECRET` — keep server-side only.
- `UPSTOX_REDIRECT_URI` — exact registered callback, e.g. `https://YOUR-DOMAIN/api/broker/upstox/callback`.
- `LIVE_TRADING_ENABLED=false` initially. Set to `true` only after broker/app/regulatory setup and thorough testing.

## Live trading

NovaTrade never asks users to enter their broker password into NovaTrade. Upstox OAuth handles broker login and returns an access token. Live order placement is intentionally guarded by `LIVE_TRADING_ENABLED` and requires a connected broker. The live connector currently accepts `TOKEN:<Upstox instrument_token>` for an order so an instrument-master mapping can be added safely before production.

Do not treat this project as a guaranteed-profit system. Automated trading can lose money. Paper-test strategies before enabling live execution, and comply with your broker/exchange/regulatory requirements.
