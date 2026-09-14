# NovaTrade Pro

A professional trading-dashboard starter with account login, paper trading, bot controls, watchlist, order ticket, and a broker OAuth integration point.

## Important
- The included trading engine is paper trading by default.
- NovaTrade does not hold customer money. Real-money trading must be routed through a regulated broker account.
- Upstox OAuth support is included as a secure server-side integration skeleton. Configure `UPSTOX_CLIENT_ID`, `UPSTOX_CLIENT_SECRET`, and `UPSTOX_REDIRECT_URI` as server environment variables before enabling live trading.
- Before production live trading, add persistent database storage, encryption/key management, audit logs, CSRF/state hardening, rate limits, monitoring, broker order reconciliation, and the regulatory/compliance controls applicable to your business and market.
