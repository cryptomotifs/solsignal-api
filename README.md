# SolSignal API — Solana Token Safety Scanner

**4 sources. 1 verdict. Under 2 seconds.**

Scan any Solana token for honeypots, rug pulls, and scams. Aggregates DexScreener, RugCheck, GoPlus, and Jupiter simulation into a single **SAFE / CAUTION / AVOID / RUG** verdict with a 0-100 safety score.

**Live at:** https://solsignal-api.onrender.com

## Quick Start

```bash
# Scan any token (10 free/day)
curl https://solsignal-api.onrender.com/scan/DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263

# Safety-screened trending tokens (3 free/day)
curl https://solsignal-api.onrender.com/trending

# Public accuracy track record
curl https://solsignal-api.onrender.com/track/stats
```

## Example Response

```json
{
  "mint": "...",
  "symbol": "SCAM",
  "verdict": "AVOID",
  "safety_score": 32,
  "price_usd": 0.000042,
  "market_cap": 85000,
  "liquidity_usd": 12000,
  "volume_24h": 45000,
  "age_hours": 3.5,
  "checks": {
    "honeypot": {"pass": false, "detail": "sell quote failed"},
    "sell_tax": {"pass": true, "tax_pct": 0.0},
    "lp_locked": {"pass": false},
    "mintable": {"pass": true},
    "rug_score": {"pass": false, "score": 4200, "flags": ["LP Unlocked"]},
    "holder_concentration": {"pass": false, "top10_pct": 78.3, "creator_pct": 22.1},
    "liquidity": {"pass": true},
    "volume": {"pass": true},
    "age": {"pass": false, "hours": 3.5}
  },
  "risk_flags": ["HONEYPOT_SUSPECTED", "LP_UNLOCKED", "CONCENTRATED_HOLDINGS"],
  "sources": {"dexscreener": true, "rugcheck": true, "goplus": true, "jupiter_sim": true},
  "latency_ms": 1200
}
```

## Endpoints

| Endpoint | Description | Auth |
|----------|-------------|------|
| `GET /scan/{mint}` | Scan any Solana token | 10 free/day, API key, or x402 |
| `GET /trending` | Safety-screened trending tokens | 3 free/day, API key, or x402 |
| `GET /track/stats` | Public accuracy track record | Free |
| `GET /track/{mint}` | Scan history for a token | Free |
| `GET /health` | System status | Free |
| `GET /docs` | Interactive API docs | Free |

### Legacy Endpoints (Experimental)

| Endpoint | Description | Price |
|----------|-------------|-------|
| `GET /signals/live/{mint}` | 646-agent scoring | $0.05 |
| `GET /signals/trending` | Top agent picks | $0.01 |
| `GET /signals/agent/{name}` | Single agent scores | $0.005 |
| `GET /signals/analysis/{mint}` | Multi-agent consensus | $0.05 |
| `GET /signals/bulk` | Bulk scores | $0.10 |

## Data Sources

| Source | What it checks | Cost |
|--------|---------------|------|
| **DexScreener** | Price, volume, liquidity, age, buy/sell counts | Free |
| **RugCheck** | LP lock, top holder %, creator %, risk flags | Free |
| **GoPlus** | Honeypot, sell tax, mintable, proxy, blacklist | Free |
| **Jupiter** | Buy + sell simulation (actual honeypot test) | Free |

## Pricing

| Tier | Price | Scans | Trending |
|------|-------|-------|----------|
| Free | $0 | 10/day (by IP) | 3/day |
| Developer | $9/month | 1,000/month | Unlimited |
| Pro | $29/month | 5,000/month | Unlimited |
| x402 | $0.01/scan | Pay per call | $0.01/call |

## Authentication

Three options:

1. **Free tier** — just call the endpoint, rate limited by IP
2. **API key** — `X-API-Key` header
3. **x402** — USDC on Solana, automatic micropayments

## Safety Score

Score starts at 100 and is reduced for each issue found:

| Issue | Deduction |
|-------|-----------|
| Honeypot (sell fails) | -40 |
| GoPlus honeypot flag | -35 |
| High sell tax (Jupiter) | -30 |
| High sell tax (GoPlus) | -15 |
| High rug score | -15 |
| LP unlocked | -15 |
| Extremely new (<1h) | -15 |
| Mintable | -10 |
| Proxy contract | -10 |
| Blacklist function | -10 |
| Concentrated holdings | -10 |
| Creator high holdings | -10 |
| Low liquidity | -10 |
| New token (<24h) | -5 |
| Low volume | -5 |

**Verdicts:** SAFE (75+) · CAUTION (50-74) · AVOID (25-49) · RUG (0-24)

## Track Record

Every `/scan` call is recorded. A background job checks token prices 1h and 24h later. The `/track/stats` endpoint publishes verifiable accuracy — e.g., "X% of tokens we said AVOID lost >20% in 24h."

## Token

**Sol Signal AI (SSAI)** on pump.fun: [`4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump`](https://pump.fun/coin/4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump)

## Self-Hosting

```bash
git clone https://github.com/cryptomotifs/solsignal-api.git
cd solsignal-api
pip install -r requirements.txt
uvicorn app:app --port 8402
```

Or with Docker:

```bash
docker build -t solsignal .
docker run -p 8402:8402 -e SIGNAL_WALLET=your_solana_wallet solsignal
```
