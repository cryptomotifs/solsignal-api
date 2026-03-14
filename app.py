"""SolSignal API — Arena-calibrated trading signals from 646 AI agents.

Standalone deployment version. No dependencies on the full bot codebase.
Reads pre-computed data from JSON/SQLite files in the data/ directory.

Deployment:
    Render.com, Railway.app, Fly.io, or any Docker host.
    Set SIGNAL_WALLET env var to enable x402 USDC payments.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

# --- Config ---
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ARENA_DB = os.path.join(DATA_DIR, "arena_snapshots.db")
RESULTS_DB = os.path.join(DATA_DIR, "arena_results.db")
BOOST_CONFIGS = os.path.join(DATA_DIR, "agent_boost_configs.json")
API_KEYS_FILE = os.path.join(DATA_DIR, "api_keys.json")

SOLANA_WALLET = os.environ.get("SIGNAL_WALLET", "")
X402_FACILITATOR = os.environ.get("X402_FACILITATOR", "https://x402.org/facilitator")
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

PRICES = {
    "trending": 10000,       # $0.01
    "agent": 5000,           # $0.005
    "analysis": 50000,       # $0.05
    "bulk": 100000,          # $0.10
}

# --- App ---
app = FastAPI(
    title="SolSignal API",
    description=(
        "Arena-calibrated trading signals from 646 AI agents. "
        "Each agent tested against 18,000+ real Solana token snapshots. "
        "Pay per request via x402 (USDC on Solana) or API key."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    expose_headers=["PAYMENT-REQUIRED", "PAYMENT-RESPONSE"],
)

# --- Caches ---
_boost_cache: dict | None = None
_boost_cache_ts: float = 0
_api_keys: dict = {}
_revenue_log: list[dict] = []


def _load_boost_configs() -> dict:
    global _boost_cache, _boost_cache_ts
    now = time.time()
    if _boost_cache and now - _boost_cache_ts < 300:  # 5-min cache
        return _boost_cache
    try:
        with open(BOOST_CONFIGS, "r") as f:
            _boost_cache = json.load(f)
            _boost_cache_ts = now
    except (FileNotFoundError, json.JSONDecodeError):
        _boost_cache = {}
    return _boost_cache


def _load_api_keys() -> dict:
    global _api_keys
    if _api_keys:
        return _api_keys
    try:
        with open(API_KEYS_FILE, "r") as f:
            _api_keys = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Create a demo key
        key = f"sk_demo_{secrets.token_hex(16)}"
        _api_keys = {key: {"name": "Demo", "credits": 1000, "total_calls": 0}}
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(API_KEYS_FILE, "w") as f:
            json.dump(_api_keys, f, indent=2)
    return _api_keys


def _check_api_key(key: str | None) -> bool:
    if not key:
        return False
    keys = _load_api_keys()
    entry = keys.get(key)
    return bool(entry and entry.get("credits", 0) > 0)


def _deduct_credit(key: str):
    keys = _load_api_keys()
    if key in keys:
        keys[key]["credits"] = keys[key].get("credits", 0) - 1
        keys[key]["total_calls"] = keys[key].get("total_calls", 0) + 1
        try:
            with open(API_KEYS_FILE, "w") as f:
                json.dump(keys, f, indent=2)
        except Exception:
            pass


def _log_revenue(endpoint: str, amount: float, method: str):
    _revenue_log.append({
        "endpoint": endpoint,
        "amount_usdc": amount,
        "method": method,
        "ts": datetime.now(timezone.utc).isoformat(),
    })


# --- x402 ---

def _build_402(resource: str, price_key: str) -> Response:
    amount = PRICES.get(price_key, 10000)
    if not SOLANA_WALLET:
        return Response(
            status_code=402,
            content=json.dumps({
                "error": "Payment required",
                "message": "Use X-API-Key header or configure x402 wallet",
                "pricing": {k: f"${v / 1_000_000:.4f}" for k, v in PRICES.items()},
            }),
            media_type="application/json",
        )
    payload = {
        "x402Version": 2,
        "accepts": [{
            "scheme": "exact",
            "network": SOLANA_NETWORK,
            "maxAmountRequired": str(amount),
            "resource": resource,
            "description": f"SolSignal: {price_key}",
            "payTo": SOLANA_WALLET,
            "asset": USDC_MINT,
            "maxTimeoutSeconds": 60,
        }],
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return Response(
        status_code=402,
        content=json.dumps(payload),
        media_type="application/json",
        headers={"PAYMENT-REQUIRED": encoded},
    )


async def _verify_x402(payment_header: str, resource: str, price_key: str) -> bool:
    if not SOLANA_WALLET:
        return False
    amount = PRICES.get(price_key, 10000)
    req_data = {
        "scheme": "exact",
        "network": SOLANA_NETWORK,
        "maxAmountRequired": str(amount),
        "resource": resource,
        "payTo": SOLANA_WALLET,
        "asset": USDC_MINT,
        "maxTimeoutSeconds": 60,
    }
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{X402_FACILITATOR}/verify",
                json={"payload": payment_header, "paymentRequirements": req_data},
            )
            if resp.status_code == 200:
                return resp.json().get("isValid", False)
    except Exception:
        pass
    return False


async def _gate(request: Request, resource: str, price_key: str) -> Response | None:
    """Returns None if authorized, or a 402 Response."""
    api_key = request.headers.get("x-api-key")
    if _check_api_key(api_key):
        _deduct_credit(api_key)
        _log_revenue(resource, PRICES.get(price_key, 10000) / 1_000_000, "api_key")
        return None

    payment = request.headers.get("payment-signature") or request.headers.get("x-payment")
    if payment:
        if await _verify_x402(payment, resource, price_key):
            _log_revenue(resource, PRICES.get(price_key, 10000) / 1_000_000, "x402")
            return None

    return _build_402(resource, price_key)


# --- Data queries ---

def _query_db(db_path: str, sql: str, params: tuple = ()) -> list[dict]:
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


# --- Endpoints ---

@app.get("/")
async def root():
    configs = _load_boost_configs()
    return {
        "name": "SolSignal API",
        "tagline": "646 AI agents. 18,000+ snapshots. Arena-calibrated precision.",
        "version": "1.0.0",
        "agents": len(configs),
        "endpoints": {
            "/health": "Free - System status",
            "/agents": "Free - All agents with precision stats",
            "/signals/trending": "$0.01 - Top tier1 picks from best agents",
            "/signals/agent/{name}": "$0.005 - Specific agent's scores",
            "/signals/analysis/{mint}": "$0.05 - Full multi-agent token consensus",
            "/signals/bulk": "$0.10 - All scores for all recent tokens",
        },
        "auth": ["x402 (USDC on Solana)", "API key (X-API-Key header)"],
        "x402_enabled": bool(SOLANA_WALLET),
        "token": {
            "name": "Sol Signal AI",
            "symbol": "SSAI",
            "mint": "4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump",
            "platform": "pump.fun",
            "url": "https://pump.fun/coin/4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump",
        },
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    configs = _load_boost_configs()
    snap_count = 0
    if os.path.exists(ARENA_DB):
        rows = _query_db(ARENA_DB, "SELECT COUNT(*) as cnt FROM snapshots")
        snap_count = rows[0]["cnt"] if rows else 0
    return {
        "status": "healthy",
        "agents": len(configs),
        "snapshots": snap_count,
        "x402": bool(SOLANA_WALLET),
        "revenue_calls": len(_revenue_log),
    }


@app.get("/agents")
async def list_agents():
    configs = _load_boost_configs()
    agents = sorted(
        [{"name": n, "precision": c.get("boosted_precision", 0),
          "original": c.get("original_precision", 0), "threshold": c.get("threshold", 0.5)}
         for n, c in configs.items()],
        key=lambda x: x["precision"], reverse=True,
    )
    return {"total": len(agents), "agents": agents}


@app.get("/signals/trending")
async def trending(request: Request, limit: int = 20):
    block = await _gate(request, "/signals/trending", "trending")
    if block:
        return block

    configs = _load_boost_configs()
    top = sorted(configs.items(), key=lambda x: x[1].get("boosted_precision", 0), reverse=True)[:limit]
    top_agents = [{"agent": n, "precision": c.get("boosted_precision", 0),
                   "threshold": c.get("threshold", 0.5), "picks": c.get("boosted_picks", 0)}
                  for n, c in top]

    snaps = _query_db(ARENA_DB, """
        SELECT mint, symbol, snapshot_ts, price_usd, volume_24h, liquidity_usd,
               price_change_1h, pct_change_1h
        FROM snapshots ORDER BY snapshot_ts DESC LIMIT 20
    """)

    return {"top_agents": top_agents, "latest_snapshots": snaps,
            "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/signals/agent/{agent_name}")
async def agent_scores(request: Request, agent_name: str, limit: int = 50):
    block = await _gate(request, f"/signals/agent/{agent_name}", "agent")
    if block:
        return block

    configs = _load_boost_configs()
    cfg = configs.get(agent_name)
    if not cfg:
        return {"error": f"Agent '{agent_name}' not found", "total_agents": len(configs)}

    scores = _query_db(RESULTS_DB, """
        SELECT agent_name, mint, score, tier, snapshot_ts
        FROM results WHERE agent_name = ? ORDER BY snapshot_ts DESC LIMIT ?
    """, (agent_name, limit))

    return {"agent": agent_name, "precision": cfg.get("boosted_precision", 0),
            "threshold": cfg.get("threshold", 0.5), "scores": scores,
            "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/signals/analysis/{mint}")
async def analysis(request: Request, mint: str):
    block = await _gate(request, f"/signals/analysis/{mint}", "analysis")
    if block:
        return block

    configs = _load_boost_configs()
    rows = _query_db(RESULTS_DB, """
        SELECT agent_name, score, tier FROM results WHERE mint = ? ORDER BY score DESC
    """, (mint,))

    if not rows:
        return {"error": f"No scores for {mint}"}

    tier1 = [r for r in rows if r["tier"] == "tier1"]
    avg = sum(r["score"] for r in rows) / len(rows)
    top = [{"agent": r["agent_name"], "score": r["score"],
            "precision": configs.get(r["agent_name"], {}).get("boosted_precision", 0)}
           for r in tier1[:10]]

    t1_pct = len(tier1) / len(rows) * 100
    consensus = ("STRONG_BUY" if t1_pct > 30 else "BUY" if t1_pct > 15
                 else "NEUTRAL" if t1_pct > 5 else "AVOID")

    return {"mint": mint, "agents_scored": len(rows), "tier1_count": len(tier1),
            "tier1_pct": round(t1_pct, 1), "avg_score": round(avg, 4),
            "consensus": consensus, "top_agents": top,
            "generated_at": datetime.now(timezone.utc).isoformat()}


@app.get("/signals/bulk")
async def bulk(request: Request):
    block = await _gate(request, "/signals/bulk", "bulk")
    if block:
        return block

    configs = _load_boost_configs()
    top50 = sorted(configs.items(), key=lambda x: x[1].get("boosted_precision", 0), reverse=True)[:50]
    snaps = _query_db(ARENA_DB, """
        SELECT mint, symbol, snapshot_ts, price_usd, volume_24h, liquidity_usd,
               price_change_1h, pct_change_1h, pct_change_4h, pct_change_24h
        FROM snapshots ORDER BY snapshot_ts DESC LIMIT 100
    """)

    return {
        "top_agents": [{"agent": n, "precision": c.get("boosted_precision", 0),
                        "threshold": c.get("threshold", 0.5)} for n, c in top50],
        "snapshots": snaps, "total_agents": len(configs),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/revenue")
async def revenue():
    total = sum(r["amount_usdc"] for r in _revenue_log)
    by_ep = {}
    for r in _revenue_log:
        by_ep[r["endpoint"]] = by_ep.get(r["endpoint"], 0) + r["amount_usdc"]
    return {"total_usdc": round(total, 4), "calls": len(_revenue_log),
            "by_endpoint": by_ep, "recent": _revenue_log[-10:]}
