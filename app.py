"""SolSignal API — Token Safety Scanner + Arena-calibrated trading signals.

Standalone deployment version. No dependencies on the full bot codebase.

Primary product: /scan/{mint} — aggregates 4 free security sources (DexScreener,
RugCheck, GoPlus, Jupiter) into a single SAFE/CAUTION/AVOID/RUG verdict in <2s.

Legacy: /signals/* endpoints — 646 AI agent scoring (experimental).

Deployment:
    Render.com, Railway.app, Fly.io, or any Docker host.
    Set SIGNAL_WALLET env var to enable x402 USDC payments.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
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
    "scan": 10000,           # $0.01
    "trending": 10000,       # $0.01
    "agent": 5000,           # $0.005
    "analysis": 50000,       # $0.05
    "bulk": 100000,          # $0.10
}

# --- Free tier rate limiting ---
# IP -> {date_str: count}
_free_tier_usage: dict[str, dict[str, int]] = {}
FREE_SCAN_DAILY = 10
FREE_TRENDING_DAILY = 3


def _check_free_tier(ip: str, endpoint: str) -> bool:
    """Check if IP has free tier quota remaining. Returns True if allowed."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{ip}:{endpoint}"

    if key not in _free_tier_usage:
        _free_tier_usage[key] = {}

    usage = _free_tier_usage[key]

    # Clean old dates
    old_keys = [d for d in usage if d != today]
    for k in old_keys:
        del usage[k]

    limit = FREE_SCAN_DAILY if endpoint == "scan" else FREE_TRENDING_DAILY
    current = usage.get(today, 0)
    return current < limit


def _record_free_usage(ip: str, endpoint: str):
    """Record a free tier usage."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{ip}:{endpoint}"
    if key not in _free_tier_usage:
        _free_tier_usage[key] = {}
    _free_tier_usage[key][today] = _free_tier_usage[key].get(today, 0) + 1


# --- Background task ---
_background_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle — starts background outcome backfiller."""
    task = asyncio.create_task(_outcome_backfill_loop())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


async def _outcome_backfill_loop():
    """Run outcome backfill every 30 minutes."""
    while True:
        try:
            await asyncio.sleep(1800)  # 30 min
            from tracker import backfill_outcomes
            await backfill_outcomes()
        except asyncio.CancelledError:
            break
        except Exception:
            pass


# --- App ---
app = FastAPI(
    title="SolSignal API",
    description=(
        "Solana Token Safety Scanner — aggregates DexScreener, RugCheck, GoPlus, "
        "and Jupiter simulation into a single SAFE/CAUTION/AVOID/RUG verdict. "
        "Plus experimental 646-agent scoring. "
        "Pay per request via x402 (USDC on Solana) or API key."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
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


async def _gate_or_free(request: Request, resource: str, price_key: str, free_endpoint: str) -> Response | None:
    """Like _gate, but allows free tier by IP first."""
    # Check API key / x402 first
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

    # Free tier check by IP
    ip = request.client.host if request.client else "unknown"
    if _check_free_tier(ip, free_endpoint):
        _record_free_usage(ip, free_endpoint)
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


# =========================================================================
# PRIMARY ENDPOINTS — Token Safety Scanner
# =========================================================================

@app.get("/")
async def root():
    configs = _load_boost_configs()
    return {
        "name": "SolSignal API",
        "tagline": "Solana Token Safety Scanner — 4 sources, 1 verdict, <2 seconds.",
        "version": "2.0.0",
        "endpoints": {
            "## Safety Scanner (PRIMARY)": "---",
            "/scan/{mint}": "Scan ANY Solana token — SAFE/CAUTION/AVOID/RUG verdict (10 free/day)",
            "/trending": "Safety-screened trending tokens (3 free/day)",
            "/track/stats": "Free — Public accuracy track record",
            "/track/{mint}": "Free — Scan history for a specific token",
            "## Legacy Signals (experimental)": "---",
            "/signals/live/{mint}": "$0.05 — 646-agent scoring (experimental, use /scan for safety)",
            "/signals/trending": "$0.01 — Top tier1 picks from best agents",
            "/signals/agent/{name}": "$0.005 — Specific agent's scores",
            "/signals/analysis/{mint}": "$0.05 — Full multi-agent consensus (historical)",
            "/signals/bulk": "$0.10 — All scores for all recent tokens",
            "## System": "---",
            "/health": "Free — System status",
            "/agents": "Free — All agents with precision stats",
            "/docs": "Interactive API docs",
        },
        "pricing": {
            "free": "10 scans/day + 3 trending/day (by IP)",
            "developer": "$9/month — 1000 scans/month",
            "pro": "$29/month — 5000 scans/month",
            "x402": "$0.01/scan (USDC on Solana)",
        },
        "auth": ["Free tier (IP)", "API key (X-API-Key header)", "x402 (USDC on Solana)"],
        "x402_enabled": bool(SOLANA_WALLET),
        "sources": ["DexScreener", "RugCheck", "GoPlus", "Jupiter Simulation"],
        "agents": len(configs),
        "token": {
            "name": "Sol Signal AI",
            "symbol": "SSAI",
            "mint": "4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump",
            "platform": "pump.fun",
            "url": "https://pump.fun/coin/4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump",
        },
        "docs": "/docs",
    }


@app.get("/scan/{mint}")
async def scan(request: Request, mint: str):
    """Scan a Solana token for safety — aggregates 4 sources into one verdict.

    Sources: DexScreener (market data), RugCheck (LP/holders), GoPlus (honeypot/tax),
    Jupiter (buy+sell simulation). All fetched in parallel.

    Free tier: 10 scans/day per IP. Also accepts API key or x402 payment.
    """
    block = await _gate_or_free(request, f"/scan/{mint}", "scan", "scan")
    if block:
        return block

    from scanner import scan_token
    from tracker import record_scan

    result = await scan_token(mint)

    # Record in tracker (non-blocking, ignore errors)
    if "error" not in result:
        try:
            record_scan(
                mint=mint,
                symbol=result.get("symbol", "???"),
                verdict=result["verdict"],
                safety_score=result["safety_score"],
                price=result.get("price_usd", 0) or 0,
            )
        except Exception:
            pass

    return result


@app.get("/trending")
async def trending_safety(request: Request, limit: int = 20):
    """Safety-screened trending tokens — fetches DexScreener trending + scans each.

    Free tier: 3 calls/day per IP. Also accepts API key or x402 payment.
    """
    block = await _gate_or_free(request, "/trending", "trending", "trending")
    if block:
        return block

    from scanner import scan_trending

    return await scan_trending(limit=min(limit, 30))


@app.get("/track/stats")
async def track_stats():
    """Public accuracy track record — shows how our verdicts perform over time.

    Every /scan call is recorded. Background job checks prices 1h/24h later.
    This endpoint shows aggregate accuracy: "X% of tokens we said AVOID lost >20% in 24h."
    """
    from tracker import get_stats
    return get_stats()


@app.get("/track/{mint}")
async def track_token(mint: str):
    """Scan history for a specific token — all past scans with outcomes."""
    from tracker import get_token_history
    return get_token_history(mint)


# =========================================================================
# SYSTEM ENDPOINTS
# =========================================================================

@app.get("/health")
async def health():
    configs = _load_boost_configs()
    snap_count = 0
    if os.path.exists(ARENA_DB):
        rows = _query_db(ARENA_DB, "SELECT COUNT(*) as cnt FROM snapshots")
        snap_count = rows[0]["cnt"] if rows else 0

    from tracker import get_stats
    try:
        stats = get_stats()
        total_scans = stats.get("total_scans", 0)
    except Exception:
        total_scans = 0

    return {
        "status": "healthy",
        "version": "2.0.0",
        "scanner": {
            "total_scans": total_scans,
            "sources": ["dexscreener", "rugcheck", "goplus", "jupiter_sim"],
        },
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


@app.get("/revenue")
async def revenue():
    total = sum(r["amount_usdc"] for r in _revenue_log)
    by_ep = {}
    for r in _revenue_log:
        by_ep[r["endpoint"]] = by_ep.get(r["endpoint"], 0) + r["amount_usdc"]
    return {"total_usdc": round(total, 4), "calls": len(_revenue_log),
            "by_endpoint": by_ep, "recent": _revenue_log[-10:]}


# =========================================================================
# LEGACY SIGNAL ENDPOINTS (experimental — kept for backwards compatibility)
# =========================================================================

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


@app.get("/signals/live/{mint}")
async def live_score(request: Request, mint: str, top_n: int = 20):
    """Score ANY Solana token in real-time against all 646 calibrated agents.

    NOTE: Experimental. For safety screening, use /scan/{mint} instead.
    """
    block = await _gate(request, f"/signals/live/{mint}", "analysis")
    if block:
        return block

    from scoring import fetch_token_data, compute_derived_metrics, score_with_agents, compute_consensus

    # Fetch live data from DexScreener
    token_data = await fetch_token_data(mint)
    if not token_data:
        return {"error": f"Token {mint} not found on DexScreener (Solana pairs only)"}

    # Compute derived metrics
    derived = compute_derived_metrics(token_data)

    # Score through all agents
    configs = _load_boost_configs()
    results = score_with_agents(derived, configs)

    # Consensus
    consensus = compute_consensus(results)

    # Top agents that like this token
    top_bullish = [r for r in results if r["tier"] == "tier1"][:top_n]
    # Top agents that dislike it
    top_bearish = results[-top_n:]

    # Risk flags
    risk_flags = []
    if derived.get("rug_risk", 0) > 0.7:
        risk_flags.append("HIGH_RUG_RISK")
    if derived.get("liquidity_depth", 1) < 0.1:
        risk_flags.append("LOW_LIQUIDITY")
    if derived.get("age_safety", 1) < 0.1:
        risk_flags.append("VERY_NEW_TOKEN")
    if derived.get("concentration_risk", 0) > 0.8:
        risk_flags.append("LOW_TRANSACTION_COUNT")
    if derived.get("volatility_risk", 0) > 0.7:
        risk_flags.append("HIGH_VOLATILITY")

    return {
        "mint": mint,
        "symbol": token_data.get("symbol", "???"),
        "price_usd": token_data.get("price_usd"),
        "market_cap": token_data.get("market_cap"),
        "liquidity_usd": token_data.get("liquidity_usd"),
        "volume_24h": token_data.get("volume_24h"),
        "price_change_1h": token_data.get("price_change_1h"),
        "price_change_24h": token_data.get("price_change_24h"),
        "consensus": consensus,
        "top_bullish_agents": top_bullish,
        "top_bearish_agents": top_bearish,
        "risk_flags": risk_flags,
        "metrics_computed": len(derived),
        "note": "Experimental — for safety screening, use /scan/{mint} instead.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# =========================================================================
# AUTO-DISCOVERY ENDPOINTS
# =========================================================================

@app.get("/.well-known/x402.json")
async def x402_manifest():
    """x402 service discovery — crawlers and AI agents find payable endpoints here."""
    return {
        "x402Version": 2,
        "name": "SolSignal API",
        "description": (
            "Solana Token Safety Scanner — aggregates DexScreener, RugCheck, GoPlus, "
            "and Jupiter simulation into one SAFE/CAUTION/AVOID/RUG verdict in <2 seconds. "
            "Plus experimental 646-agent scoring."
        ),
        "homepage": "https://github.com/cryptomotifs/solsignal-api",
        "network": SOLANA_NETWORK,
        "asset": USDC_MINT,
        "payTo": SOLANA_WALLET or "not_configured",
        "facilitator": X402_FACILITATOR,
        "endpoints": [
            {
                "path": "/scan/{mint}",
                "method": "GET",
                "description": "Token safety scan — 4 sources, 1 verdict (10 free/day)",
                "maxAmountRequired": str(PRICES["scan"]),
                "currency": "USDC",
                "priceUsd": "$0.01",
            },
            {
                "path": "/trending",
                "method": "GET",
                "description": "Safety-screened trending Solana tokens (3 free/day)",
                "maxAmountRequired": str(PRICES["trending"]),
                "currency": "USDC",
                "priceUsd": "$0.01",
            },
            {
                "path": "/signals/live/{mint}",
                "method": "GET",
                "description": "Experimental: Real-time 646-agent scoring",
                "maxAmountRequired": str(PRICES["analysis"]),
                "currency": "USDC",
                "priceUsd": "$0.05",
            },
            {
                "path": "/signals/trending",
                "method": "GET",
                "description": "Legacy: Top-performing agents and latest snapshots",
                "maxAmountRequired": str(PRICES["trending"]),
                "currency": "USDC",
                "priceUsd": "$0.01",
            },
            {
                "path": "/signals/agent/{agent_name}",
                "method": "GET",
                "description": "Legacy: Scores from a specific calibrated agent",
                "maxAmountRequired": str(PRICES["agent"]),
                "currency": "USDC",
                "priceUsd": "$0.005",
            },
            {
                "path": "/signals/analysis/{mint}",
                "method": "GET",
                "description": "Legacy: Full multi-agent consensus analysis",
                "maxAmountRequired": str(PRICES["analysis"]),
                "currency": "USDC",
                "priceUsd": "$0.05",
            },
            {
                "path": "/signals/bulk",
                "method": "GET",
                "description": "Legacy: All scores from top 50 agents for recent tokens",
                "maxAmountRequired": str(PRICES["bulk"]),
                "currency": "USDC",
                "priceUsd": "$0.10",
            },
        ],
        "freeEndpoints": ["/", "/health", "/agents", "/track/stats", "/track/{mint}", "/docs"],
        "token": {
            "name": "Sol Signal AI",
            "symbol": "SSAI",
            "mint": "4KQnaEvCWp315CrVTvjUG7osfj2uAVCMpT5GhRQ7pump",
        },
    }


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin():
    """OpenAI-compatible plugin manifest — used by AI agent frameworks for discovery."""
    return {
        "schema_version": "v1",
        "name_for_human": "SolSignal",
        "name_for_model": "solsignal",
        "description_for_human": (
            "Solana Token Safety Scanner — scan any token for honeypots, rug pulls, "
            "and scams. Plus experimental 646-agent trading signals."
        ),
        "description_for_model": (
            "Solana token safety scanner. /scan/{mint} aggregates 4 free security sources "
            "(DexScreener, RugCheck, GoPlus, Jupiter simulation) into a single "
            "SAFE/CAUTION/AVOID/RUG verdict in under 2 seconds. Returns safety_score (0-100), "
            "individual checks (honeypot, sell_tax, lp_locked, mintable, holder_concentration, "
            "liquidity, age), and risk_flags. /trending returns safety-screened trending tokens. "
            "/track/stats shows public accuracy record. Free tier: 10 scans/day. "
            "Also supports x402 USDC payments and API key auth."
        ),
        "auth": {"type": "none"},
        "api": {
            "type": "openapi",
            "url": "https://solsignal-api.onrender.com/openapi.json",
        },
        "logo_url": "https://solsignal-api.onrender.com/logo.png",
        "contact_email": "s_amr@users.noreply.github.com",
        "legal_info_url": "https://github.com/cryptomotifs/solsignal-api",
    }


@app.get("/.well-known/agent.json")
async def agent_manifest():
    """Solana Agent Protocol discovery — for agent-to-agent communication."""
    return {
        "name": "SolSignal",
        "description": (
            "Solana Token Safety Scanner — aggregates 4 sources into one verdict. "
            "Plus 646 AI agents providing experimental trading signals."
        ),
        "url": "https://solsignal-api.onrender.com",
        "documentationUrl": "https://solsignal-api.onrender.com/docs",
        "capabilities": [
            "token-safety-scan",
            "honeypot-detection",
            "rug-detection",
            "trending-tokens",
            "accuracy-tracking",
            "trading-signals",
            "token-analysis",
            "agent-scores",
        ],
        "payment": {
            "protocol": "x402",
            "network": "solana",
            "asset": "USDC",
            "facilitator": X402_FACILITATOR,
        },
        "version": "2.0.0",
    }
