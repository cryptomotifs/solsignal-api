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
from fastapi.responses import JSONResponse

from x402.http import (
    FacilitatorConfig,
    HTTPFacilitatorClient,
    decode_payment_signature_header,
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.mechanisms.svm.exact import ExactSvmServerScheme
from x402.schemas import AssetAmount, ResourceConfig, ResourceInfo
from x402.server import x402ResourceServer

# --- Config ---
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ARENA_DB = os.path.join(DATA_DIR, "arena_snapshots.db")
RESULTS_DB = os.path.join(DATA_DIR, "arena_results.db")
BOOST_CONFIGS = os.path.join(DATA_DIR, "agent_boost_configs.json")
API_KEYS_FILE = os.path.join(DATA_DIR, "api_keys.json")

SOLANA_WALLET = os.environ.get("SIGNAL_WALLET", "").strip()
# Production x402 v2 facilitator. Override deliberately via environment if needed.
X402_FACILITATOR = os.environ.get(
    "X402_FACILITATOR", "https://x402.dexter.cash"
).rstrip("/")
PUBLIC_BASE_URL = os.environ.get(
    "PUBLIC_BASE_URL", "https://solsignal-api.onrender.com"
).rstrip("/")
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

PRICES = {
    "scan": 10000,           # $0.01 USDC, 6 decimals
    "trending": 10000,       # $0.01
    "agent": 5000,           # $0.005
    "analysis": 50000,       # $0.05
    "bulk": 100000,          # $0.10
}

PAYMENTS_DB = os.path.join(DATA_DIR, "payments.db")

_x402_facilitator_client = HTTPFacilitatorClient(
    FacilitatorConfig(url=X402_FACILITATOR)
)
_x402_resource_server = x402ResourceServer(_x402_facilitator_client).register(
    SOLANA_NETWORK,
    ExactSvmServerScheme(),
)
_x402_requirements_cache: dict[str, Any] = {}
_x402_ready = False
_x402_init_error = ""

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
    """Startup/shutdown lifecycle.

    Initialize production x402 capabilities before accepting paid requests.
    If the facilitator is temporarily unavailable, the API stays up but paid
    requests fail closed rather than being counted as revenue.
    """
    global _x402_ready, _x402_init_error

    if SOLANA_WALLET:
        try:
            await asyncio.to_thread(_x402_resource_server.initialize)
            _x402_ready = True
            _x402_init_error = ""
        except Exception as exc:
            _x402_ready = False
            _x402_init_error = str(exc)

    _init_payments_db()

    task = asyncio.create_task(_outcome_backfill_loop())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await _x402_facilitator_client.aclose()


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

@app.middleware("http")
async def settle_verified_x402(request: Request, call_next):
    """Settle verified payments only after successful endpoint execution.

    A verify result is never counted as revenue. Revenue is written only after
    the facilitator returns success with an on-chain transaction signature.
    """
    response = await call_next(request)
    payload = getattr(request.state, "x402_payment_payload", None)
    requirements = getattr(request.state, "x402_payment_requirements", None)

    if payload is None or requirements is None:
        return response
    if not 200 <= response.status_code < 300:
        return response

    try:
        settle_result = await _x402_resource_server.settle_payment(payload, requirements)
    except Exception:
        return JSONResponse(
            status_code=502,
            content={"error": "Payment settlement failed; no revenue was recorded"},
        )

    if not settle_result.success or not settle_result.transaction:
        return JSONResponse(
            status_code=502,
            content={
                "error": "Payment settlement was not confirmed",
                "reason": settle_result.error_reason,
            },
        )

    amount_atomic = int(
        getattr(settle_result, "amount", None)
        or getattr(request.state, "x402_amount_atomic", 0)
    )
    _record_settlement(
        transaction=settle_result.transaction,
        endpoint=getattr(request.state, "x402_endpoint", request.url.path),
        amount_atomic=amount_atomic,
        payer=settle_result.payer,
        network=settle_result.network,
    )
    response.headers["PAYMENT-RESPONSE"] = encode_payment_response_header(settle_result)
    return response


# --- Caches ---
_boost_cache: dict | None = None
_boost_cache_ts: float = 0
_api_keys: dict = {}


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


# --- x402 v2 + settlement-backed revenue ---

def _init_payments_db() -> None:
    """Create the settlement ledger used by the public revenue endpoint."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(PAYMENTS_DB)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settlements (
                transaction TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                amount_atomic INTEGER NOT NULL,
                amount_usdc REAL NOT NULL,
                payer TEXT,
                network TEXT NOT NULL,
                facilitator TEXT NOT NULL,
                settled_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _record_settlement(
    *,
    transaction: str,
    endpoint: str,
    amount_atomic: int,
    payer: str | None,
    network: str,
) -> None:
    """Persist a confirmed on-chain settlement exactly once."""
    if not transaction:
        raise ValueError("A confirmed settlement must include a transaction signature")
    _init_payments_db()
    conn = sqlite3.connect(PAYMENTS_DB)
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO settlements
            (transaction, endpoint, amount_atomic, amount_usdc, payer, network, facilitator, settled_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transaction,
                endpoint,
                int(amount_atomic),
                int(amount_atomic) / 1_000_000,
                payer,
                network,
                X402_FACILITATOR,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _payment_stats() -> dict[str, Any]:
    """Return revenue derived only from confirmed settlement receipts."""
    _init_payments_db()
    conn = sqlite3.connect(PAYMENTS_DB)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount_atomic), 0) AS total FROM settlements"
        ).fetchone()
        recent = [
            dict(r)
            for r in conn.execute(
                """
                SELECT transaction, endpoint, amount_usdc, payer, network, facilitator, settled_at
                FROM settlements
                ORDER BY settled_at DESC
                LIMIT 20
                """
            ).fetchall()
        ]
    finally:
        conn.close()

    total_atomic = int(row["total"]) if row else 0
    count = int(row["cnt"]) if row else 0
    return {
        "total_usdc": round(total_atomic / 1_000_000, 6),
        "settlements": count,
        "recent": recent,
    }


def _get_x402_requirements(price_key: str):
    """Build facilitator-enriched SVM payment requirements for one price."""
    if not SOLANA_WALLET:
        raise RuntimeError("SIGNAL_WALLET is not configured")
    if not _x402_ready:
        raise RuntimeError("x402 facilitator is not ready")

    cached = _x402_requirements_cache.get(price_key)
    if cached is not None:
        return cached

    amount = PRICES.get(price_key, 10000)
    config = ResourceConfig(
        scheme="exact",
        price=AssetAmount(amount=str(amount), asset=USDC_MINT),
        network=SOLANA_NETWORK,
        pay_to=SOLANA_WALLET,
        max_timeout_seconds=60,
    )
    built = _x402_resource_server.build_payment_requirements(config)
    if not built:
        raise RuntimeError("Unable to build x402 payment requirements")

    _x402_requirements_cache[price_key] = built[0]
    return built[0]


async def _build_402(resource: str, price_key: str) -> Response:
    """Return a canonical x402 v2 PaymentRequired response."""
    if not SOLANA_WALLET:
        return JSONResponse(
            status_code=503,
            content={"error": "Payment service is not configured"},
        )
    if not _x402_ready:
        return JSONResponse(
            status_code=503,
            content={"error": "Payment service is temporarily unavailable"},
        )

    requirements = _get_x402_requirements(price_key)
    payment_required = await _x402_resource_server.create_payment_required_response(
        [requirements],
        resource=ResourceInfo(
            url=f"{PUBLIC_BASE_URL}{resource}",
            description=f"SolSignal paid API: {price_key}",
            mime_type="application/json",
            service_name="SolSignal",
            tags=["solana", "token-safety", "crypto"],
        ),
        error="Payment required",
    )
    payload = payment_required.model_dump(by_alias=True, exclude_none=True)
    return JSONResponse(
        status_code=402,
        content=payload,
        headers={"PAYMENT-REQUIRED": encode_payment_required_header(payment_required)},
    )


async def _authorize_x402(
    request: Request,
    payment_header: str,
    resource: str,
    price_key: str,
) -> bool:
    """Verify an x402 v2 payment authorization without counting it as revenue."""
    if not SOLANA_WALLET or not _x402_ready:
        return False
    try:
        payload = decode_payment_signature_header(payment_header)
        if getattr(payload, "x402_version", None) != 2:
            return False

        requirements = _get_x402_requirements(price_key)
        matched = _x402_resource_server.find_matching_requirements([requirements], payload)
        if matched is None:
            return False

        verify_result = await _x402_resource_server.verify_payment(payload, matched)
        if not verify_result.is_valid:
            return False

        # Settlement happens only after the endpoint returns a successful response.
        request.state.x402_payment_payload = payload
        request.state.x402_payment_requirements = matched
        request.state.x402_endpoint = resource
        request.state.x402_amount_atomic = int(matched.amount)
        return True
    except Exception:
        return False


async def _gate(request: Request, resource: str, price_key: str) -> Response | None:
    """Authorize an API key or a verified x402 payment."""
    api_key = request.headers.get("x-api-key")
    if _check_api_key(api_key):
        _deduct_credit(api_key)
        return None

    payment = request.headers.get("payment-signature")
    if payment and await _authorize_x402(request, payment, resource, price_key):
        return None

    return await _build_402(resource, price_key)


async def _gate_or_free(
    request: Request,
    resource: str,
    price_key: str,
    free_endpoint: str,
) -> Response | None:
    """Allow API key/x402 payment, otherwise consume the free IP quota."""
    api_key = request.headers.get("x-api-key")
    if _check_api_key(api_key):
        _deduct_credit(api_key)
        return None

    payment = request.headers.get("payment-signature")
    if payment and await _authorize_x402(request, payment, resource, price_key):
        return None

    ip = request.client.host if request.client else "unknown"
    if _check_free_tier(ip, free_endpoint):
        _record_free_usage(ip, free_endpoint)
        return None

    return await _build_402(resource, price_key)


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
        "x402_enabled": bool(SOLANA_WALLET and _x402_ready),
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
        "x402": {
            "configured": bool(SOLANA_WALLET),
            "ready": bool(_x402_ready),
            "facilitator": X402_FACILITATOR,
            "network": SOLANA_NETWORK,
        },
        "revenue_settlements": _payment_stats()["settlements"],
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
    """Public settlement-backed revenue record.

    Only confirmed x402 on-chain settlements count as revenue. API-key usage is
    reported separately because consuming credits does not prove a new payment.
    """
    stats = _payment_stats()
    keys = _load_api_keys()
    api_key_calls = sum(int(v.get("total_calls", 0)) for v in keys.values())
    return {
        **stats,
        "currency": "USDC",
        "recipient": SOLANA_WALLET or None,
        "facilitator": X402_FACILITATOR,
        "api_key_calls": api_key_calls,
        "verification_rule": "x402 settlement success + non-empty on-chain transaction",
    }


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
                "amount": str(PRICES["scan"]),
                "currency": "USDC",
                "priceUsd": "$0.01",
            },
            {
                "path": "/trending",
                "method": "GET",
                "description": "Safety-screened trending Solana tokens (3 free/day)",
                "amount": str(PRICES["trending"]),
                "currency": "USDC",
                "priceUsd": "$0.01",
            },
            {
                "path": "/signals/live/{mint}",
                "method": "GET",
                "description": "Experimental: Real-time 646-agent scoring",
                "amount": str(PRICES["analysis"]),
                "currency": "USDC",
                "priceUsd": "$0.05",
            },
            {
                "path": "/signals/trending",
                "method": "GET",
                "description": "Legacy: Top-performing agents and latest snapshots",
                "amount": str(PRICES["trending"]),
                "currency": "USDC",
                "priceUsd": "$0.01",
            },
            {
                "path": "/signals/agent/{agent_name}",
                "method": "GET",
                "description": "Legacy: Scores from a specific calibrated agent",
                "amount": str(PRICES["agent"]),
                "currency": "USDC",
                "priceUsd": "$0.005",
            },
            {
                "path": "/signals/analysis/{mint}",
                "method": "GET",
                "description": "Legacy: Full multi-agent consensus analysis",
                "amount": str(PRICES["analysis"]),
                "currency": "USDC",
                "priceUsd": "$0.05",
            },
            {
                "path": "/signals/bulk",
                "method": "GET",
                "description": "Legacy: All scores from top 50 agents for recent tokens",
                "amount": str(PRICES["bulk"]),
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
