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
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from x402.extensions.bazaar import declare_discovery_extension
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

SOLANA_WALLET = os.environ.get("SIGNAL_WALLET", "HDJ88KsVwUGxGZmEdKtgMxHvssZR4gfFp1v1izCPK5x9").strip()
# Production x402 v2 facilitator. Override deliberately via environment if needed.
X402_FACILITATOR = os.environ.get(
    "X402_FACILITATOR", "https://x402.dexter.cash"
).rstrip("/")
PUBLIC_BASE_URL = (
    os.environ.get("PUBLIC_BASE_URL")
    or os.environ.get("RENDER_EXTERNAL_URL")
    or "https://solsignal-api.onrender.com"
).rstrip("/")
AGENT402_REGISTER_URL = os.environ.get(
    "AGENT402_REGISTER_URL", "https://agent402.tools/api/index/register"
).strip()
AGENT402_AUTO_REGISTER = os.environ.get("AGENT402_AUTO_REGISTER", "1").strip().lower() not in {
    "0", "false", "no", "off"
}
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

PRICES = {
    "scan": 10000,           # $0.01 USDC, 6 decimals
    "trending": 10000,       # $0.01
    "agent": 5000,           # $0.005
    "analysis": 50000,       # $0.05
    "bulk": 100000,          # $0.10
    "tool_ping": 1000,        # $0.001
    "tool_json": 1000,        # $0.001
    "tool_transform": 1000,   # $0.001
    "tool_url": 3000,         # $0.003
    "tool_defi": 3000,        # $0.003
    "tool_pdf": 5000,         # $0.005
    "tool_repo": 10000,       # $0.01
}


def _paid_endpoint_catalog() -> list[dict[str, Any]]:
    """Canonical machine-readable catalog used by discovery surfaces."""
    specs = [
        ("/tools/x402/ping", "GET", "Low-cost end-to-end x402 payment-path check", "tool_ping"),
        ("/tools/defi/yields", "GET", "Filter current DeFi yield pools by chain, token, TVL, APY, or stablecoin flag", "tool_defi"),
        ("/tools/defi/protocols", "GET", "Rank and filter DeFi protocols by chain, category, and TVL", "tool_defi"),
        ("/tools/repo/preflight", "GET", "Preflight a public GitHub repository for maintenance, license, CI, security-policy, and integration-risk signals", "tool_repo"),
        ("/tools/url/read", "POST", "Convert a public HTML or text URL into compact agent-readable Markdown plus links", "tool_url"),
        ("/tools/pdf/markdown", "POST", "Extract a public PDF text layer into page-structured Markdown", "tool_pdf"),
        ("/tools/json/repair", "POST", "Repair common malformed LLM JSON without another model call", "tool_json"),
        ("/tools/transform", "POST", "Hash, Base64/hex/URL encode-decode, or decode JWT header and payload", "tool_transform"),
        ("/scan/{mint}", "GET", "Solana token safety scan using multiple independent data sources", "scan"),
        ("/trending", "GET", "Safety-screened trending Solana tokens", "trending"),
        ("/signals/live/{mint}", "GET", "Experimental real-time multi-agent token scoring", "analysis"),
        ("/signals/trending", "GET", "Legacy top-performing signal agents and latest snapshots", "trending"),
        ("/signals/agent/{agent_name}", "GET", "Legacy scores from a specific calibrated signal agent", "agent"),
        ("/signals/analysis/{mint}", "GET", "Legacy full multi-agent consensus analysis", "analysis"),
        ("/signals/bulk", "GET", "Legacy bulk recent signal scores", "bulk"),
    ]
    rows: list[dict[str, Any]] = []
    for path, method, description, price_key in specs:
        amount = int(PRICES[price_key])
        rows.append({
            "path": path,
            "route": path,
            "url": f"{PUBLIC_BASE_URL}{path}",
            "method": method,
            "description": description,
            "price_key": price_key,
            "amount": str(amount),
            "price_usdc": amount / 1_000_000,
            "priceUsd": f"${amount / 1_000_000:g}",
            "currency": "USDC",
            "network": SOLANA_NETWORK,
            "asset": USDC_MINT,
            "payTo": SOLANA_WALLET or None,
        })
    return rows


def _match_discovery_endpoint(resource: str, price_key: str) -> dict[str, Any] | None:
    path = resource.split("?", 1)[0]
    for item in _paid_endpoint_catalog():
        template = item["path"]
        if "{" not in template:
            if path == template:
                return item
            continue
        prefix = template.split("{", 1)[0]
        suffix = template.split("}", 1)[1]
        if path.startswith(prefix) and path.endswith(suffix):
            return item
    for item in _paid_endpoint_catalog():
        if item["price_key"] == price_key:
            return item
    return None


def _bazaar_extensions(resource: str, price_key: str) -> dict[str, Any]:
    """Declare how an autonomous buyer should call this paid HTTP resource."""
    item = _match_discovery_endpoint(resource, price_key)
    method = item["method"] if item else "GET"
    path = resource.split("?", 1)[0]

    input_example: dict[str, Any] | None = None
    input_schema: dict[str, Any] | None = None
    path_schema: dict[str, Any] | None = None
    path_params: dict[str, str] = {}
    route_template: str | None = None

    if item:
        template = item["path"]
        if template == "/tools/repo/preflight":
            input_example = {"repo": "openai/openai-agents-python"}
            input_schema = {
                "properties": {"repo": {"type": "string"}},
                "required": ["repo"],
            }
        elif template == "/tools/defi/yields":
            input_example = {"chain": "Solana", "limit": 20}
            input_schema = {
                "properties": {
                    "chain": {"type": "string"},
                    "token": {"type": "string"},
                    "min_tvl": {"type": "number"},
                    "min_apy": {"type": "number"},
                    "stablecoin_only": {"type": "boolean"},
                    "limit": {"type": "integer"},
                }
            }
        elif template == "/tools/defi/protocols":
            input_example = {"chain": "Solana", "limit": 20}
            input_schema = {
                "properties": {
                    "chain": {"type": "string"},
                    "category": {"type": "string"},
                    "min_tvl": {"type": "number"},
                    "limit": {"type": "integer"},
                }
            }
        elif template == "/tools/url/read":
            input_example = {"url": "https://example.com"}
            input_schema = {
                "properties": {
                    "url": {"type": "string", "format": "uri"},
                    "max_chars": {"type": "integer"},
                },
                "required": ["url"],
            }
        elif template == "/tools/pdf/markdown":
            input_example = {"url": "https://example.com/document.pdf"}
            input_schema = {
                "properties": {
                    "url": {"type": "string", "format": "uri"},
                    "max_pages": {"type": "integer"},
                    "max_chars": {"type": "integer"},
                },
                "required": ["url"],
            }
        elif template == "/tools/json/repair":
            input_example = {"text": "{'status':'ok',}"}
            input_schema = {
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            }
        elif template == "/tools/transform":
            input_example = {"operation": "sha256", "value": "hello"}
            input_schema = {
                "properties": {
                    "operation": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["operation", "value"],
            }

        if "{" in template:
            param = template.split("{", 1)[1].split("}", 1)[0]
            prefix = template.split("{", 1)[0]
            suffix = template.split("}", 1)[1]
            value = path[len(prefix):]
            if suffix and value.endswith(suffix):
                value = value[:-len(suffix)]
            path_schema = {
                "properties": {param: {"type": "string"}},
                "required": [param],
            }
            path_params[param] = value
            route_template = template.replace("{" + param + "}", ":" + param)

    declared = declare_discovery_extension(
        input=input_example,
        input_schema=input_schema,
        path_params_schema=path_schema,
        body_type="json" if method in {"POST", "PUT", "PATCH"} else None,
    )
    bazaar = declared.get("bazaar")
    if isinstance(bazaar, dict):
        info = bazaar.setdefault("info", {})
        if isinstance(info, dict):
            inp = info.setdefault("input", {})
            if isinstance(inp, dict):
                inp["method"] = method
                if path_params:
                    inp["pathParams"] = path_params
        if route_template:
            bazaar["routeTemplate"] = route_template
    return declared

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

    registration_task = asyncio.create_task(_register_agent402_origin())
    _background_tasks.add(registration_task)
    registration_task.add_done_callback(_background_tasks.discard)

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


async def _register_agent402_origin() -> None:
    """Best-effort registration with Agent402's public seller index.

    This sends only the public service origin. Failures never block API startup.
    """
    if not AGENT402_AUTO_REGISTER:
        return
    if not PUBLIC_BASE_URL.startswith("https://"):
        return
    try:
        import httpx

        async with httpx.AsyncClient(timeout=12.0) as client:
            response = await client.post(
                AGENT402_REGISTER_URL,
                json={"origin": PUBLIC_BASE_URL},
                headers={"User-Agent": "CIPHER-Agent-Tools/1.0"},
            )
        print(json.dumps({
            "event": "agent402_registration",
            "status_code": response.status_code,
            "origin": PUBLIC_BASE_URL,
            "ok": 200 <= response.status_code < 300,
        }))
    except Exception as exc:
        print(json.dumps({
            "event": "agent402_registration",
            "origin": PUBLIC_BASE_URL,
            "ok": False,
            "error_type": type(exc).__name__,
        }))


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
    title="CIPHER Agent Tools",
    description=(
        "Machine-payable utilities for AI agents: DeFi data, GitHub repo preflight, "
        "URL/PDF extraction, JSON repair, and SolSignal token safety. "
        "Pay per request via x402 v2 in USDC on Solana."
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
    existing_cache = response.headers.get("Cache-Control", "")
    if "private" not in existing_cache.lower():
        response.headers["Cache-Control"] = (
            f"{existing_cache}, private".strip(", ") if existing_cache else "private"
        )
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


# --- x402 v2 + settlement-backed revenue ---

def _init_payments_db() -> None:
    """Create the settlement ledger used by the public revenue endpoint."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(PAYMENTS_DB)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settlements (
                tx_signature TEXT PRIMARY KEY,
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
            (tx_signature, endpoint, amount_atomic, amount_usdc, payer, network, facilitator, settled_at)
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
        recent = []
        recent_rows = conn.execute(
            """
            SELECT tx_signature, endpoint, amount_usdc, payer, network, facilitator, settled_at
            FROM settlements
            ORDER BY settled_at DESC
            LIMIT 20
            """
        ).fetchall()
        for r in recent_rows:
            item = dict(r)
            item["transaction"] = item.pop("tx_signature")
            recent.append(item)
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
            service_name="CIPHER Agent Tools",
            tags=["solana", "token-safety", "crypto"],
        ),
        error="Payment required",
        extensions=_bazaar_extensions(resource, price_key),
    )
    payload = payment_required.model_dump(by_alias=True, exclude_none=True)
    return JSONResponse(
        status_code=402,
        content=payload,
        headers={
            "PAYMENT-REQUIRED": encode_payment_required_header(payment_required),
            "Cache-Control": "no-store",
        },
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
        "name": "CIPHER Agent Tools",
        "tagline": "Low-cost machine-payable utilities for AI agents, settled in USDC on Solana.",
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
            "## CIPHER Agent Tools": "---",
            "/tools/catalog": "Free — machine-readable paid-tool catalog",
            "/tools/x402/ping": "$0.001 — end-to-end x402 payment-path check",
            "/skill.md": "Free — agent-facing capability/payment contract",
            "/tools/defi/yields": "$0.003 — normalized/filterable DeFi yield data",
            "/tools/defi/protocols": "$0.003 — normalized/filterable DeFi protocol data",
            "/tools/repo/preflight": "$0.01 — GitHub integration preflight",
            "/tools/url/read": "$0.003 — public page to agent-readable markdown",
            "/tools/pdf/markdown": "$0.005 — PDF text layer to markdown",
            "/tools/json/repair": "$0.001 — repair malformed LLM JSON",
            "/tools/transform": "$0.001 — hash/encode/decode/JWT plumbing",
            "## System": "---",
            "/health": "Free — System status",
            "/agents": "Free — All agents with precision stats",
            "/docs": "Interactive API docs",
        },
        "pricing": {
            "free": "10 scans/day + 3 trending/day (by IP)",
            "developer": "$9/month — 1000 scans/month",
            "pro": "$29/month — 5000 scans/month",
            "x402": "$0.001-$0.10 per call (USDC on Solana)",
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
# CIPHER AGENT TOOLS — low-cost machine-to-machine utilities
# =========================================================================

@app.get("/tools/catalog")
async def tools_catalog():
    """Free machine-readable catalog of CIPHER agent utilities."""
    tools = []
    for item in _paid_endpoint_catalog():
        if not item["path"].startswith("/tools/"):
            continue
        tools.append({
            "path": item["path"],
            "method": item["method"],
            "price_usdc": item["price_usdc"],
            "description": item["description"],
            "network": item["network"],
            "asset": item["asset"],
        })
    return {
        "name": "CIPHER Agent Tools",
        "payment": "x402 v2 / USDC on Solana",
        "recipient": SOLANA_WALLET or None,
        "tools": tools,
    }


def _paid_resource(request: Request) -> str:
    """Bind the payment challenge to the requested route/query."""
    if request.url.query:
        return f"{request.url.path}?{request.url.query}"
    return request.url.path


@app.get("/tools/x402/ping")
async def tool_x402_ping(request: Request):
    block = await _gate(request, request.url.path, "tool_ping")
    if block:
        return block
    return {
        "ok": True,
        "service": "CIPHER Agent Tools",
        "purpose": "x402 payment path verified",
        "network": SOLANA_NETWORK,
        "asset": "USDC",
        "recipient": SOLANA_WALLET,
        "note": "Read the PAYMENT-RESPONSE header for settlement proof.",
    }


@app.get("/tools/defi/yields")
async def tool_defi_yields(
    request: Request,
    chain: str | None = None,
    token: str | None = None,
    min_tvl: float = 0,
    min_apy: float = 0,
    stablecoin_only: bool = False,
    limit: int = 20,
):
    block = await _gate(request, _paid_resource(request), "tool_defi")
    if block:
        return block
    try:
        from agent_tools import ToolError, defi_yields
        return await defi_yields(
            chain=chain,
            token=token,
            min_tvl=max(min_tvl, 0),
            min_apy=max(min_apy, 0),
            stablecoin_only=stablecoin_only,
            limit=limit,
        )
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.get("/tools/defi/protocols")
async def tool_defi_protocols(
    request: Request,
    chain: str | None = None,
    category: str | None = None,
    min_tvl: float = 0,
    limit: int = 20,
):
    block = await _gate(request, _paid_resource(request), "tool_defi")
    if block:
        return block
    try:
        from agent_tools import ToolError, defi_protocols
        return await defi_protocols(
            chain=chain,
            category=category,
            min_tvl=max(min_tvl, 0),
            limit=limit,
        )
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.get("/tools/repo/preflight")
async def tool_repo_preflight(request: Request, repo: str | None = None):
    block = await _gate(request, _paid_resource(request), "tool_repo")
    if block:
        return block
    if not repo:
        return JSONResponse(status_code=400, content={"error": "repo is required"})
    try:
        from agent_tools import ToolError, repo_preflight
        return await repo_preflight(
            repo,
            github_token=os.environ.get("GITHUB_TOKEN", "").strip(),
        )
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.post("/tools/url/read")
async def tool_url_read(request: Request):
    block = await _gate(request, request.url.path, "tool_url")
    if block:
        return block
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "valid JSON body is required"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "JSON object body is required"})
    url = str(payload.get("url") or "").strip()
    if not url:
        return JSONResponse(status_code=400, content={"error": "url is required"})
    try:
        from agent_tools import ToolError, read_url
        return await read_url(url, max_chars=int(payload.get("max_chars") or 50000))
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "max_chars must be an integer"})
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.post("/tools/pdf/markdown")
async def tool_pdf_markdown(request: Request):
    block = await _gate(request, request.url.path, "tool_pdf")
    if block:
        return block
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "valid JSON body is required"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "JSON object body is required"})
    url = str(payload.get("url") or "").strip()
    if not url:
        return JSONResponse(status_code=400, content={"error": "url is required"})
    try:
        from agent_tools import ToolError, pdf_to_markdown
        return await pdf_to_markdown(
            url,
            max_pages=int(payload.get("max_pages") or 20),
            max_chars=int(payload.get("max_chars") or 80000),
        )
    except (TypeError, ValueError):
        return JSONResponse(
            status_code=400,
            content={"error": "max_pages and max_chars must be integers"},
        )
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.post("/tools/transform")
async def tool_transform(request: Request):
    block = await _gate(request, request.url.path, "tool_transform")
    if block:
        return block
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "valid JSON body is required"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "JSON object body is required"})
    operation = str(payload.get("operation") or "").strip()
    value = payload.get("value")
    if not operation or not isinstance(value, str):
        return JSONResponse(
            status_code=400,
            content={"error": "operation and string value are required"},
        )
    try:
        from agent_tools import ToolError, transform_value
        return transform_value(operation, value)
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.post("/tools/json/repair")
async def tool_json_repair(request: Request):
    block = await _gate(request, request.url.path, "tool_json")
    if block:
        return block
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "valid JSON body is required"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "JSON object body is required"})
    raw = payload.get("text")
    if not isinstance(raw, str) or not raw:
        return JSONResponse(
            status_code=400,
            content={"error": "text must be a non-empty string"},
        )
    try:
        from agent_tools import ToolError, repair_json
        return repair_json(raw)
    except ToolError as exc:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.get("/skill.md")
async def skill_md():
    """Agent-facing contract for CIPHER Agent Tools."""
    body = f"""---
name: CIPHER Agent Tools
description: Low-cost machine-payable utilities for AI agents: DeFi data, GitHub repo preflight, URL/PDF extraction, JSON repair, and Solana token safety.
base_url: {PUBLIC_BASE_URL}
payment: x402 v2
network: {SOLANA_NETWORK}
asset: USDC
pay_to: {SOLANA_WALLET}
---

# CIPHER Agent Tools

Use these endpoints when your agent needs normalized data or deterministic utility work without spending model tokens.

## Discovery

- `GET /tools/catalog` — free machine-readable catalog.
- `GET /openapi.json` — free OpenAPI schema.
- `GET /.well-known/x402` — free x402 compatibility manifest.
- `GET /.well-known/x402.json` — detailed x402 manifest.
- `GET /revenue` — settlement-backed public revenue counter.

## Paid tools

| Tool | Method | Price | Use when |
|---|---|---:|---|
| `/tools/x402/ping` | GET | $0.001 | Prove the agent's x402 wallet/payment path works end to end. |
| `/tools/defi/yields` | GET | $0.003 | Filter current DeFi yield pools by chain, token, TVL, APY, or stablecoin flag. |
| `/tools/defi/protocols` | GET | $0.003 | Rank/filter protocols by chain, category, and TVL. |
| `/tools/repo/preflight` | GET | $0.01 | Check a public GitHub repo's maintenance, license, CI, security policy, and integration-risk signals. |
| `/tools/url/read` | POST | $0.003 | Convert a public HTML/text URL into compact agent-readable Markdown. |
| `/tools/pdf/markdown` | POST | $0.005 | Extract a public PDF text layer into page-structured Markdown. |
| `/tools/json/repair` | POST | $0.001 | Repair common malformed LLM JSON without another model call. |
| `/scan/{{mint}}` | GET | $0.01 after free quota | Screen a Solana token across multiple safety sources. |

## Payment flow

1. Call the endpoint normally.
2. If payment is required, the service returns HTTP 402 with a `PAYMENT-REQUIRED` header.
3. Sign/pay the advertised x402 v2 USDC requirement on Solana.
4. Retry with `PAYMENT-SIGNATURE`.
5. On success, the response includes `PAYMENT-RESPONSE` with settlement details.

Revenue is recorded only after a successful settlement with an on-chain transaction signature.

## Spend guidance

- Prefer DeFi data endpoints over model-generated market summaries when raw normalized data is enough.
- Use JSON repair before retrying an LLM call.
- Use repo preflight before importing an unfamiliar public dependency.
- Use URL/PDF extraction for public resources only.
- DeFi APY data is observational, not a recommendation or guarantee.

## Examples

`GET {PUBLIC_BASE_URL}/tools/defi/yields?chain=Solana&min_tvl=1000000&limit=10`

`GET {PUBLIC_BASE_URL}/tools/repo/preflight?repo=openai/openai-agents-python`

`POST {PUBLIC_BASE_URL}/tools/json/repair`
body: `{{"text":"{{'ok': true,}}"}}`
"""
    return Response(content=body, media_type="text/markdown; charset=utf-8")


@app.get("/llms.txt")
async def llms_txt():
    content = """# CIPHER Agent Tools / SolSignal

Machine-payable APIs for AI agents. Payment: x402 v2, USDC on Solana.

Free discovery:
- GET /tools/catalog
- GET /docs
- GET /.well-known/x402.json
- GET /.well-known/agent.json
- GET /revenue

Paid tools:
- GET /tools/x402/ping — $0.001
- GET /tools/defi/yields — $0.003
- GET /tools/defi/protocols — $0.003
- GET /tools/repo/preflight — $0.01
- POST /tools/url/read — $0.003
- POST /tools/pdf/markdown — $0.005
- POST /tools/json/repair — $0.001
- GET /scan/{mint} — Solana token safety
"""
    return Response(content=content, media_type="text/plain; charset=utf-8")


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

def _x402_manifest_payload() -> dict[str, Any]:
    endpoints = _paid_endpoint_catalog()
    return {
        "version": 1,
        "x402Version": 2,
        "name": "CIPHER Agent Tools",
        "description": (
            "Machine-payable utilities for AI agents: developer preflight, web/document "
            "context extraction, deterministic transforms, DeFi data, and Solana token safety."
        ),
        "origin": PUBLIC_BASE_URL,
        "homepage": "https://github.com/cryptomotifs/solsignal-api",
        "network": SOLANA_NETWORK,
        "asset": USDC_MINT,
        "payTo": SOLANA_WALLET or "not_configured",
        "facilitator": X402_FACILITATOR,
        "resources": endpoints,
        "endpoints": endpoints,
        "freeEndpoints": [
            "/", "/health", "/agents", "/track/stats", "/track/{mint}",
            "/tools/catalog", "/skill.md", "/llms.txt", "/docs",
        ],
    }


@app.get("/.well-known/x402")
async def x402_compat_manifest():
    """Full crawler-friendly x402 discovery document."""
    return _x402_manifest_payload()


@app.get("/.well-known/x402.json")
async def x402_manifest():
    """Detailed x402 service discovery document."""
    return _x402_manifest_payload()


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin():
    """OpenAI-compatible plugin manifest — used by AI agent frameworks for discovery."""
    return {
        "schema_version": "v1",
        "name_for_human": "CIPHER Agent Tools",
        "name_for_model": "cipher_agent_tools",
        "description_for_human": (
            "Machine-payable AI-agent utilities for DeFi data, developer preflight, "
            "document extraction, JSON repair, and Solana token safety."
        ),
        "description_for_model": (
            "Use CIPHER Agent Tools for machine-payable utilities. /tools/defi/yields and "
            "/tools/defi/protocols normalize DeFi data; /tools/repo/preflight checks public "
            "GitHub repository maintenance and license signals; /tools/url/read and "
            "/tools/pdf/markdown create agent-readable context; /tools/json/repair fixes common "
            "malformed model JSON; /scan/{mint} provides Solana token safety. Paid calls use "
            "x402 v2 USDC on Solana."
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
        "name": "CIPHER Agent Tools",
        "description": (
            "Machine-payable utilities for AI agents, including DeFi data, developer "
            "preflight, document extraction, JSON repair, and SolSignal token safety."
        ),
        "url": PUBLIC_BASE_URL,
        "documentationUrl": f"{PUBLIC_BASE_URL}/docs",
        "capabilities": [
            "token-safety-scan",
            "honeypot-detection",
            "rug-detection",
            "trending-tokens",
            "accuracy-tracking",
            "trading-signals",
            "token-analysis",
            "agent-scores",
            "defi-yield-data",
            "defi-protocol-data",
            "github-repo-preflight",
            "url-to-markdown",
            "pdf-to-markdown",
            "json-repair",
            "hashing-and-encoding",
            "jwt-decode",
        ],
        "payment": {
            "protocol": "x402",
            "network": "solana",
            "asset": "USDC",
            "facilitator": X402_FACILITATOR,
        },
        "version": "2.0.0",
    }


# =========================================================================
# OPENAPI PAYMENT DISCOVERY
# =========================================================================

def _openapi_request_body_schema(path: str) -> dict[str, Any] | None:
    """JSON request schemas for raw-Request handlers that FastAPI cannot infer."""
    schemas: dict[str, dict[str, Any]] = {
        "/tools/url/read": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri",
                    "description": "Public HTTP(S) URL to read.",
                    "example": "https://example.com",
                },
                "max_chars": {
                    "type": "integer",
                    "minimum": 1000,
                    "maximum": 100000,
                    "default": 50000,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        "/tools/pdf/markdown": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri",
                    "description": "Public PDF URL.",
                    "example": "https://example.com/document.pdf",
                },
                "max_pages": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 40,
                    "default": 20,
                },
                "max_chars": {
                    "type": "integer",
                    "minimum": 1000,
                    "maximum": 150000,
                    "default": 80000,
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        "/tools/json/repair": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Malformed JSON or common LLM JSON-like output.",
                    "example": "{'status':'ok',}",
                }
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "/tools/transform": {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "sha256", "sha512", "sha1", "md5", "blake2b",
                        "base64_encode", "base64_decode", "base64url_decode",
                        "hex_encode", "hex_decode", "url_encode", "url_decode",
                        "jwt_decode",
                    ],
                    "example": "sha256",
                },
                "value": {
                    "type": "string",
                    "description": "Text to transform.",
                    "example": "hello",
                },
            },
            "required": ["operation", "value"],
            "additionalProperties": False,
        },
    }
    return schemas.get(path)


def _cipher_openapi() -> dict[str, Any]:
    """OpenAPI contract enriched for autonomous paid-tool discovery."""
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    info = schema.setdefault("info", {})
    info["x-guidance"] = (
        "CIPHER Agent Tools provides deterministic, machine-payable utilities over x402 v2 "
        "USDC on Solana. Prefer the lowest-cost tool that directly matches the task. "
        "Paid routes return HTTP 402 before performing paid work; an x402 client pays and retries. "
        "Use /tools/catalog or /.well-known/x402 for the complete machine-readable catalog."
    )

    # /scan and /trending have free quotas, so do not claim they are always paid
    # in an OpenAPI registry whose probes expect an immediate 402.
    openapi_paid = [
        item
        for item in _paid_endpoint_catalog()
        if item["path"] not in {"/scan/{mint}", "/trending"}
    ]

    paths = schema.setdefault("paths", {})
    for item in openapi_paid:
        path_item = paths.get(item["path"])
        if not isinstance(path_item, dict):
            continue
        operation = path_item.get(item["method"].lower())
        if not isinstance(operation, dict):
            continue

        operation["x-payment-info"] = {
            "price": {
                "mode": "fixed",
                "currency": "USD",
                "amount": f"{item['price_usdc']:.6f}",
            },
            "protocols": [{"x402": {}}],
        }
        responses = operation.setdefault("responses", {})
        responses["402"] = {
            "description": "Payment Required",
            "headers": {
                "PAYMENT-REQUIRED": {
                    "description": "Base64-encoded x402 v2 payment requirements.",
                    "schema": {"type": "string"},
                }
            },
        }

        body_schema = _openapi_request_body_schema(item["path"])
        if body_schema is not None and item["method"] in {"POST", "PUT", "PATCH"}:
            operation["requestBody"] = {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": body_schema,
                    }
                },
            }

        if item["path"] == "/tools/repo/preflight":
            parameters = operation.setdefault("parameters", [])
            found_repo = False
            for parameter in parameters:
                if (
                    isinstance(parameter, dict)
                    and parameter.get("in") == "query"
                    and parameter.get("name") == "repo"
                ):
                    parameter["required"] = True
                    parameter.setdefault("schema", {})["example"] = "openai/openai-agents-python"
                    found_repo = True
            if not found_repo:
                parameters.append({
                    "name": "repo",
                    "in": "query",
                    "required": True,
                    "description": "owner/repository or a public GitHub repository URL",
                    "schema": {
                        "type": "string",
                        "example": "openai/openai-agents-python",
                    },
                })

    app.openapi_schema = schema
    return schema


app.openapi = _cipher_openapi
