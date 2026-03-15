"""Token Safety Scanner — Aggregates 4 free security sources into one verdict.

Sources: DexScreener (market data), RugCheck (LP/holders), GoPlus (honeypot/tax),
Jupiter (buy+sell simulation). All fetched in parallel via asyncio.gather.

No bot dependencies — fully standalone. Uses httpx (already in requirements).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

# --- API endpoints ---
RUGCHECK_API_URL = "https://api.rugcheck.xyz/v1/tokens"
GOPLUS_API_URL = "https://api.gopluslabs.io/api/v1/token_security/solana"
JUPITER_QUOTE_URL = "https://api.jup.ag/swap/v1/quote"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
HONEYPOT_TEST_AMOUNT_USDC = 10_000_000  # $10 USDC (6 decimals)

# --- Cache ---
_scan_cache: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Individual fetchers (all return dicts, never raise)
# ---------------------------------------------------------------------------

async def fetch_dexscreener(mint: str) -> dict:
    """Fetch market data from DexScreener."""
    url = f"https://api.dexscreener.com/latest/dex/tokens/{mint}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {}
            data = resp.json()
    except Exception:
        return {}

    pairs = data.get("pairs") or []
    sol_pairs = [p for p in pairs if (p.get("chainId") or "").lower() == "solana"]
    if not sol_pairs:
        return {}

    pair = max(sol_pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))

    vol = pair.get("volume") or {}
    txns = pair.get("txns") or {}
    liq = pair.get("liquidity") or {}

    created_at = pair.get("pairCreatedAt") or 0
    if created_at > 1e12:
        created_at /= 1000
    age_hours = (time.time() - created_at) / 3600.0 if created_at > 0 else 0.0

    buys_24h = float((txns.get("h24") or {}).get("buys") or 0)
    sells_24h = float((txns.get("h24") or {}).get("sells") or 0)

    return {
        "symbol": (pair.get("baseToken") or {}).get("symbol", "???"),
        "price_usd": float(pair.get("priceUsd") or 0),
        "market_cap": float(pair.get("marketCap") or 0),
        "liquidity_usd": float(liq.get("usd") or 0),
        "volume_24h": float(vol.get("h24") or 0),
        "age_hours": age_hours,
        "buys_24h": buys_24h,
        "sells_24h": sells_24h,
    }


async def fetch_rugcheck(mint: str) -> dict:
    """Fetch RugCheck risk report."""
    try:
        url = f"{RUGCHECK_API_URL}/{mint}/report"
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {}
            data = resp.json()

        score = data.get("score", 0)
        risks = data.get("risks", [])
        lp_locked = not any(
            r.get("name", "") in ("LP Unlocked", "No LP Lock")
            for r in risks
        )
        top_holders = data.get("topHolders", [])
        top_holders_pct = sum(
            float(h.get("pct", 0)) for h in top_holders[:10]
        ) if top_holders else 0.0

        creator_pct = 0.0
        creator_addr = data.get("creator", "")
        if creator_addr and top_holders:
            for h in top_holders:
                if h.get("address", "") == creator_addr:
                    creator_pct = float(h.get("pct", 0))
                    break

        return {
            "score": score,
            "flags": [r.get("name", "") for r in risks[:5]],
            "lp_locked": lp_locked,
            "top10_pct": round(top_holders_pct, 1),
            "creator_pct": round(creator_pct, 1),
        }
    except Exception:
        return {}


async def fetch_goplus(mint: str) -> dict:
    """Fetch GoPlus security data."""
    try:
        url = f"{GOPLUS_API_URL}?contract_addresses={mint}"
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {}
            data = resp.json()

        result_data = data.get("result", {}).get(mint.lower(), {})
        if not result_data:
            result_data = data.get("result", {}).get(mint, {})
        if not result_data:
            return {}

        return {
            "is_honeypot": result_data.get("is_honeypot") == "1",
            "is_mintable": result_data.get("is_mintable") == "1",
            "sell_tax": float(result_data.get("sell_tax", 0) or 0) * 100,
            "buy_tax": float(result_data.get("buy_tax", 0) or 0) * 100,
            "is_proxy": result_data.get("is_proxy") == "1",
            "is_blacklisted": result_data.get("is_blacklisted") == "1",
        }
    except Exception:
        return {}


async def simulate_honeypot(mint: str) -> dict:
    """Simulate buy+sell via Jupiter quotes to detect honeypots.

    Returns {sell_failed, sell_tax_pct} or empty dict on error.
    """
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            # Step 1: Quote buy — USDC → Token
            buy_resp = await client.get(JUPITER_QUOTE_URL, params={
                "inputMint": USDC_MINT,
                "outputMint": mint,
                "amount": str(HONEYPOT_TEST_AMOUNT_USDC),
                "slippageBps": "500",
            })
            if buy_resp.status_code != 200:
                return {"sell_failed": True, "sell_tax_pct": -1}
            buy_quote = buy_resp.json()

            out_amount = buy_quote.get("outAmount")
            if not out_amount or int(out_amount) <= 0:
                return {"sell_failed": True, "sell_tax_pct": -1}

            # Step 2: Quote sell — Token → USDC
            sell_resp = await client.get(JUPITER_QUOTE_URL, params={
                "inputMint": mint,
                "outputMint": USDC_MINT,
                "amount": str(out_amount),
                "slippageBps": "500",
            })
            if sell_resp.status_code != 200:
                # Buy works but sell fails = honeypot
                return {"sell_failed": True, "sell_tax_pct": -1}
            sell_quote = sell_resp.json()

            sell_out = sell_quote.get("outAmount")
            if not sell_out or int(sell_out) <= 0:
                return {"sell_failed": True, "sell_tax_pct": -1}

            # Step 3: Calculate effective sell tax
            loss_pct = (1.0 - int(sell_out) / HONEYPOT_TEST_AMOUNT_USDC) * 100.0
            sell_tax_pct = max(0.0, loss_pct - 2.0)  # Subtract ~2% baseline slippage

            return {"sell_failed": False, "sell_tax_pct": round(sell_tax_pct, 2)}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Verdict computation
# ---------------------------------------------------------------------------

def compute_verdict(
    dex: dict, rugcheck: dict, goplus: dict, jup_sim: dict,
) -> tuple[str, int, list[dict], list[str]]:
    """Compute safety verdict from all sources.

    Returns (verdict, safety_score, checks, risk_flags).
    Verdict: SAFE / CAUTION / AVOID / RUG
    Safety score: 0-100 (100 = safest)
    """
    checks: dict[str, dict] = {}
    risk_flags: list[str] = []
    score = 100  # Start at 100, deduct for each issue

    # --- Honeypot (Jupiter simulation) ---
    if jup_sim:
        sell_failed = jup_sim.get("sell_failed", False)
        sell_tax = jup_sim.get("sell_tax_pct", 0)
        if sell_failed:
            checks["honeypot"] = {"pass": False, "detail": "sell quote failed"}
            risk_flags.append("HONEYPOT_SUSPECTED")
            score -= 40
        elif sell_tax > 10:
            checks["honeypot"] = {"pass": False, "detail": f"high sell tax ({sell_tax}%)"}
            risk_flags.append("HIGH_SELL_TAX")
            score -= 30
        else:
            checks["honeypot"] = {"pass": True, "detail": "sell quote succeeded"}
    else:
        checks["honeypot"] = {"pass": True, "detail": "simulation unavailable (neutral)"}

    # --- Sell tax (GoPlus) ---
    if goplus:
        gp_honeypot = goplus.get("is_honeypot", False)
        gp_sell_tax = goplus.get("sell_tax", 0)
        gp_buy_tax = goplus.get("buy_tax", 0)

        if gp_honeypot:
            checks["goplus_honeypot"] = {"pass": False, "detail": "GoPlus flags as honeypot"}
            if "HONEYPOT_SUSPECTED" not in risk_flags:
                risk_flags.append("HONEYPOT_SUSPECTED")
            score -= 35

        if gp_sell_tax > 5:
            checks["sell_tax"] = {"pass": False, "tax_pct": gp_sell_tax}
            if "HIGH_SELL_TAX" not in risk_flags:
                risk_flags.append("HIGH_SELL_TAX")
            score -= 15
        else:
            checks["sell_tax"] = {"pass": True, "tax_pct": gp_sell_tax}

        checks["mintable"] = {"pass": not goplus.get("is_mintable", False)}
        if goplus.get("is_mintable"):
            risk_flags.append("MINTABLE")
            score -= 10

        checks["proxy_contract"] = {"pass": not goplus.get("is_proxy", False)}
        if goplus.get("is_proxy"):
            risk_flags.append("PROXY_CONTRACT")
            score -= 10

        checks["blacklist_function"] = {"pass": not goplus.get("is_blacklisted", False)}
        if goplus.get("is_blacklisted"):
            risk_flags.append("BLACKLIST_FUNCTION")
            score -= 10
    else:
        checks["sell_tax"] = {"pass": True, "detail": "GoPlus unavailable (neutral)"}
        checks["mintable"] = {"pass": True, "detail": "GoPlus unavailable (neutral)"}

    # --- RugCheck ---
    if rugcheck:
        rug_score = rugcheck.get("score", 0)
        lp_locked = rugcheck.get("lp_locked", True)
        top10 = rugcheck.get("top10_pct", 0)
        creator = rugcheck.get("creator_pct", 0)
        flags = rugcheck.get("flags", [])

        checks["rug_score"] = {
            "pass": rug_score < 5000,
            "score": rug_score,
            "flags": flags,
        }
        if rug_score >= 5000:
            risk_flags.append("HIGH_RUG_SCORE")
            score -= 15

        checks["lp_locked"] = {"pass": lp_locked}
        if not lp_locked:
            risk_flags.append("LP_UNLOCKED")
            score -= 15

        checks["holder_concentration"] = {
            "pass": top10 < 50,
            "top10_pct": top10,
            "creator_pct": creator,
        }
        if top10 >= 50:
            risk_flags.append("CONCENTRATED_HOLDINGS")
            score -= 10
        if creator >= 20:
            risk_flags.append("CREATOR_HIGH_HOLDINGS")
            score -= 10
    else:
        checks["rug_score"] = {"pass": True, "detail": "RugCheck unavailable (neutral)"}
        checks["lp_locked"] = {"pass": True, "detail": "RugCheck unavailable (neutral)"}
        checks["holder_concentration"] = {"pass": True, "detail": "RugCheck unavailable (neutral)"}

    # --- DexScreener market data ---
    if dex:
        liq_usd = dex.get("liquidity_usd", 0)
        vol_24h = dex.get("volume_24h", 0)
        age_h = dex.get("age_hours", 0)

        checks["liquidity"] = {"pass": liq_usd >= 5000, "usd": liq_usd}
        if liq_usd < 5000:
            risk_flags.append("LOW_LIQUIDITY")
            score -= 10
        elif liq_usd < 1000:
            score -= 5  # Additional penalty for very low

        checks["volume"] = {"pass": vol_24h >= 1000, "usd_24h": vol_24h}
        if vol_24h < 1000:
            risk_flags.append("LOW_VOLUME")
            score -= 5

        checks["age"] = {"pass": age_h >= 24, "hours": round(age_h, 1)}
        if age_h < 1:
            risk_flags.append("EXTREMELY_NEW")
            score -= 15
        elif age_h < 24:
            risk_flags.append("NEW_TOKEN")
            score -= 5
    else:
        checks["liquidity"] = {"pass": True, "detail": "DexScreener unavailable"}
        checks["volume"] = {"pass": True, "detail": "DexScreener unavailable"}
        checks["age"] = {"pass": True, "detail": "DexScreener unavailable"}

    # Clamp score
    score = max(0, min(100, score))

    # Determine verdict
    if score >= 75:
        verdict = "SAFE"
    elif score >= 50:
        verdict = "CAUTION"
    elif score >= 25:
        verdict = "AVOID"
    else:
        verdict = "RUG"

    # Convert checks dict to list format expected by API
    checks_out = {k: v for k, v in checks.items()}

    return verdict, score, checks_out, risk_flags


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

async def scan_token(mint: str) -> dict:
    """Scan a token for safety — fetches all 4 sources in parallel.

    Returns full scan result dict. Uses 5-minute cache.
    """
    # Check cache
    now = time.time()
    if mint in _scan_cache:
        cached_ts, cached_result = _scan_cache[mint]
        if now - cached_ts < CACHE_TTL:
            return {**cached_result, "cached": True}

    t0 = time.time()

    # Fetch all 4 sources in parallel
    dex, rugcheck, goplus, jup_sim = await asyncio.gather(
        fetch_dexscreener(mint),
        fetch_rugcheck(mint),
        fetch_goplus(mint),
        simulate_honeypot(mint),
        return_exceptions=True,
    )

    # Handle exceptions from gather
    if isinstance(dex, Exception):
        dex = {}
    if isinstance(rugcheck, Exception):
        rugcheck = {}
    if isinstance(goplus, Exception):
        goplus = {}
    if isinstance(jup_sim, Exception):
        jup_sim = {}

    # Token not found at all
    if not dex:
        return {"error": f"Token {mint} not found on DexScreener (Solana pairs only)"}

    # Compute verdict
    verdict, safety_score, checks, risk_flags = compute_verdict(
        dex, rugcheck, goplus, jup_sim,
    )

    latency_ms = round((time.time() - t0) * 1000)

    result = {
        "mint": mint,
        "symbol": dex.get("symbol", "???"),
        "verdict": verdict,
        "safety_score": safety_score,
        "price_usd": dex.get("price_usd"),
        "market_cap": dex.get("market_cap"),
        "liquidity_usd": dex.get("liquidity_usd"),
        "volume_24h": dex.get("volume_24h"),
        "age_hours": round(dex.get("age_hours", 0), 1),
        "checks": checks,
        "risk_flags": risk_flags,
        "sources": {
            "dexscreener": bool(dex),
            "rugcheck": bool(rugcheck),
            "goplus": bool(goplus),
            "jupiter_sim": bool(jup_sim),
        },
        "latency_ms": latency_ms,
        "cached": False,
    }

    # Cache result
    _scan_cache[mint] = (now, result)

    return result


# ---------------------------------------------------------------------------
# Trending scanner
# ---------------------------------------------------------------------------

async def fetch_trending_mints() -> list[str]:
    """Fetch trending Solana mints from DexScreener."""
    mints: list[str] = []

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.dexscreener.com/token-boosts/top/v1",
                headers={"User-Agent": "SolSignal/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data if isinstance(data, list) else data.get("data", data.get("tokens", []))
                for item in items:
                    if isinstance(item, dict):
                        chain = item.get("chainId", item.get("chain", ""))
                        if chain == "solana":
                            addr = item.get("tokenAddress", item.get("address", ""))
                            if addr and len(addr) > 20:
                                mints.append(addr)
    except Exception:
        pass

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for m in mints:
        if m not in seen:
            seen.add(m)
            unique.append(m)
    return unique


# --- Trending cache ---
_trending_cache: dict[str, Any] = {}
_trending_cache_ts: float = 0
TRENDING_CACHE_TTL = 300  # 5 minutes


async def scan_trending(limit: int = 20) -> dict:
    """Fetch trending tokens and scan each for safety.

    Cached for 5 minutes. Scans up to `limit` tokens in parallel.
    """
    global _trending_cache, _trending_cache_ts
    now = time.time()

    if _trending_cache and now - _trending_cache_ts < TRENDING_CACHE_TTL:
        return {**_trending_cache, "cached": True}

    t0 = time.time()

    mints = await fetch_trending_mints()
    if not mints:
        return {"error": "Could not fetch trending tokens", "tokens": []}

    # Scan top N in parallel (with some concurrency control)
    mints_to_scan = mints[:limit]
    sem = asyncio.Semaphore(5)  # Max 5 concurrent scans

    async def _scan_with_sem(m: str) -> dict:
        async with sem:
            return await scan_token(m)

    results = await asyncio.gather(
        *[_scan_with_sem(m) for m in mints_to_scan],
        return_exceptions=True,
    )

    tokens = []
    for r in results:
        if isinstance(r, dict) and "error" not in r:
            tokens.append(r)

    # Sort by safety_score descending
    tokens.sort(key=lambda t: t.get("safety_score", 0), reverse=True)

    output = {
        "total_scanned": len(mints_to_scan),
        "total_returned": len(tokens),
        "tokens": tokens,
        "verdicts": {
            "SAFE": sum(1 for t in tokens if t.get("verdict") == "SAFE"),
            "CAUTION": sum(1 for t in tokens if t.get("verdict") == "CAUTION"),
            "AVOID": sum(1 for t in tokens if t.get("verdict") == "AVOID"),
            "RUG": sum(1 for t in tokens if t.get("verdict") == "RUG"),
        },
        "latency_ms": round((time.time() - t0) * 1000),
        "cached": False,
    }

    _trending_cache = output
    _trending_cache_ts = now

    return output
