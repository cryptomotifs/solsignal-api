"""Live Scoring Engine — Score any Solana token in real-time.

Fetches live data from DexScreener, computes 40 derived metrics,
and scores through all 646 calibrated agents using IC-weighted scoring.
No bot dependencies — fully standalone.
"""
from __future__ import annotations

import math
import time

import httpx


# ---------------------------------------------------------------------------
# DexScreener fetch
# ---------------------------------------------------------------------------

async def fetch_token_data(mint: str) -> dict | None:
    """Fetch live token data from DexScreener for any Solana mint."""
    url = f"https://api.dexscreener.com/latest/dex/tokens/{mint}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception:
        return None

    pairs = data.get("pairs") or []
    # Filter to Solana pairs only
    sol_pairs = [p for p in pairs if (p.get("chainId") or "").lower() == "solana"]
    if not sol_pairs:
        return None

    # Pick highest-liquidity pair
    pair = max(sol_pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))

    vol = pair.get("volume") or {}
    txns = pair.get("txns") or {}
    pc = pair.get("priceChange") or {}
    liq = pair.get("liquidity") or {}

    created_at = pair.get("pairCreatedAt") or 0
    if created_at > 1e12:
        created_at /= 1000
    age_hours = (time.time() - created_at) / 3600.0 if created_at > 0 else 0.0

    return {
        "mint": mint,
        "symbol": (pair.get("baseToken") or {}).get("symbol", "???"),
        "price_usd": float(pair.get("priceUsd") or 0),
        "volume_5m": float(vol.get("m5") or 0),
        "volume_1h": float(vol.get("h1") or 0),
        "volume_6h": float(vol.get("h6") or 0),
        "volume_24h": float(vol.get("h24") or 0),
        "liquidity_usd": float(liq.get("usd") or 0),
        "buys_5m": float((txns.get("m5") or {}).get("buys") or 0),
        "sells_5m": float((txns.get("m5") or {}).get("sells") or 0),
        "buys_1h": float((txns.get("h1") or {}).get("buys") or 0),
        "sells_1h": float((txns.get("h1") or {}).get("sells") or 0),
        "buys_24h": float((txns.get("h24") or {}).get("buys") or 0),
        "sells_24h": float((txns.get("h24") or {}).get("sells") or 0),
        "pair_age_hours": age_hours,
        "market_cap": float(pair.get("marketCap") or 0),
        "fdv": float(pair.get("fdv") or 0),
        "price_change_5m": float(pc.get("m5") or 0),
        "price_change_1h": float(pc.get("h1") or 0),
        "price_change_6h": float(pc.get("h6") or 0),
        "price_change_24h": float(pc.get("h24") or 0),
    }


# ---------------------------------------------------------------------------
# Derived metrics (40 features, all normalized [0,1])
# ---------------------------------------------------------------------------

def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def compute_derived_metrics(raw: dict) -> dict[str, float]:
    """Compute ~40 normalised [0,1] derived metrics from raw token data."""
    g = raw.get
    vol5m = g("volume_5m", 0.0) or 0.0
    vol1h = g("volume_1h", 0.0) or 0.0
    vol6h = g("volume_6h", 0.0) or 0.0
    vol24h = g("volume_24h", 0.0) or 0.0
    liq = g("liquidity_usd", 0.0) or 0.0
    buys5m = g("buys_5m", 0.0) or 0.0
    sells5m = g("sells_5m", 0.0) or 0.0
    buys1h = g("buys_1h", 0.0) or 0.0
    sells1h = g("sells_1h", 0.0) or 0.0
    buys24h = g("buys_24h", 0.0) or 0.0
    sells24h = g("sells_24h", 0.0) or 0.0
    age_h = g("pair_age_hours", 0.0) or 0.0
    mcap = g("market_cap", 0.0) or 0.0
    pc5m = g("price_change_5m", 0.0) or 0.0
    pc1h = g("price_change_1h", 0.0) or 0.0
    pc6h = g("price_change_6h", 0.0) or 0.0
    pc24h = g("price_change_24h", 0.0) or 0.0
    open1h = g("open_1h", 0.0) or 0.0
    high1h = g("high_1h", 0.0) or 0.0
    low1h = g("low_1h", 0.0) or 0.0
    close1h = g("close_1h", 0.0) or 0.0
    trades1h = g("trades_1h", 0.0) or 0.0
    fdv = g("fdv", 0.0) or 0.0

    total_txns_1h = buys1h + sells1h
    hourly_avg_vol = _safe_div(vol24h, 24.0)

    d: dict[str, float] = {}

    # Volume
    d["volume_momentum"] = _clamp(_safe_div(vol1h, hourly_avg_vol, 0.5) / 5.0)
    d["volume_spike"] = _clamp(vol5m / max(hourly_avg_vol / 12.0, 1.0) / 5.0)
    d["volume_flow"] = _clamp(vol1h / 500_000.0)
    d["volume_intensity"] = _clamp(vol24h / 5_000_000.0)
    d["volume_consistency"] = _clamp(_safe_div(vol6h, vol24h * 0.25 + 1) / 2.0)
    d["volume_acceleration"] = _clamp((vol5m * 12) / max(vol1h, 1.0) / 3.0)
    d["volume_to_mcap"] = _clamp(_safe_div(vol24h, mcap + 1) / 2.0)

    # Price / momentum
    d["price_momentum_1h"] = _clamp((pc1h + 50) / 100.0)
    d["price_momentum_5m"] = _clamp((pc5m + 20) / 40.0)
    d["price_momentum_6h"] = _clamp((pc6h + 50) / 100.0)
    d["price_momentum_24h"] = _clamp((pc24h + 100) / 200.0)
    d["price_trend"] = _clamp((pc1h + pc6h / 2 + 75) / 150.0)
    d["breakout_strength"] = _clamp(pc5m / 20.0) if pc5m > 0 else 0.0
    d["mean_reversion"] = _clamp(1.0 - abs(pc1h) / 50.0)
    d["candle_body_ratio"] = _clamp(abs(close1h - open1h) / max(high1h - low1h, 0.0001))
    d["upper_wick_ratio"] = _clamp((high1h - max(open1h, close1h)) / max(high1h - low1h, 0.0001))
    d["lower_wick_ratio"] = _clamp((min(open1h, close1h) - low1h) / max(high1h - low1h, 0.0001))

    # Liquidity
    d["liquidity_depth"] = _clamp(liq / 500_000.0)
    d["liquidity_health"] = _clamp(liq / 50_000.0)
    d["liquidity_concentration"] = _clamp(_safe_div(liq, mcap + 1) * 5.0)
    d["volume_to_liquidity"] = _clamp(_safe_div(vol24h, liq + 1) / 10.0)

    # Order flow
    d["buy_sell_ratio"] = _clamp(_safe_div(buys1h, total_txns_1h + 1))
    d["buy_pressure"] = _clamp(buys1h / max(sells1h, 1.0) / 3.0)
    d["sell_pressure"] = _clamp(sells1h / max(buys1h, 1.0) / 3.0)
    d["whale_accumulation"] = _clamp(buys1h / 100.0) if buys1h > sells1h * 1.5 else 0.0
    d["distribution_signal"] = _clamp(sells1h / 100.0) if sells1h > buys1h * 1.5 else 0.0
    d["order_flow_imbalance"] = _clamp(abs(buys1h - sells1h) / max(total_txns_1h, 1.0))
    d["transaction_density"] = _clamp(total_txns_1h / 500.0)

    # Risk
    d["rug_risk"] = _clamp(1.0 - min(liq / max(mcap * 0.1, 1.0), 1.0))
    d["age_safety"] = _clamp(min(age_h / 720.0, 1.0))
    d["volatility_risk"] = _clamp(abs(pc1h) / 30.0)
    d["concentration_risk"] = _clamp(1.0 - _safe_div(total_txns_1h, 200.0))

    # Market structure
    d["market_maturity"] = _clamp(min(age_h / 2160.0, 1.0))
    d["market_cap_tier"] = _clamp(math.log10(mcap + 1) / 9.0) if mcap > 0 else 0.0
    d["fdv_ratio"] = _clamp(_safe_div(mcap, fdv + 1))
    d["trade_frequency"] = _clamp(trades1h / 300.0)

    # Composite
    d["bullish_sentiment"] = _clamp(
        (d["buy_pressure"] + d["price_momentum_1h"] + d["volume_momentum"]) / 3.0
    )
    d["bearish_sentiment"] = _clamp(
        (d["sell_pressure"] + (1.0 - d["price_momentum_1h"]) + d["volatility_risk"]) / 3.0
    )
    d["smart_money_signal"] = _clamp(
        (d["whale_accumulation"] + d["volume_momentum"] + d["liquidity_depth"]) / 3.0
    )

    return d


# ---------------------------------------------------------------------------
# Score a token through all agents using boost configs
# ---------------------------------------------------------------------------

def score_with_agents(derived: dict[str, float], boost_configs: dict) -> list[dict]:
    """Score derived metrics through all agents using pre-calibrated IC weights.

    Each agent's boost config contains:
        weights: {metric_key: ic_weight}
        flip: [metric_keys to invert]
        threshold: score cutoff for tier1

    Returns list of {agent, score, tier, precision} sorted by score desc.
    """
    results = []

    for agent_name, cfg in boost_configs.items():
        weights = cfg.get("weights", {})
        flip_set = set(cfg.get("flip", []))
        threshold = cfg.get("threshold", 0.5)
        precision = cfg.get("boosted_precision", 0)

        if not weights:
            continue

        weighted_sum = 0.0
        weight_total = 0.0

        for metric_key, ic_weight in weights.items():
            val = derived.get(metric_key, 0.5)
            w = abs(ic_weight)

            # Flip negatively-correlated metrics
            if metric_key in flip_set:
                val = 1.0 - val

            weighted_sum += val * w
            weight_total += w

        if weight_total < 1e-9:
            continue

        score = weighted_sum / weight_total
        tier = "tier1" if score >= threshold else "tier2" if score >= threshold * 0.7 else "tier3"

        results.append({
            "agent": agent_name,
            "score": round(score, 4),
            "tier": tier,
            "precision": precision,
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def compute_consensus(results: list[dict]) -> dict:
    """Compute multi-agent consensus from scoring results."""
    if not results:
        return {"consensus": "NO_DATA", "confidence": 0}

    tier1 = [r for r in results if r["tier"] == "tier1"]
    high_prec_tier1 = [r for r in tier1 if r["precision"] >= 60]

    t1_pct = len(tier1) / len(results) * 100
    avg_score = sum(r["score"] for r in results) / len(results)

    # Weight by precision for confidence
    if tier1:
        avg_t1_precision = sum(r["precision"] for r in tier1) / len(tier1)
    else:
        avg_t1_precision = 0

    # Consensus based on tier1 percentage + high-precision agreement
    if t1_pct > 40 and len(high_prec_tier1) > 20:
        consensus = "STRONG_BUY"
        confidence = min(95, int(avg_t1_precision))
    elif t1_pct > 25 and len(high_prec_tier1) > 10:
        consensus = "BUY"
        confidence = min(80, int(avg_t1_precision * 0.9))
    elif t1_pct > 15:
        consensus = "LEAN_BUY"
        confidence = min(65, int(avg_t1_precision * 0.7))
    elif t1_pct > 5:
        consensus = "NEUTRAL"
        confidence = 40
    else:
        consensus = "AVOID"
        confidence = max(30, 100 - int(t1_pct * 10))

    return {
        "consensus": consensus,
        "confidence": confidence,
        "agents_scored": len(results),
        "tier1_count": len(tier1),
        "tier1_pct": round(t1_pct, 1),
        "high_precision_tier1": len(high_prec_tier1),
        "avg_score": round(avg_score, 4),
        "avg_tier1_precision": round(avg_t1_precision, 1),
    }
