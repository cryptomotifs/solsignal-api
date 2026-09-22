"""SolSignal Sentinel — deterministic pre-trade risk gate for Steve Agent Arena.

This module does NOT execute trades. It converts SolSignal token-security evidence
into an auditable APPROVE / WATCH / BLOCK decision that can be paired with Steve's
own simulation, signing, execution, and receipt pipeline.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict, dataclass
from typing import Any

from scanner import scan_token


STRATEGY_VERSION = "sentinel-1.0"


@dataclass(frozen=True)
class SentinelPolicy:
    min_safety_score: int = 75
    watch_floor: int = 60
    min_liquidity_usd: float = 10_000.0
    max_notional_usd: float = 25.0
    max_liquidity_share_bps: float = 5.0
    critical_flags: tuple[str, ...] = (
        "HONEYPOT_SUSPECTED",
        "HIGH_SELL_TAX",
        "LP_UNLOCKED",
        "BLACKLIST_FUNCTION",
    )


def _max_size(scan: dict[str, Any], policy: SentinelPolicy) -> float:
    liquidity = max(0.0, float(scan.get("liquidity_usd") or 0.0))
    liquidity_cap = liquidity * (policy.max_liquidity_share_bps / 10_000.0)
    return round(max(0.0, min(policy.max_notional_usd, liquidity_cap)), 2)


def decision_from_scan(
    scan: dict[str, Any],
    requested_notional_usd: float = 5.0,
    policy: SentinelPolicy | None = None,
) -> dict[str, Any]:
    """Turn a SolSignal scan into a deterministic Steve pre-trade decision."""
    policy = policy or SentinelPolicy()
    requested = max(0.0, float(requested_notional_usd))

    if scan.get("error"):
        return {
            "strategy": "SolSignal Sentinel",
            "strategy_version": STRATEGY_VERSION,
            "decision": "BLOCK",
            "eligible_for_execution": False,
            "requested_notional_usd": requested,
            "max_allowed_notional_usd": 0.0,
            "reasons": ["SCAN_UNAVAILABLE"],
            "scan_error": scan.get("error"),
        }

    verdict = str(scan.get("verdict") or "UNKNOWN").upper()
    score = int(scan.get("safety_score") or 0)
    liquidity = float(scan.get("liquidity_usd") or 0.0)
    risk_flags = [str(x) for x in (scan.get("risk_flags") or [])]
    critical = [flag for flag in risk_flags if flag in policy.critical_flags]
    max_allowed = _max_size(scan, policy)

    reasons: list[str] = []
    decision = "APPROVE"

    if verdict in {"RUG", "AVOID"}:
        decision = "BLOCK"
        reasons.append(f"VERDICT_{verdict}")

    if critical:
        decision = "BLOCK"
        reasons.extend(f"CRITICAL_{flag}" for flag in critical)

    if liquidity < policy.min_liquidity_usd:
        decision = "BLOCK"
        reasons.append("LIQUIDITY_BELOW_FLOOR")

    if decision != "BLOCK" and (verdict == "CAUTION" or score < policy.min_safety_score):
        decision = "WATCH"
        reasons.append("SAFETY_SCORE_BELOW_EXECUTION_THRESHOLD")

    if decision == "APPROVE" and requested > max_allowed:
        decision = "WATCH"
        reasons.append("REQUESTED_SIZE_ABOVE_POLICY_CAP")

    if score < policy.watch_floor:
        decision = "BLOCK"
        reasons.append("SAFETY_SCORE_BELOW_WATCH_FLOOR")

    if not reasons:
        reasons.append("ALL_SENTINEL_GATES_PASSED")

    return {
        "strategy": "SolSignal Sentinel",
        "strategy_version": STRATEGY_VERSION,
        "decision": decision,
        "eligible_for_execution": decision == "APPROVE",
        "symbol": scan.get("symbol"),
        "mint": scan.get("mint"),
        "verdict": verdict,
        "safety_score": score,
        "risk_flags": risk_flags,
        "requested_notional_usd": requested,
        "max_allowed_notional_usd": max_allowed,
        "liquidity_usd": liquidity,
        "sources": scan.get("sources") or {},
        "reasons": list(dict.fromkeys(reasons)),
        "next_step": (
            "Hand the candidate to Steve for route construction + transaction simulation."
            if decision == "APPROVE"
            else "Do not execute. Re-scan later or reject the candidate."
        ),
    }


async def evaluate_mint(
    mint: str,
    requested_notional_usd: float = 5.0,
    policy: SentinelPolicy | None = None,
) -> dict[str, Any]:
    scan = await scan_token(mint)
    return decision_from_scan(scan, requested_notional_usd, policy)


def main() -> None:
    parser = argparse.ArgumentParser(description="SolSignal Sentinel pre-trade gate")
    parser.add_argument("mint", help="Solana token mint")
    parser.add_argument("--notional", type=float, default=5.0, help="Requested USD notional")
    parser.add_argument("--show-policy", action="store_true")
    args = parser.parse_args()

    policy = SentinelPolicy()
    if args.show_policy:
        print(json.dumps(asdict(policy), indent=2))
        return

    result = asyncio.run(evaluate_mint(args.mint, args.notional, policy))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
