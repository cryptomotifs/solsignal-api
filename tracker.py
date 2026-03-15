"""Scan Tracker — Records scan results and tracks outcome accuracy.

Stores every /scan call in SQLite. Background job checks prices 1h/24h later
via DexScreener. Public /track/stats endpoint shows verifiable accuracy.
"""
from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timezone

import httpx

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scan_history.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mint TEXT NOT NULL,
            symbol TEXT,
            verdict TEXT NOT NULL,
            safety_score INTEGER,
            price_at_scan REAL,
            scan_ts REAL NOT NULL,
            price_1h REAL,
            price_24h REAL,
            pct_change_1h REAL,
            pct_change_24h REAL,
            outcome TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans (scan_ts)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_mint ON scans (mint)
    """)
    conn.commit()
    return conn


def record_scan(mint: str, symbol: str, verdict: str, safety_score: int, price: float):
    """Record a scan result."""
    conn = _get_conn()
    conn.execute(
        "INSERT INTO scans (mint, symbol, verdict, safety_score, price_at_scan, scan_ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (mint, symbol, verdict, safety_score, price, time.time()),
    )
    conn.commit()
    conn.close()


async def backfill_outcomes():
    """Check prices for past scans that need 1h or 24h price updates.

    Called periodically (every ~30 min) by background task.
    """
    conn = _get_conn()
    now = time.time()

    # Find scans needing 1h price (scanned 1-2h ago, no price_1h yet)
    rows_1h = conn.execute(
        "SELECT id, mint, price_at_scan FROM scans "
        "WHERE price_1h IS NULL AND scan_ts < ? AND scan_ts > ?",
        (now - 3600, now - 7200),
    ).fetchall()

    # Find scans needing 24h price (scanned 24-48h ago, no price_24h yet)
    rows_24h = conn.execute(
        "SELECT id, mint, price_at_scan FROM scans "
        "WHERE price_24h IS NULL AND scan_ts < ? AND scan_ts > ?",
        (now - 86400, now - 172800),
    ).fetchall()

    # Collect unique mints to fetch
    mints_to_fetch: set[str] = set()
    for row in rows_1h:
        mints_to_fetch.add(row["mint"])
    for row in rows_24h:
        mints_to_fetch.add(row["mint"])

    if not mints_to_fetch:
        conn.close()
        return

    # Fetch current prices from DexScreener
    prices: dict[str, float] = {}
    for mint in mints_to_fetch:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://api.dexscreener.com/latest/dex/tokens/{mint}")
                if resp.status_code == 200:
                    data = resp.json()
                    pairs = data.get("pairs") or []
                    sol_pairs = [p for p in pairs if (p.get("chainId") or "").lower() == "solana"]
                    if sol_pairs:
                        pair = max(sol_pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0))
                        prices[mint] = float(pair.get("priceUsd") or 0)
        except Exception:
            pass

    # Update 1h prices
    for row in rows_1h:
        price_now = prices.get(row["mint"])
        if price_now is not None and row["price_at_scan"] and row["price_at_scan"] > 0:
            pct = ((price_now - row["price_at_scan"]) / row["price_at_scan"]) * 100
            conn.execute(
                "UPDATE scans SET price_1h = ?, pct_change_1h = ? WHERE id = ?",
                (price_now, round(pct, 2), row["id"]),
            )

    # Update 24h prices + compute outcome
    for row in rows_24h:
        price_now = prices.get(row["mint"])
        if price_now is not None and row["price_at_scan"] and row["price_at_scan"] > 0:
            pct = ((price_now - row["price_at_scan"]) / row["price_at_scan"]) * 100
            # Outcome: did our verdict predict correctly?
            outcome = _compute_outcome(
                conn.execute("SELECT verdict FROM scans WHERE id = ?", (row["id"],)).fetchone()["verdict"],
                pct,
            )
            conn.execute(
                "UPDATE scans SET price_24h = ?, pct_change_24h = ?, outcome = ? WHERE id = ?",
                (price_now, round(pct, 2), outcome, row["id"]),
            )

    conn.commit()
    conn.close()


def _compute_outcome(verdict: str, pct_24h: float) -> str:
    """Determine if our verdict was correct based on 24h price change.

    AVOID/RUG verdicts are correct if price dropped >20%.
    SAFE verdicts are correct if price didn't drop >30%.
    CAUTION is harder to grade — neutral outcome.
    """
    if verdict in ("AVOID", "RUG"):
        if pct_24h < -20:
            return "CORRECT"
        elif pct_24h < 0:
            return "PARTIALLY_CORRECT"
        else:
            return "INCORRECT"
    elif verdict == "SAFE":
        if pct_24h > -30:
            return "CORRECT"
        else:
            return "INCORRECT"
    else:  # CAUTION
        if -20 < pct_24h < 20:
            return "CORRECT"
        else:
            return "NEUTRAL"


def get_stats() -> dict:
    """Compute aggregate accuracy stats for public display."""
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) as cnt FROM scans").fetchone()["cnt"]
    with_outcome = conn.execute(
        "SELECT COUNT(*) as cnt FROM scans WHERE outcome IS NOT NULL"
    ).fetchone()["cnt"]

    # Verdict distribution
    verdict_counts = {}
    for row in conn.execute("SELECT verdict, COUNT(*) as cnt FROM scans GROUP BY verdict"):
        verdict_counts[row["verdict"]] = row["cnt"]

    # Accuracy by verdict (only for scans with outcomes)
    accuracy: dict[str, dict] = {}
    for verdict in ("SAFE", "CAUTION", "AVOID", "RUG"):
        rows = conn.execute(
            "SELECT outcome, COUNT(*) as cnt FROM scans "
            "WHERE verdict = ? AND outcome IS NOT NULL GROUP BY outcome",
            (verdict,),
        ).fetchall()
        if rows:
            outcomes = {r["outcome"]: r["cnt"] for r in rows}
            total_v = sum(outcomes.values())
            correct = outcomes.get("CORRECT", 0) + outcomes.get("PARTIALLY_CORRECT", 0) * 0.5
            accuracy[verdict] = {
                "total": total_v,
                "correct": outcomes.get("CORRECT", 0),
                "partially_correct": outcomes.get("PARTIALLY_CORRECT", 0),
                "incorrect": outcomes.get("INCORRECT", 0),
                "accuracy_pct": round(correct / total_v * 100, 1) if total_v > 0 else 0,
            }

    # Overall accuracy
    all_with_outcome = conn.execute(
        "SELECT outcome, COUNT(*) as cnt FROM scans WHERE outcome IS NOT NULL GROUP BY outcome"
    ).fetchall()
    total_graded = sum(r["cnt"] for r in all_with_outcome)
    correct_total = sum(
        r["cnt"] for r in all_with_outcome if r["outcome"] == "CORRECT"
    ) + sum(
        r["cnt"] * 0.5 for r in all_with_outcome if r["outcome"] == "PARTIALLY_CORRECT"
    )
    overall_accuracy = round(correct_total / total_graded * 100, 1) if total_graded > 0 else 0

    # Recent scans
    recent = [
        dict(r) for r in conn.execute(
            "SELECT mint, symbol, verdict, safety_score, price_at_scan, "
            "scan_ts, pct_change_1h, pct_change_24h, outcome "
            "FROM scans ORDER BY scan_ts DESC LIMIT 20"
        ).fetchall()
    ]

    # Avg price change by verdict (for scans with 24h data)
    avg_changes: dict[str, float] = {}
    for verdict in ("SAFE", "CAUTION", "AVOID", "RUG"):
        row = conn.execute(
            "SELECT AVG(pct_change_24h) as avg_pct FROM scans "
            "WHERE verdict = ? AND pct_change_24h IS NOT NULL",
            (verdict,),
        ).fetchone()
        if row["avg_pct"] is not None:
            avg_changes[verdict] = round(row["avg_pct"], 2)

    conn.close()

    return {
        "total_scans": total,
        "scans_with_outcomes": with_outcome,
        "overall_accuracy_pct": overall_accuracy,
        "verdict_distribution": verdict_counts,
        "accuracy_by_verdict": accuracy,
        "avg_24h_change_by_verdict": avg_changes,
        "recent_scans": recent,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_token_history(mint: str) -> dict:
    """Get scan history for a specific token."""
    conn = _get_conn()
    rows = [
        dict(r) for r in conn.execute(
            "SELECT * FROM scans WHERE mint = ? ORDER BY scan_ts DESC LIMIT 50",
            (mint,),
        ).fetchall()
    ]
    conn.close()

    if not rows:
        return {"error": f"No scan history for {mint}"}

    return {
        "mint": mint,
        "symbol": rows[0].get("symbol", "???"),
        "total_scans": len(rows),
        "scans": rows,
    }
