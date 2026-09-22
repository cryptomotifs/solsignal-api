from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any


class PaymentStore:
    """Settlement ledger with Postgres in production and SQLite fallback locally."""

    def __init__(self, *, database_url: str = "", sqlite_path: str) -> None:
        self.database_url = (database_url or "").strip()
        self.sqlite_path = sqlite_path

    @property
    def backend(self) -> str:
        return "postgres" if self.database_url else "sqlite"

    @property
    def durable(self) -> bool:
        return bool(self.database_url)

    def _connect(self):
        if self.database_url:
            import psycopg

            return psycopg.connect(self.database_url)

        os.makedirs(os.path.dirname(self.sqlite_path), exist_ok=True)
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            if self.database_url:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settlements (
                        tx_signature TEXT PRIMARY KEY,
                        endpoint TEXT NOT NULL,
                        amount_atomic BIGINT NOT NULL,
                        amount_usdc DOUBLE PRECISION NOT NULL,
                        payer TEXT,
                        network TEXT NOT NULL,
                        facilitator TEXT NOT NULL,
                        settled_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
            else:
                cur.execute(
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

    def record_settlement(
        self,
        *,
        transaction: str,
        endpoint: str,
        amount_atomic: int,
        payer: str | None,
        network: str,
        facilitator: str,
    ) -> None:
        if not transaction:
            raise ValueError("A confirmed settlement must include a transaction signature")

        self.initialize()
        conn = self._connect()
        try:
            cur = conn.cursor()
            params = (
                transaction,
                endpoint,
                int(amount_atomic),
                int(amount_atomic) / 1_000_000,
                payer,
                network,
                facilitator,
                datetime.now(timezone.utc),
            )
            if self.database_url:
                cur.execute(
                    """
                    INSERT INTO settlements
                    (tx_signature, endpoint, amount_atomic, amount_usdc, payer, network, facilitator, settled_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tx_signature) DO NOTHING
                    """,
                    params,
                )
            else:
                cur.execute(
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
                        facilitator,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def stats(self) -> dict[str, Any]:
        self.initialize()
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) AS cnt, COALESCE(SUM(amount_atomic), 0) AS total FROM settlements"
            )
            row = cur.fetchone()

            cur.execute(
                """
                SELECT tx_signature, endpoint, amount_usdc, payer, network, facilitator, settled_at
                FROM settlements
                ORDER BY settled_at DESC
                LIMIT 20
                """
            )
            rows = cur.fetchall()

            recent: list[dict[str, Any]] = []
            for r in rows:
                if self.database_url:
                    tx_signature, endpoint, amount_usdc, payer, network, facilitator, settled_at = r
                    item = {
                        "transaction": tx_signature,
                        "endpoint": endpoint,
                        "amount_usdc": float(amount_usdc),
                        "payer": payer,
                        "network": network,
                        "facilitator": facilitator,
                        "settled_at": settled_at.isoformat() if hasattr(settled_at, "isoformat") else str(settled_at),
                    }
                else:
                    item = dict(r)
                    item["transaction"] = item.pop("tx_signature")
                recent.append(item)

            count = int(row[0] if self.database_url else row["cnt"]) if row else 0
            total_atomic = int(row[1] if self.database_url else row["total"]) if row else 0
            return {
                "total_usdc": round(total_atomic / 1_000_000, 6),
                "settlements": count,
                "recent": recent,
                "ledger_backend": self.backend,
                "ledger_durable": self.durable,
            }
        finally:
            conn.close()
