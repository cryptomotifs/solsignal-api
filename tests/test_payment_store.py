from payment_store import PaymentStore


def test_sqlite_payment_store_is_idempotent_and_reports_backend(tmp_path) -> None:
    store = PaymentStore(sqlite_path=str(tmp_path / "payments.db"))
    store.initialize()

    kwargs = {
        "transaction": "tx-123",
        "endpoint": "/tools/transform",
        "amount_atomic": 1000,
        "payer": "payer-1",
        "network": "solana:test",
        "facilitator": "https://facilitator.example",
    }
    store.record_settlement(**kwargs)
    store.record_settlement(**kwargs)

    stats = store.stats()
    assert stats["settlements"] == 1
    assert stats["total_usdc"] == 0.001
    assert stats["recent"][0]["transaction"] == "tx-123"
    assert stats["ledger_backend"] == "sqlite"
    assert stats["ledger_durable"] is False


def test_database_url_selects_postgres_backend_without_connecting(tmp_path) -> None:
    store = PaymentStore(
        database_url="postgresql://user:pass@example.invalid/db",
        sqlite_path=str(tmp_path / "payments.db"),
    )
    assert store.backend == "postgres"
    assert store.durable is True
