from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import Request, Response
from x402.schemas import SettleResponse

import app as solsignal


def _request(path: str = "/paid") -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 443),
    }
    return Request(scope)


def test_settlement_ledger_is_idempotent(tmp_path, monkeypatch) -> None:
    db = tmp_path / "payments.db"
    monkeypatch.setattr(solsignal, "PAYMENTS_DB", str(db))

    solsignal._record_settlement(
        transaction="tx-one",
        endpoint="/scan/example",
        amount_atomic=10_000,
        payer="payer-one",
        network=solsignal.SOLANA_NETWORK,
    )
    # Same on-chain transaction must never be double-counted.
    solsignal._record_settlement(
        transaction="tx-one",
        endpoint="/scan/example",
        amount_atomic=10_000,
        payer="payer-one",
        network=solsignal.SOLANA_NETWORK,
    )

    stats = solsignal._payment_stats()
    assert stats["settlements"] == 1
    assert stats["total_usdc"] == 0.01
    assert stats["recent"][0]["transaction"] == "tx-one"


@pytest.mark.asyncio
async def test_successful_settlement_is_recorded_after_handler(tmp_path, monkeypatch) -> None:
    db = tmp_path / "payments.db"
    monkeypatch.setattr(solsignal, "PAYMENTS_DB", str(db))

    settlement = SettleResponse(
        success=True,
        transaction="confirmed-signature",
        network=solsignal.SOLANA_NETWORK,
        payer="payer-wallet",
        amount="10000",
    )

    class FakeResourceServer:
        async def settle_payment(self, payload, requirements):
            return settlement

    monkeypatch.setattr(solsignal, "_x402_resource_server", FakeResourceServer())

    request = _request()
    request.state.x402_payment_payload = object()
    request.state.x402_payment_requirements = SimpleNamespace(amount="10000")
    request.state.x402_endpoint = "/scan/example"
    request.state.x402_amount_atomic = 10_000

    async def call_next(_request: Request) -> Response:
        return Response(content=b"ok", status_code=200)

    response = await solsignal.settle_verified_x402(request, call_next)
    assert response.status_code == 200
    assert "PAYMENT-RESPONSE" in response.headers
    assert solsignal._payment_stats()["settlements"] == 1


@pytest.mark.asyncio
async def test_failed_settlement_never_counts_as_revenue(tmp_path, monkeypatch) -> None:
    db = tmp_path / "payments.db"
    monkeypatch.setattr(solsignal, "PAYMENTS_DB", str(db))

    settlement = SettleResponse(
        success=False,
        transaction="",
        network=solsignal.SOLANA_NETWORK,
        error_reason="not_settled",
    )

    class FakeResourceServer:
        async def settle_payment(self, payload, requirements):
            return settlement

    monkeypatch.setattr(solsignal, "_x402_resource_server", FakeResourceServer())

    request = _request()
    request.state.x402_payment_payload = object()
    request.state.x402_payment_requirements = SimpleNamespace(amount="10000")
    request.state.x402_endpoint = "/scan/example"
    request.state.x402_amount_atomic = 10_000

    async def call_next(_request: Request) -> Response:
        return Response(content=b"ok", status_code=200)

    response = await solsignal.settle_verified_x402(request, call_next)
    assert response.status_code == 502
    assert solsignal._payment_stats()["settlements"] == 0
