from __future__ import annotations

import httpx
import pytest

from cipher_mcp import LazyMCPBridge, build_cipher_mcp
from x402.schemas import PaymentRequirements


@pytest.mark.asyncio
async def test_lazy_mcp_bridge_fails_closed_before_startup() -> None:
    bridge = LazyMCPBridge()
    transport = httpx.ASGITransport(app=bridge)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.post("/")
    assert response.status_code == 503
    assert response.json()["error"] == "CIPHER MCP is temporarily unavailable"
    assert bridge.ready is False


@pytest.mark.asyncio
async def test_lazy_mcp_bridge_delegates_after_ready() -> None:
    async def ready_app(scope, receive, send):
        response = httpx.Response(200, json={"ready": True})
        body = response.content
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })

    bridge = LazyMCPBridge()
    bridge.set_app(ready_app)
    transport = httpx.ASGITransport(app=bridge)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get("/")
    assert response.status_code == 200
    assert response.json() == {"ready": True}
    assert bridge.ready is True


def test_build_paid_mcp_with_pinned_sdk_registers_all_prices() -> None:
    price_keys: list[str] = []

    class FakeScheme:
        # x402 validation intentionally skips payment-flow resolution
        # when payment_flows is not a Mapping.
        payment_flows = None

    class FakeResourceServer:
        def get_registered_scheme(self, network, scheme):
            return FakeScheme()

    def requirements_for_price(price_key: str):
        price_keys.append(price_key)
        return PaymentRequirements(
            scheme="exact",
            network="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            asset="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            amount="1000",
            pay_to="HDJ88KsVwUGxGZmEdKtgMxHvssZR4gfFp1v1izCPK5x9",
            max_timeout_seconds=60,
        )

    def recorder(**kwargs):
        raise AssertionError("settlement recorder must not run during registration")

    mcp, asgi = build_cipher_mcp(
        resource_server=FakeResourceServer(),
        requirements_for_price=requirements_for_price,
        public_base_url="https://solsignal-api.onrender.com",
        settlement_recorder=recorder,
    )

    assert mcp is not None
    assert asgi is not None
    assert len(price_keys) == 8
    assert set(price_keys) == {
        "tool_solana_tx_status",
        "tool_solana_simulate",
        "tool_solana_forensics",
        "tool_solana_wallet",
        "tool_mcp_audit",
        "tool_x402_audit",
        "tool_x402_prepay",
        "tool_json",
    }
    # streamable_http_app() must have created a session manager for host lifespan.
    assert mcp.session_manager is not None
