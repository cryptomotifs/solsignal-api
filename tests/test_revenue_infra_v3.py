from __future__ import annotations

import types

import pytest

import app as solsignal
import agent_infra_tools as infra


@pytest.mark.asyncio
async def test_mcp_oauth_doctor_valid_discovery(monkeypatch) -> None:
    monkeypatch.setattr(infra, "_validate_public_url", lambda url: None)

    class Response:
        status_code = 401
        headers = {
            "www-authenticate": (
                'Bearer resource_metadata="https://mcp.example/.well-known/'
                'oauth-protected-resource/mcp", scope="files:read"'
            )
        }

    async def fake_bounded_request(*args, **kwargs):
        return Response(), b"", "https://mcp.example/mcp"

    async def fake_fetch_json(client, url, *, timeout_seconds):
        if "oauth-protected-resource" in url:
            return (
                {
                    "resource": "https://mcp.example/mcp",
                    "authorization_servers": ["https://auth.example"],
                    "scopes_supported": ["files:read"],
                },
                200,
                url,
            )
        if "oauth-authorization-server" in url:
            return (
                {
                    "authorization_endpoint": "https://auth.example/authorize",
                    "token_endpoint": "https://auth.example/token",
                    "registration_endpoint": "https://auth.example/register",
                    "code_challenge_methods_supported": ["S256"],
                },
                200,
                url,
            )
        return None, 404, url

    monkeypatch.setattr(infra, "_bounded_request", fake_bounded_request)
    monkeypatch.setattr(infra, "_fetch_json_document", fake_fetch_json)

    result = await infra.mcp_oauth_doctor("https://mcp.example/mcp")
    assert result["status"] == "PASS"
    assert result["resource_metadata"]["resource"] == "https://mcp.example/mcp"
    assert result["authorization_servers"][0]["metadata_found"] is True
    assert result["authorization_servers"][0]["dynamic_client_registration_available"] is True
    assert result["credentials_requested"] is False
    assert result["tokens_requested"] is False


@pytest.mark.asyncio
async def test_mcp_oauth_doctor_flags_resource_mismatch(monkeypatch) -> None:
    monkeypatch.setattr(infra, "_validate_public_url", lambda url: None)

    class Response:
        status_code = 401
        headers = {}

    async def fake_bounded_request(*args, **kwargs):
        return Response(), b"", "https://mcp.example/mcp"

    async def fake_fetch_json(client, url, *, timeout_seconds):
        if "oauth-protected-resource" in url:
            return (
                {
                    "resource": "https://mcp.example/",
                    "authorization_servers": ["https://auth.example"],
                },
                200,
                url,
            )
        return (
            {
                "authorization_endpoint": "https://auth.example/authorize",
                "token_endpoint": "https://auth.example/token",
                "code_challenge_methods_supported": ["S256"],
            },
            200,
            url,
        )

    monkeypatch.setattr(infra, "_bounded_request", fake_bounded_request)
    monkeypatch.setattr(infra, "_fetch_json_document", fake_fetch_json)

    result = await infra.mcp_oauth_doctor("https://mcp.example/mcp")
    assert result["status"] == "FAIL"
    codes = {item["code"] for item in result["findings"]}
    assert "RESOURCE_IDENTIFIER_MISMATCH" in codes


def _challenge(pay_to: str = "seller-wallet", amount: str = "10000") -> dict:
    payload = {
        "x402Version": 2,
        "resource": {"url": "https://merchant.example/tool"},
        "accepts": [
            {
                "scheme": "exact",
                "network": solsignal.SOLANA_NETWORK,
                "asset": solsignal.USDC_MINT,
                "amount": amount,
                "payTo": pay_to,
                "maxTimeoutSeconds": 60,
            }
        ],
    }
    return {
        "http_status": 402,
        "challenge_found": True,
        "payload": payload,
        "x402_version": 2,
        "resource": payload["resource"],
        "requirements": [
            {
                "scheme": "exact",
                "network": solsignal.SOLANA_NETWORK,
                "asset": solsignal.USDC_MINT,
                "amount": amount,
                "amount_atomic": int(amount),
                "amount_usdc": int(amount) / 1_000_000,
                "payTo": pay_to,
                "maxTimeoutSeconds": 60,
            }
        ],
    }


@pytest.mark.asyncio
async def test_x402_prepay_verify_approves_stable_terms(monkeypatch) -> None:
    async def fake_audit(*args, **kwargs):
        return {
            "status": "PASS",
            "paid_method": "POST",
            "challenge": _challenge(),
        }

    monkeypatch.setattr(infra, "audit_x402_endpoint", fake_audit)
    result = await infra.x402_prepay_verify(
        "https://merchant.example/tool",
        policy={
            "max_amount_usdc": 0.05,
            "allowed_networks": [solsignal.SOLANA_NETWORK],
            "allowed_assets": [solsignal.USDC_MINT],
            "expected_pay_to": "seller-wallet",
            "allowed_origins": ["https://merchant.example"],
        },
    )
    assert result["approved"] is True
    assert result["challenge_consistent"] is True
    assert result["payment_signed"] is False
    assert result["payment_settled"] is False


@pytest.mark.asyncio
async def test_x402_prepay_verify_rejects_changed_terms(monkeypatch) -> None:
    calls = 0

    async def fake_audit(*args, **kwargs):
        nonlocal calls
        calls += 1
        return {
            "status": "PASS",
            "paid_method": "POST",
            "challenge": _challenge(
                pay_to="seller-wallet" if calls == 1 else "changed-wallet"
            ),
        }

    monkeypatch.setattr(infra, "audit_x402_endpoint", fake_audit)
    result = await infra.x402_prepay_verify(
        "https://merchant.example/tool",
        policy={"max_amount_usdc": 0.05},
    )
    assert result["approved"] is False
    assert result["challenge_consistent"] is False
    assert "PAYMENT_TERMS_CHANGED_BETWEEN_FETCHES" in result["reasons"]


def test_v3_products_are_machine_discoverable() -> None:
    catalog = {item["path"]: item for item in solsignal._paid_endpoint_catalog()}
    assert catalog["/tools/mcp/oauth-doctor"]["amount"] == "10000"
    assert catalog["/tools/x402/prepay-verify"]["amount"] == "5000"

    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    assert schema["paths"]["/tools/mcp/oauth-doctor"]["post"]["x-payment-info"]
    assert schema["paths"]["/tools/x402/prepay-verify"]["post"]["x-payment-info"]
    prepay = schema["paths"]["/tools/x402/prepay-verify"]["post"]["requestBody"]
    assert prepay["content"]["application/json"]["schema"]["required"] == ["url", "policy"]
