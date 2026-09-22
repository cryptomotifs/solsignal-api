import pytest

import app as solsignal
import agent_infra_tools as infra
from agent_tools import ToolError


@pytest.mark.asyncio
async def test_bulk_mcp_caps_batch_size() -> None:
    with pytest.raises(ToolError):
        await infra.bulk_mcp_audit(["https://example.com/mcp"] * 11)


@pytest.mark.asyncio
async def test_bulk_x402_caps_batch_size() -> None:
    with pytest.raises(ToolError):
        await infra.bulk_x402_audit(["https://example.com/tool"] * 11)


@pytest.mark.asyncio
async def test_adoption_preflight_requires_evidence_source() -> None:
    with pytest.raises(ToolError):
        await infra.agent_adoption_preflight()


@pytest.mark.asyncio
async def test_registry_doctor_uses_schema_and_common_warnings(monkeypatch) -> None:
    async def fake_schema(_url: str):
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["description"],
            "properties": {"description": {"type": "string"}},
        }

    monkeypatch.setattr(infra, "_load_registry_schema", fake_schema)
    result = await infra.mcp_registry_doctor(
        {"description": "A remote MCP server"},
        probe_remote=False,
    )
    assert result["valid_against_declared_schema"] is True
    assert result["publish_readiness"] == "REVIEW"
    codes = {item["code"] for item in result["warnings"]}
    assert "NO_PACKAGE_OR_REMOTE" in codes


def test_v2_revenue_tools_are_discoverable() -> None:
    catalog = {item["path"]: item for item in solsignal._paid_endpoint_catalog()}
    assert catalog["/tools/mcp/bulk"]["amount"] == "50000"
    assert catalog["/tools/x402/bulk"]["amount"] == "50000"
    assert catalog["/tools/agent/adoption-preflight"]["amount"] == "25000"
    assert catalog["/tools/mcp/registry-doctor"]["amount"] == "10000"

    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    for path in (
        "/tools/mcp/bulk",
        "/tools/x402/bulk",
        "/tools/agent/adoption-preflight",
        "/tools/mcp/registry-doctor",
    ):
        operation = schema["paths"][path]["post"]
        assert operation["x-payment-info"]
        assert "402" in operation["responses"]
        assert operation["requestBody"]["required"] is True
