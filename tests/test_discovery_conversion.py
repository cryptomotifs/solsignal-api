from __future__ import annotations

import pytest

import app as solsignal


def test_bazaar_solana_status_has_output_example() -> None:
    ext = solsignal._bazaar_extensions(
        "/tools/solana/tx-status",
        "tool_solana_tx_status",
    )
    bazaar = ext["bazaar"]
    assert bazaar["info"]["input"]["method"] == "POST"
    assert bazaar["info"]["output"]["type"] == "json"
    example = bazaar["info"]["output"]["example"]
    assert example["confirmation_status"] == "finalized"
    assert example["finalized"] is True
    assert "output" in bazaar["schema"]["properties"]


def test_bazaar_simulation_example_states_no_broadcast() -> None:
    ext = solsignal._bazaar_extensions(
        "/tools/solana/simulate",
        "tool_solana_simulate",
    )
    example = ext["bazaar"]["info"]["output"]["example"]
    assert example["simulation_success"] is True
    assert example["broadcast"] is False


def test_catalog_tags_are_specific_and_keep_agent_tags() -> None:
    catalog = {item["path"]: item for item in solsignal._paid_endpoint_catalog()}

    solana_tags = solsignal._catalog_tags(catalog["/tools/solana/tx-forensics"])
    assert {"ai-agents", "x402", "solana", "blockchain"} <= set(solana_tags)

    mcp_tags = solsignal._catalog_tags(catalog["/tools/mcp/audit"])
    assert {"mcp", "developer-tools"} <= set(mcp_tags)

    payment_tags = solsignal._catalog_tags(catalog["/tools/x402/prepay-verify"])
    assert {"payments", "x402-security"} <= set(payment_tags)


@pytest.mark.asyncio
async def test_skill_md_contains_entire_canonical_catalog() -> None:
    response = await solsignal.skill_md()
    text = bytes(response.body).decode("utf-8")
    for item in solsignal._paid_endpoint_catalog():
        assert item["path"] in text
        assert item["description"] in text
    assert "tx-forensics" in text
    assert "prepay-verify" in text
    assert "mcp/oauth-doctor" in text


@pytest.mark.asyncio
async def test_llms_txt_contains_entire_canonical_catalog() -> None:
    response = await solsignal.llms_txt()
    text = bytes(response.body).decode("utf-8")
    catalog = solsignal._paid_endpoint_catalog()
    assert len(catalog) >= 34
    for item in catalog:
        expected = (
            f"{item['method']} {item['path']} — "
            f"{item['priceUsd']} — {item['description']}"
        )
        assert expected in text


def test_every_top_agent_tool_has_useful_resource_description() -> None:
    catalog = solsignal._paid_endpoint_catalog()
    generic = {"", "Low-cost machine-payable API for autonomous agents"}
    for item in catalog:
        assert item["description"] not in generic
        assert len(item["description"]) >= 20
