from __future__ import annotations

import pytest
from solders.pubkey import Pubkey

import app as solsignal
import solana_tools as st


@pytest.mark.asyncio
async def test_latest_blockhash(monkeypatch) -> None:
    async def fake_rpc(client, method, params=None):
        assert method == "getLatestBlockhash"
        return {
            "context": {"slot": 123},
            "value": {
                "blockhash": "11111111111111111111111111111111",
                "lastValidBlockHeight": 999,
            },
        }

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_latest_blockhash()
    assert result["blockhash"] == "11111111111111111111111111111111"
    assert result["last_valid_block_height"] == 999
    assert result["context_slot"] == 123


@pytest.mark.asyncio
async def test_priority_fee_summary(monkeypatch) -> None:
    account = str(Pubkey.default())

    async def fake_rpc(client, method, params=None):
        assert method == "getRecentPrioritizationFees"
        assert params == [[account]]
        return [
            {"slot": 1, "prioritizationFee": 0},
            {"slot": 2, "prioritizationFee": 1000},
            {"slot": 3, "prioritizationFee": 2000},
            {"slot": 4, "prioritizationFee": 3000},
            {"slot": 5, "prioritizationFee": 4000},
        ]

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_priority_fees(accounts=[account], sample_limit=5)
    assert result["unit"] == "micro-lamports per compute unit"
    assert result["summary"]["minimum"] == 0
    assert result["summary"]["median_nonzero"] == 3000
    assert result["summary"]["p75_nonzero"] == 3000
    assert result["summary"]["p90_nonzero"] == 4000
    assert result["maximum"] == 4000
    assert result["sample_count"] == 5


@pytest.mark.asyncio
async def test_rent_exemption(monkeypatch) -> None:
    async def fake_rpc(client, method, params=None):
        assert method == "getMinimumBalanceForRentExemption"
        assert params[0] == 165
        return 2_039_280

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_rent_exemption(165)
    assert result["lamports"] == 2_039_280
    assert result["sol"] == "0.00203928"


@pytest.mark.asyncio
async def test_account_info_compact(monkeypatch) -> None:
    address = str(Pubkey.default())

    async def fake_rpc(client, method, params=None):
        assert method == "getAccountInfo"
        return {
            "context": {"slot": 44},
            "value": {
                "lamports": 1_000_000_000,
                "owner": "11111111111111111111111111111111",
                "executable": False,
                "space": 165,
                "rentEpoch": 123,
                "data": {
                    "program": "spl-token",
                    "parsed": {"type": "account", "info": {}},
                },
            },
        }

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_account_info(address)
    assert result["exists"] is True
    assert result["sol"] == "1"
    assert result["space_bytes"] == 165
    assert result["parsed_program"] == "spl-token"
    assert result["parsed_type"] == "account"


@pytest.mark.asyncio
async def test_message_fee(monkeypatch) -> None:
    async def fake_rpc(client, method, params=None):
        assert method == "getFeeForMessage"
        assert params[0] == "AQ=="
        return {"context": {"slot": 88}, "value": 5000}

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_message_fee("AQ==")
    assert result["fee_lamports"] == 5000
    assert result["fee_sol"] == "0.000005"
    assert result["context_slot"] == 88


def test_v5_products_are_discoverable() -> None:
    catalog = {item["path"]: item for item in solsignal._paid_endpoint_catalog()}
    expected = {
        "/tools/solana/blockhash": "1000",
        "/tools/solana/priority-fees": "2000",
        "/tools/solana/rent": "1000",
        "/tools/solana/account": "1000",
        "/tools/solana/message-fee": "2000",
    }
    for path, amount in expected.items():
        assert catalog[path]["amount"] == amount

    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    for path in expected:
        method = "get" if path.endswith("/blockhash") else "post"
        assert schema["paths"][path][method]["x-payment-info"]
