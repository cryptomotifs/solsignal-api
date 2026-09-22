from __future__ import annotations

import base64

import pytest
from solders.pubkey import Pubkey
from solders.signature import Signature

import app as solsignal
import solana_tools as st


@pytest.mark.asyncio
async def test_transaction_status_finalized(monkeypatch) -> None:
    signature = str(Signature.default())

    async def fake_rpc(client, method, params=None):
        assert method == "getSignatureStatuses"
        assert params == [[signature], {"searchTransactionHistory": True}]
        return {
            "context": {"slot": 500},
            "value": [
                {
                    "slot": 450,
                    "confirmations": None,
                    "err": None,
                    "confirmationStatus": "finalized",
                }
            ],
        }

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_transaction_status(signature)
    assert result["found"] is True
    assert result["success"] is True
    assert result["confirmed"] is True
    assert result["finalized"] is True
    assert result["slot"] == 450


@pytest.mark.asyncio
async def test_simulation_never_broadcasts(monkeypatch) -> None:
    raw = b"test-transaction"
    encoded = base64.b64encode(raw).decode()

    async def fake_rpc(client, method, params=None):
        assert method == "simulateTransaction"
        assert params[0] == encoded
        config = params[1]
        assert config["encoding"] == "base64"
        assert config["sigVerify"] is False
        assert config["replaceRecentBlockhash"] is True
        assert config["innerInstructions"] is True
        return {
            "context": {"slot": 123},
            "value": {
                "err": None,
                "unitsConsumed": 1777,
                "fee": 5000,
                "logs": ["Program A invoke [1]", "Program A success"],
                "replacementBlockhash": {
                    "blockhash": "abc",
                    "lastValidBlockHeight": 999,
                },
                "returnData": None,
                "loadedAccountsDataSize": 100,
                "innerInstructions": [{"index": 0, "instructions": []}],
                "preBalances": [10000],
                "postBalances": [5000],
                "preTokenBalances": [],
                "postTokenBalances": [],
            },
        }

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    result = await st.solana_simulate_transaction(
        encoded,
        inner_instructions=True,
    )
    assert result["simulation_success"] is True
    assert result["units_consumed"] == 1777
    assert result["fee_lamports"] == 5000
    assert result["broadcast"] is False
    assert result["sig_verify"] is False
    assert len(result["logs"]) == 2


@pytest.mark.asyncio
async def test_transaction_forensics_builds_compact_report(monkeypatch) -> None:
    signature = str(Signature.default())
    signer = str(Pubkey.default())
    other = "7YttLkHDoYQ8Tt6vJx5Jks4wNdM8iZtZxMPrtVSSM4cR"

    async def fake_rpc(client, method, params=None):
        if method == "getSignatureStatuses":
            return {
                "context": {"slot": 300},
                "value": [
                    {
                        "slot": 250,
                        "confirmations": 2,
                        "err": None,
                        "confirmationStatus": "confirmed",
                    }
                ],
            }
        if method == "getTransaction":
            return {
                "slot": 250,
                "blockTime": 1700000000,
                "meta": {
                    "err": None,
                    "fee": 5000,
                    "computeUnitsConsumed": 1234,
                    "preBalances": [2_000_000, 1_000_000],
                    "postBalances": [1_995_000, 1_005_000],
                    "preTokenBalances": [
                        {
                            "mint": st.USDC_MINT,
                            "owner": signer,
                            "uiTokenAmount": {"amount": "2000000"},
                        },
                        {
                            "mint": st.USDC_MINT,
                            "owner": other,
                            "uiTokenAmount": {"amount": "1000000"},
                        },
                    ],
                    "postTokenBalances": [
                        {
                            "mint": st.USDC_MINT,
                            "owner": signer,
                            "uiTokenAmount": {"amount": "1500000"},
                        },
                        {
                            "mint": st.USDC_MINT,
                            "owner": other,
                            "uiTokenAmount": {"amount": "1500000"},
                        },
                    ],
                    "logMessages": [
                        "Program 11111111111111111111111111111111 invoke [1]",
                        "Program 11111111111111111111111111111111 success",
                    ],
                },
                "transaction": {
                    "signatures": [signature],
                    "message": {
                        "accountKeys": [
                            {
                                "pubkey": signer,
                                "signer": True,
                                "writable": True,
                                "source": "transaction",
                            },
                            {
                                "pubkey": other,
                                "signer": False,
                                "writable": True,
                                "source": "transaction",
                            },
                        ],
                        "instructions": [
                            {
                                "program": "system",
                                "programId": "11111111111111111111111111111111",
                                "parsed": {
                                    "type": "transfer",
                                    "info": {
                                        "source": signer,
                                        "destination": other,
                                        "lamports": 5000,
                                    },
                                },
                            }
                        ],
                    },
                },
            }
        raise AssertionError(method)

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_transaction_forensics(signature)
    assert result["found_transaction"] is True
    assert result["success"] is True
    assert result["confirmation_status"] == "confirmed"
    assert result["fee_lamports"] == 5000
    assert result["compute_units_consumed"] == 1234
    assert result["instruction_count"] == 1
    assert "system" in result["programs"]
    assert result["instructions"][0]["type"] == "transfer"
    assert len(result["usdc_owner_deltas"]) == 2
    assert result["cached"] is False


def test_v6_products_are_discoverable() -> None:
    catalog = {item["path"]: item for item in solsignal._paid_endpoint_catalog()}
    assert catalog["/tools/solana/tx-status"]["amount"] == "1000"
    assert catalog["/tools/solana/simulate"]["amount"] == "5000"
    assert catalog["/tools/solana/tx-forensics"]["amount"] == "10000"

    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    for path in (
        "/tools/solana/tx-status",
        "/tools/solana/simulate",
        "/tools/solana/tx-forensics",
    ):
        assert schema["paths"][path]["post"]["x-payment-info"]
        request_schema = (
            schema["paths"][path]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]
        )
        assert request_schema["required"]
