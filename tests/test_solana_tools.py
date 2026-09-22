from __future__ import annotations

from solders.pubkey import Pubkey
from solders.signature import Signature
import pytest

import app as solsignal
import solana_tools as st


@pytest.mark.asyncio
async def test_chain_status_aggregates_rpc(monkeypatch) -> None:
    async def fake_rpc(client, method, params=None):
        values = {
            "getSlot": 123456,
            "getBlockHeight": 120000,
            "getEpochInfo": {
                "epoch": 900,
                "absoluteSlot": 123456,
                "slotIndex": 3456,
                "slotsInEpoch": 432000,
            },
        }
        return values[method]

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_chain_status()
    assert result["slot"] == 123456
    assert result["block_height"] == 120000
    assert result["epoch"] == 900
    assert result["source"] == "solana_rpc"


def test_extract_token_accounts_sums_raw_balances() -> None:
    result = {
        "value": [
            {
                "pubkey": "acct-1",
                "account": {
                    "data": {
                        "parsed": {
                            "info": {
                                "state": "initialized",
                                "tokenAmount": {
                                    "amount": "1500000",
                                    "decimals": 6,
                                },
                            }
                        }
                    }
                },
            },
            {
                "pubkey": "acct-2",
                "account": {
                    "data": {
                        "parsed": {
                            "info": {
                                "state": "initialized",
                                "tokenAmount": {
                                    "amount": "250000",
                                    "decimals": 6,
                                },
                            }
                        }
                    }
                },
            },
        ]
    }
    total, decimals, accounts = st._extract_token_accounts(result)
    assert total == 1_750_000
    assert decimals == 6
    assert len(accounts) == 2
    assert accounts[0]["ui_amount"] == "1.5"


@pytest.mark.asyncio
async def test_wallet_summary_is_read_only(monkeypatch) -> None:
    address = str(Pubkey.default())

    async def fake_rpc(client, method, params=None):
        if method == "getBalance":
            return {"value": 2_000_000_000}
        if method == "getTokenAccountsByOwner":
            return {
                "value": [
                    {
                        "pubkey": "usdc-account",
                        "account": {
                            "data": {
                                "parsed": {
                                    "info": {
                                        "state": "initialized",
                                        "tokenAmount": {
                                            "amount": "3250000",
                                            "decimals": 6,
                                        },
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        if method == "getSignaturesForAddress":
            return [
                {
                    "signature": str(Signature.default()),
                    "slot": 100,
                    "blockTime": 1700000000,
                    "confirmationStatus": "confirmed",
                    "err": None,
                }
            ]
        raise AssertionError(method)

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_wallet_summary(address)
    assert result["sol"]["amount"] == "2"
    assert result["usdc"]["amount"] == "3.25"
    assert result["recent_signatures"][0]["success"] is True
    assert "no wallet signing" in result["note"]


@pytest.mark.asyncio
async def test_token_balance_validates_and_sums(monkeypatch) -> None:
    owner = str(Pubkey.default())
    mint = st.USDC_MINT

    async def fake_rpc(client, method, params=None):
        assert method == "getTokenAccountsByOwner"
        return {
            "value": [
                {
                    "pubkey": "one",
                    "account": {
                        "data": {
                            "parsed": {
                                "info": {
                                    "state": "initialized",
                                    "tokenAmount": {
                                        "amount": "1000000",
                                        "decimals": 6,
                                    },
                                }
                            }
                        }
                    },
                },
                {
                    "pubkey": "two",
                    "account": {
                        "data": {
                            "parsed": {
                                "info": {
                                    "state": "initialized",
                                    "tokenAmount": {
                                        "amount": "250000",
                                        "decimals": 6,
                                    },
                                }
                            }
                        }
                    },
                },
            ]
        }

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_token_balance(owner, mint)
    assert result["raw_amount"] == "1250000"
    assert result["ui_amount"] == "1.25"
    assert result["token_account_count"] == 2


@pytest.mark.asyncio
async def test_verify_usdc_settlement_uses_owner_delta(monkeypatch) -> None:
    signature = str(Signature.default())
    recipient = str(Pubkey.default())
    payer = "7YttLkHDoYQ8Tt6vJx5Jks4wNdM8iZtZxMPrtVSSM4cR"

    async def fake_rpc(client, method, params=None):
        assert method == "getTransaction"
        return {
            "slot": 999,
            "blockTime": 1700000000,
            "meta": {
                "err": None,
                "fee": 5000,
                "preTokenBalances": [
                    {
                        "mint": st.USDC_MINT,
                        "owner": payer,
                        "uiTokenAmount": {"amount": "3000000"},
                    },
                    {
                        "mint": st.USDC_MINT,
                        "owner": recipient,
                        "uiTokenAmount": {"amount": "1000000"},
                    },
                ],
                "postTokenBalances": [
                    {
                        "mint": st.USDC_MINT,
                        "owner": payer,
                        "uiTokenAmount": {"amount": "2500000"},
                    },
                    {
                        "mint": st.USDC_MINT,
                        "owner": recipient,
                        "uiTokenAmount": {"amount": "1500000"},
                    },
                ],
            },
        }

    monkeypatch.setattr(st, "_rpc", fake_rpc)
    st._CACHE.clear()
    result = await st.solana_verify_usdc_settlement(
        signature,
        to=recipient,
        min_usdc=0.5,
    )
    assert result["verified"] is True
    assert result["recipient_credit_usdc"] == "0.5"
    assert result["transaction_success"] is True
    assert result["fee_lamports"] == 5000


def test_v4_solana_products_are_discoverable() -> None:
    catalog = {item["path"]: item for item in solsignal._paid_endpoint_catalog()}
    assert catalog["/tools/solana/chain"]["amount"] == "1000"
    assert catalog["/tools/solana/wallet"]["amount"] == "3000"
    assert catalog["/tools/solana/token-balance"]["amount"] == "2000"
    assert catalog["/tools/solana/tx-verify"]["amount"] == "5000"

    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    for path in (
        "/tools/solana/chain",
        "/tools/solana/wallet",
        "/tools/solana/token-balance",
        "/tools/solana/tx-verify",
    ):
        method = "get" if path.endswith("/chain") else "post"
        assert schema["paths"][path][method]["x-payment-info"]
