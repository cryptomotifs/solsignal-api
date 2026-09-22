from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
from solders.pubkey import Pubkey
from solders.signature import Signature

from agent_tools import ToolError


SOLANA_RPC_URL = os.environ.get(
    "SOLANA_RPC_URL",
    "https://api.mainnet-beta.solana.com",
).strip()
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

_CACHE: dict[str, tuple[float, Any]] = {}


def _cache_get(key: str, ttl: float) -> Any | None:
    item = _CACHE.get(key)
    if item is None:
        return None
    ts, value = item
    if time.time() - ts > ttl:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: Any) -> None:
    _CACHE[key] = (time.time(), value)
    if len(_CACHE) > 256:
        oldest = sorted(_CACHE.items(), key=lambda kv: kv[1][0])[:64]
        for key, _ in oldest:
            _CACHE.pop(key, None)


def _validate_pubkey(value: str, *, field: str = "address") -> str:
    try:
        return str(Pubkey.from_string(value.strip()))
    except Exception as exc:
        raise ToolError(400, f"{field} must be a valid Solana public key") from exc


def _validate_signature(value: str) -> str:
    try:
        return str(Signature.from_string(value.strip()))
    except Exception as exc:
        raise ToolError(400, "signature must be a valid Solana transaction signature") from exc


async def _rpc(
    client: httpx.AsyncClient,
    method: str,
    params: list[Any] | None = None,
) -> Any:
    try:
        response = await client.post(
            SOLANA_RPC_URL,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params or [],
            },
            headers={"User-Agent": "CIPHER-Solana-Tools/1.0"},
        )
    except httpx.HTTPError as exc:
        raise ToolError(
            502,
            f"Solana RPC request failed: {type(exc).__name__}",
        ) from exc

    if response.status_code == 429:
        raise ToolError(503, "Solana RPC is rate limited; retry shortly")
    if response.status_code >= 400:
        raise ToolError(502, f"Solana RPC returned HTTP {response.status_code}")

    try:
        payload = response.json()
    except Exception as exc:
        raise ToolError(502, "Solana RPC returned invalid JSON") from exc

    if not isinstance(payload, dict):
        raise ToolError(502, "Solana RPC returned an invalid response")
    if payload.get("error"):
        error = payload["error"]
        message = (
            error.get("message")
            if isinstance(error, dict)
            else str(error)
        )
        raise ToolError(502, f"Solana RPC error: {message}")
    return payload.get("result")


async def solana_chain_status() -> dict[str, Any]:
    cached = _cache_get("solana:chain-status", 2.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=10.0) as client:
        slot, block_height, epoch = await asyncio.gather(
            _rpc(client, "getSlot", [{"commitment": "confirmed"}]),
            _rpc(client, "getBlockHeight", [{"commitment": "confirmed"}]),
            _rpc(client, "getEpochInfo", [{"commitment": "confirmed"}]),
        )

    result = {
        "network": "solana-mainnet",
        "slot": int(slot),
        "block_height": int(block_height),
        "epoch": int((epoch or {}).get("epoch", 0)),
        "absolute_slot": int((epoch or {}).get("absoluteSlot", slot)),
        "slot_index": int((epoch or {}).get("slotIndex", 0)),
        "slots_in_epoch": int((epoch or {}).get("slotsInEpoch", 0)),
        "source": "solana_rpc",
        "cached": False,
    }
    _cache_set("solana:chain-status", result)
    return result


def _extract_token_accounts(result: Any) -> tuple[int, int, list[dict[str, Any]]]:
    total_raw = 0
    decimals = 6
    accounts: list[dict[str, Any]] = []

    values = (result or {}).get("value", []) if isinstance(result, dict) else []
    for entry in values:
        if not isinstance(entry, dict):
            continue
        account = entry.get("account") or {}
        data = account.get("data") or {}
        parsed = data.get("parsed") or {}
        info = parsed.get("info") or {}
        token_amount = info.get("tokenAmount") or {}
        try:
            raw = int(token_amount.get("amount") or 0)
            decimals = int(token_amount.get("decimals") or decimals)
        except (TypeError, ValueError):
            continue
        total_raw += raw
        accounts.append(
            {
                "token_account": entry.get("pubkey"),
                "raw_amount": str(raw),
                "decimals": decimals,
                "ui_amount": str(
                    Decimal(raw) / (Decimal(10) ** decimals)
                ),
                "state": info.get("state"),
            }
        )
    return total_raw, decimals, accounts


async def solana_token_balance(
    owner: str,
    mint: str,
) -> dict[str, Any]:
    owner = _validate_pubkey(owner, field="owner")
    mint = _validate_pubkey(mint, field="mint")
    cache_key = f"solana:token:{owner}:{mint}"
    cached = _cache_get(cache_key, 4.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=12.0) as client:
        result = await _rpc(
            client,
            "getTokenAccountsByOwner",
            [
                owner,
                {"mint": mint},
                {
                    "encoding": "jsonParsed",
                    "commitment": "confirmed",
                },
            ],
        )

    total_raw, decimals, accounts = _extract_token_accounts(result)
    output = {
        "owner": owner,
        "mint": mint,
        "raw_amount": str(total_raw),
        "decimals": decimals,
        "ui_amount": str(Decimal(total_raw) / (Decimal(10) ** decimals)),
        "token_accounts": accounts,
        "token_account_count": len(accounts),
        "source": "solana_rpc",
        "cached": False,
    }
    _cache_set(cache_key, output)
    return output


async def solana_wallet_summary(
    address: str,
    *,
    recent_limit: int = 5,
) -> dict[str, Any]:
    address = _validate_pubkey(address)
    recent_limit = min(max(int(recent_limit), 0), 20)
    cache_key = f"solana:wallet:{address}:{recent_limit}"
    cached = _cache_get(cache_key, 4.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=12.0) as client:
        jobs = [
            _rpc(
                client,
                "getBalance",
                [address, {"commitment": "confirmed"}],
            ),
            _rpc(
                client,
                "getTokenAccountsByOwner",
                [
                    address,
                    {"mint": USDC_MINT},
                    {
                        "encoding": "jsonParsed",
                        "commitment": "confirmed",
                    },
                ],
            ),
        ]
        if recent_limit:
            jobs.append(
                _rpc(
                    client,
                    "getSignaturesForAddress",
                    [
                        address,
                        {
                            "limit": recent_limit,
                            "commitment": "confirmed",
                        },
                    ],
                )
            )
        values = await asyncio.gather(*jobs)

    balance_result = values[0] or {}
    lamports = int(
        balance_result.get("value", 0)
        if isinstance(balance_result, dict)
        else 0
    )
    usdc_raw, usdc_decimals, usdc_accounts = _extract_token_accounts(values[1])

    recent = []
    if recent_limit and len(values) > 2 and isinstance(values[2], list):
        for item in values[2]:
            if not isinstance(item, dict):
                continue
            recent.append(
                {
                    "signature": item.get("signature"),
                    "slot": item.get("slot"),
                    "block_time": item.get("blockTime"),
                    "confirmation_status": item.get("confirmationStatus"),
                    "success": item.get("err") is None,
                }
            )

    result = {
        "address": address,
        "sol": {
            "lamports": lamports,
            "amount": str(Decimal(lamports) / Decimal(1_000_000_000)),
        },
        "usdc": {
            "mint": USDC_MINT,
            "raw_amount": str(usdc_raw),
            "decimals": usdc_decimals,
            "amount": str(
                Decimal(usdc_raw) / (Decimal(10) ** usdc_decimals)
            ),
            "token_account_count": len(usdc_accounts),
        },
        "recent_signatures": recent,
        "source": "solana_rpc",
        "cached": False,
        "note": "Read-only public-chain data; no wallet signing or private keys are used.",
    }
    _cache_set(cache_key, result)
    return result


def _usdc_owner_balances(entries: Any) -> dict[str, int]:
    totals: dict[str, int] = {}
    if not isinstance(entries, list):
        return totals
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("mint") != USDC_MINT:
            continue
        owner = entry.get("owner")
        amount = (entry.get("uiTokenAmount") or {}).get("amount")
        if not owner or amount is None:
            continue
        try:
            totals[str(owner)] = totals.get(str(owner), 0) + int(amount)
        except (TypeError, ValueError):
            continue
    return totals


async def solana_verify_usdc_settlement(
    signature: str,
    *,
    to: str | None = None,
    min_usdc: float | str | None = None,
) -> dict[str, Any]:
    signature = _validate_signature(signature)
    recipient = _validate_pubkey(to, field="to") if to else None

    minimum_raw = 0
    minimum_text = None
    if min_usdc is not None:
        try:
            minimum = Decimal(str(min_usdc))
        except InvalidOperation as exc:
            raise ToolError(400, "min_usdc must be numeric") from exc
        if minimum < 0:
            raise ToolError(400, "min_usdc cannot be negative")
        minimum_raw = int(minimum * Decimal(1_000_000))
        minimum_text = str(minimum)

    cache_key = f"solana:tx:{signature}"
    transaction = _cache_get(cache_key, 30.0)
    cached = transaction is not None

    if transaction is None:
        async with httpx.AsyncClient(timeout=15.0) as client:
            transaction = await _rpc(
                client,
                "getTransaction",
                [
                    signature,
                    {
                        "encoding": "jsonParsed",
                        "commitment": "confirmed",
                        "maxSupportedTransactionVersion": 0,
                    },
                ],
            )
        if transaction is None:
            raise ToolError(404, "Confirmed transaction was not found")
        _cache_set(cache_key, transaction)

    if not isinstance(transaction, dict):
        raise ToolError(502, "Solana RPC returned an invalid transaction")

    meta = transaction.get("meta") or {}
    pre = _usdc_owner_balances(meta.get("preTokenBalances"))
    post = _usdc_owner_balances(meta.get("postTokenBalances"))
    owners = sorted(set(pre) | set(post))

    deltas = []
    credits: dict[str, int] = {}
    debits: dict[str, int] = {}
    for owner in owners:
        delta = post.get(owner, 0) - pre.get(owner, 0)
        if delta > 0:
            credits[owner] = delta
        elif delta < 0:
            debits[owner] = -delta
        if delta:
            deltas.append(
                {
                    "owner": owner,
                    "raw_delta": str(delta),
                    "usdc_delta": str(Decimal(delta) / Decimal(1_000_000)),
                }
            )

    success = meta.get("err") is None
    recipient_credit_raw = credits.get(recipient, 0) if recipient else None
    if recipient:
        verified = success and recipient_credit_raw >= minimum_raw
    else:
        verified = success and bool(credits)

    return {
        "signature": signature,
        "network": "solana-mainnet",
        "confirmed": True,
        "transaction_success": success,
        "verified": verified,
        "recipient": recipient,
        "minimum_usdc": minimum_text,
        "recipient_credit_usdc": (
            str(Decimal(recipient_credit_raw) / Decimal(1_000_000))
            if recipient_credit_raw is not None
            else None
        ),
        "usdc_credits": [
            {
                "owner": owner,
                "raw_amount": str(raw),
                "amount": str(Decimal(raw) / Decimal(1_000_000)),
            }
            for owner, raw in sorted(credits.items())
        ],
        "usdc_debits": [
            {
                "owner": owner,
                "raw_amount": str(raw),
                "amount": str(Decimal(raw) / Decimal(1_000_000)),
            }
            for owner, raw in sorted(debits.items())
        ],
        "usdc_owner_deltas": deltas,
        "slot": transaction.get("slot"),
        "block_time": transaction.get("blockTime"),
        "fee_lamports": meta.get("fee"),
        "cached": cached,
        "source": "solana_rpc",
        "scope_note": (
            "Verifies confirmed transaction state and USDC owner balance deltas. "
            "It does not infer off-chain intent or prove delivery of a purchased service."
        ),
    }



def _percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = int(round((len(ordered) - 1) * min(max(fraction, 0.0), 1.0)))
    return int(ordered[index])


async def solana_latest_blockhash() -> dict[str, Any]:
    """Fresh blockhash material for building a Solana transaction."""
    cached = _cache_get("solana:blockhash", 2.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=10.0) as client:
        result = await _rpc(
            client,
            "getLatestBlockhash",
            [{"commitment": "confirmed"}],
        )

    if not isinstance(result, dict):
        raise ToolError(502, "Solana RPC returned invalid blockhash data")
    context = result.get("context") or {}
    value = result.get("value") or {}
    blockhash = value.get("blockhash")
    last_valid = value.get("lastValidBlockHeight")
    if not blockhash or last_valid is None:
        raise ToolError(502, "Solana RPC response is missing blockhash fields")

    output = {
        "network": "solana-mainnet",
        "blockhash": blockhash,
        "last_valid_block_height": int(last_valid),
        "context_slot": context.get("slot"),
        "commitment": "confirmed",
        "source": "solana_rpc",
        "cached": False,
    }
    _cache_set("solana:blockhash", output)
    return output


async def solana_priority_fees(
    *,
    accounts: list[str] | None = None,
    sample_limit: int = 50,
) -> dict[str, Any]:
    """Recent priority-fee samples, optionally scoped to writable accounts."""
    addresses = accounts or []
    if not isinstance(addresses, list):
        raise ToolError(400, "accounts must be an array of Solana public keys")
    if len(addresses) > 128:
        raise ToolError(400, "accounts cannot contain more than 128 addresses")
    validated = [
        _validate_pubkey(str(address), field="accounts[]")
        for address in addresses
    ]
    try:
        sample_limit = min(max(int(sample_limit), 1), 150)
    except (TypeError, ValueError) as exc:
        raise ToolError(400, "sample_limit must be an integer") from exc

    cache_key = "solana:priority:" + hashlib.sha256(
        ("|".join(validated) + f":{sample_limit}").encode("utf-8")
    ).hexdigest()
    cached = _cache_get(cache_key, 3.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=10.0) as client:
        result = await _rpc(
            client,
            "getRecentPrioritizationFees",
            [validated],
        )

    if not isinstance(result, list):
        raise ToolError(502, "Solana RPC returned invalid priority-fee data")

    rows: list[dict[str, int]] = []
    for item in result:
        if not isinstance(item, dict):
            continue
        try:
            slot = int(item.get("slot"))
            fee = int(item.get("prioritizationFee"))
        except (TypeError, ValueError):
            continue
        rows.append(
            {
                "slot": slot,
                "micro_lamports_per_cu": max(fee, 0),
            }
        )

    rows.sort(key=lambda item: item["slot"], reverse=True)
    rows = rows[:sample_limit]
    positive = sorted(
        item["micro_lamports_per_cu"]
        for item in rows
        if item["micro_lamports_per_cu"] > 0
    )
    all_values = sorted(item["micro_lamports_per_cu"] for item in rows)

    output = {
        "network": "solana-mainnet",
        "writable_accounts": validated,
        "sample_count": len(rows),
        "nonzero_sample_count": len(positive),
        "unit": "micro-lamports per compute unit",
        "summary": {
            "minimum": min(all_values) if all_values else 0,
            "median_nonzero": _percentile(positive, 0.50),
            "p75_nonzero": _percentile(positive, 0.75),
            "p90_nonzero": _percentile(positive, 0.90),
            "maximum": max(all_values) if all_values else 0,
        },
        "samples": rows,
        "source": "solana_rpc:getRecentPrioritizationFees",
        "cached": False,
        "note": (
            "These are recent observed per-CU prices, not a guarantee that a transaction "
            "will land. Account-scoped queries are more relevant for contended writable accounts."
        ),
    }
    _cache_set(cache_key, output)
    return output


async def solana_rent_exemption(data_len: int) -> dict[str, Any]:
    """Minimum lamports required for an account of data_len bytes to be rent exempt."""
    try:
        data_len = int(data_len)
    except (TypeError, ValueError) as exc:
        raise ToolError(400, "data_len must be an integer") from exc
    if data_len < 0 or data_len > 10_485_760:
        raise ToolError(400, "data_len must be between 0 and 10,485,760 bytes")

    cache_key = f"solana:rent:{data_len}"
    cached = _cache_get(cache_key, 60.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=10.0) as client:
        result = await _rpc(
            client,
            "getMinimumBalanceForRentExemption",
            [data_len, {"commitment": "confirmed"}],
        )
    try:
        lamports = int(result)
    except (TypeError, ValueError) as exc:
        raise ToolError(502, "Solana RPC returned invalid rent data") from exc

    output = {
        "network": "solana-mainnet",
        "data_len": data_len,
        "lamports": lamports,
        "sol": str(Decimal(lamports) / Decimal(1_000_000_000)),
        "commitment": "confirmed",
        "source": "solana_rpc:getMinimumBalanceForRentExemption",
        "cached": False,
    }
    _cache_set(cache_key, output)
    return output


async def solana_account_info(address: str) -> dict[str, Any]:
    """Compact metadata for a public Solana account without returning large raw data."""
    address = _validate_pubkey(address)
    cache_key = f"solana:account:{address}"
    cached = _cache_get(cache_key, 4.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=10.0) as client:
        result = await _rpc(
            client,
            "getAccountInfo",
            [
                address,
                {
                    "encoding": "jsonParsed",
                    "commitment": "confirmed",
                },
            ],
        )

    context = (result or {}).get("context", {}) if isinstance(result, dict) else {}
    value = (result or {}).get("value") if isinstance(result, dict) else None
    if value is None:
        output = {
            "address": address,
            "exists": False,
            "context_slot": context.get("slot"),
            "source": "solana_rpc:getAccountInfo",
            "cached": False,
        }
        _cache_set(cache_key, output)
        return output
    if not isinstance(value, dict):
        raise ToolError(502, "Solana RPC returned invalid account data")

    parsed_program = None
    parsed_type = None
    data = value.get("data")
    if isinstance(data, dict):
        parsed_program = data.get("program")
        parsed = data.get("parsed")
        if isinstance(parsed, dict):
            parsed_type = parsed.get("type")

    lamports = int(value.get("lamports") or 0)
    output = {
        "address": address,
        "exists": True,
        "lamports": lamports,
        "sol": str(Decimal(lamports) / Decimal(1_000_000_000)),
        "owner_program": value.get("owner"),
        "executable": bool(value.get("executable")),
        "space_bytes": value.get("space"),
        "rent_epoch": value.get("rentEpoch"),
        "parsed_program": parsed_program,
        "parsed_type": parsed_type,
        "context_slot": context.get("slot"),
        "source": "solana_rpc:getAccountInfo",
        "cached": False,
        "note": "Compact metadata only; large raw account data is intentionally omitted.",
    }
    _cache_set(cache_key, output)
    return output


async def solana_message_fee(message_base64: str) -> dict[str, Any]:
    """Network fee for a base64-encoded serialized Solana message."""
    if not isinstance(message_base64, str) or not message_base64.strip():
        raise ToolError(400, "message_base64 must be a non-empty string")
    value = message_base64.strip()
    if len(value) > 20_000:
        raise ToolError(413, "Serialized message is too large")
    try:
        base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ToolError(400, "message_base64 is not valid Base64") from exc

    cache_key = "solana:message-fee:" + hashlib.sha256(
        value.encode("ascii")
    ).hexdigest()
    cached = _cache_get(cache_key, 3.0)
    if cached is not None:
        return {**cached, "cached": True}

    async with httpx.AsyncClient(timeout=10.0) as client:
        result = await _rpc(
            client,
            "getFeeForMessage",
            [
                value,
                {"commitment": "confirmed"},
            ],
        )

    if not isinstance(result, dict):
        raise ToolError(502, "Solana RPC returned invalid message-fee data")
    context = result.get("context") or {}
    fee = result.get("value")
    if fee is None:
        raise ToolError(
            422,
            "RPC could not calculate a fee; the message may reference an expired blockhash",
        )
    try:
        lamports = int(fee)
    except (TypeError, ValueError) as exc:
        raise ToolError(502, "Solana RPC returned invalid fee data") from exc

    output = {
        "network": "solana-mainnet",
        "fee_lamports": lamports,
        "fee_sol": str(Decimal(lamports) / Decimal(1_000_000_000)),
        "context_slot": context.get("slot"),
        "commitment": "confirmed",
        "source": "solana_rpc:getFeeForMessage",
        "cached": False,
        "note": "Read-only fee calculation; no transaction is signed or submitted.",
    }
    _cache_set(cache_key, output)
    return output
