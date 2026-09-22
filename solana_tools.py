from __future__ import annotations

import asyncio
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
