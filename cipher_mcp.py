from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

from starlette.responses import JSONResponse


class LazyMCPBridge:
    """ASGI placeholder that becomes the paid MCP app after x402 startup succeeds."""

    def __init__(self) -> None:
        self._app: Any | None = None

    @property
    def ready(self) -> bool:
        return self._app is not None

    def set_app(self, app: Any) -> None:
        self._app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if self._app is None:
            response = JSONResponse(
                status_code=503,
                content={
                    "error": "CIPHER MCP is temporarily unavailable",
                    "reason": "x402 payment service is not ready",
                },
            )
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


def _mcp_extensions(
    *,
    tool_name: str,
    description: str,
    input_schema: dict[str, Any],
    example: dict[str, Any],
    output_example: dict[str, Any],
) -> dict[str, Any]:
    from x402.extensions.bazaar import (
        DeclareMcpDiscoveryConfig,
        OutputConfig,
        declare_mcp_discovery_extension,
    )

    return declare_mcp_discovery_extension(
        DeclareMcpDiscoveryConfig(
            tool_name=tool_name,
            description=description,
            transport="streamable-http",
            input_schema=input_schema,
            example=example,
            output=OutputConfig(
                example=output_example,
                schema={"type": "object"},
            ),
        )
    )


def _transport_security(public_base_url: str) -> Any | None:
    """Build production Host/Origin protection when the installed MCP SDK supports it."""
    try:
        from mcp.server.transport_security import TransportSecuritySettings
    except Exception:
        return None

    parsed = urlparse(public_base_url)
    host = parsed.netloc.split("@")[-1]
    if not host:
        return None
    hostname = host.split(":")[0]
    origin = f"{parsed.scheme}://{host}"
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            host,
            hostname,
            f"{hostname}:*",
            "localhost",
            "localhost:*",
            "127.0.0.1",
            "127.0.0.1:*",
        ],
        allowed_origins=[
            origin,
            "http://localhost:*",
            "http://127.0.0.1:*",
        ],
    )


def _build_streamable_http_app(mcp: Any, public_base_url: str) -> Any:
    """Build a deployment-safe MCP ASGI app across compatible MCP SDK versions."""
    method = mcp.streamable_http_app
    sig = inspect.signature(method)
    kwargs: dict[str, Any] = {}

    if "json_response" in sig.parameters:
        kwargs["json_response"] = True
    if "streamable_http_path" in sig.parameters:
        kwargs["streamable_http_path"] = "/"

    security = _transport_security(public_base_url)
    if security is not None and "transport_security" in sig.parameters:
        kwargs["transport_security"] = security
    elif "host" in sig.parameters:
        parsed = urlparse(public_base_url)
        kwargs["host"] = parsed.hostname or "0.0.0.0"

    settings = getattr(mcp, "settings", None)
    if settings is not None and hasattr(settings, "streamable_http_path"):
        try:
            settings.streamable_http_path = "/"
        except Exception:
            pass

    return method(**kwargs)


def build_cipher_mcp(
    *,
    resource_server: Any,
    requirements_for_price: Callable[[str], Any],
    public_base_url: str,
    settlement_recorder: Callable[..., Any],
) -> tuple[Any, Any]:
    """Build CIPHER's paid MCP server after the shared x402 resource server is initialized."""
    from mcp.server.fastmcp import FastMCP
    from x402.mcp import PaymentWrapperHooks, create_payment_wrapper
    from x402.schemas import ResourceInfo

    fastmcp_kwargs: dict[str, Any] = {}
    fastmcp_sig = inspect.signature(FastMCP)
    if "instructions" in fastmcp_sig.parameters:
        fastmcp_kwargs["instructions"] = (
            "CIPHER provides machine-payable Solana, MCP, x402, and deterministic "
            "developer infrastructure. Each paid tool returns an x402 payment request "
            "until the caller supplies valid payment metadata."
        )
    if "stateless_http" in fastmcp_sig.parameters:
        fastmcp_kwargs["stateless_http"] = True

    mcp = FastMCP("CIPHER Agent Tools", **fastmcp_kwargs)
    resource_url = f"{public_base_url.rstrip('/')}/mcp"

    def wrapper(
        *,
        tool_name: str,
        description: str,
        price_key: str,
        input_schema: dict[str, Any],
        example: dict[str, Any],
        output_example: dict[str, Any],
    ) -> Callable:
        requirements = [requirements_for_price(price_key)]

        async def after_settlement(context: Any) -> None:
            settlement = context.settlement
            result = settlement_recorder(
                tool_name=tool_name,
                transaction=getattr(settlement, "transaction", ""),
                amount_atomic=int(context.payment_requirements.amount),
                payer=getattr(settlement, "payer", None),
                network=getattr(settlement, "network", context.payment_requirements.network),
            )
            if inspect.isawaitable(result):
                await result

        hooks = PaymentWrapperHooks(on_after_settlement=after_settlement)
        return create_payment_wrapper(
            resource_server,
            accepts=requirements,
            resource=ResourceInfo(
                url=resource_url,
                description=description,
                mime_type="application/json",
                service_name="CIPHER Agent Tools",
                tags=["ai-agents", "x402", "mcp", "solana"],
            ),
            hooks=hooks,
            extensions=_mcp_extensions(
                tool_name=tool_name,
                description=description,
                input_schema=input_schema,
                example=example,
                output_example=output_example,
            ),
        )

    tx_status_description = (
        "Check a Solana transaction signature for processed, confirmed, or finalized "
        "status and whether execution succeeded."
    )
    tx_status_wrapper = wrapper(
        tool_name="solana_tx_status",
        description=tx_status_description,
        price_key="tool_solana_tx_status",
        input_schema={
            "type": "object",
            "properties": {
                "signature": {"type": "string"},
                "search_history": {"type": "boolean", "default": True},
            },
            "required": ["signature"],
        },
        example={"signature": "5" + "1" * 87, "search_history": True},
        output_example={
            "found": True,
            "success": True,
            "confirmation_status": "finalized",
            "finalized": True,
        },
    )

    @mcp.tool(name="solana_tx_status", description=tx_status_description)
    @tx_status_wrapper
    async def solana_tx_status(signature: str, search_history: bool = True) -> dict[str, Any]:
        from solana_tools import solana_transaction_status

        return await solana_transaction_status(
            signature,
            search_history=search_history,
        )

    simulate_description = (
        "Simulate a serialized Solana transaction without signing or broadcasting it; "
        "return errors, logs, compute units, fee, and balance effects."
    )
    simulate_wrapper = wrapper(
        tool_name="solana_simulate",
        description=simulate_description,
        price_key="tool_solana_simulate",
        input_schema={
            "type": "object",
            "properties": {
                "transaction_base64": {"type": "string"},
                "replace_recent_blockhash": {"type": "boolean", "default": True},
                "inner_instructions": {"type": "boolean", "default": False},
            },
            "required": ["transaction_base64"],
        },
        example={
            "transaction_base64": "AQ==",
            "replace_recent_blockhash": True,
            "inner_instructions": False,
        },
        output_example={
            "simulation_success": True,
            "units_consumed": 125000,
            "fee_lamports": 5000,
            "broadcast": False,
        },
    )

    @mcp.tool(name="solana_simulate", description=simulate_description)
    @simulate_wrapper
    async def solana_simulate(
        transaction_base64: str,
        replace_recent_blockhash: bool = True,
        inner_instructions: bool = False,
    ) -> dict[str, Any]:
        from solana_tools import solana_simulate_transaction

        return await solana_simulate_transaction(
            transaction_base64,
            replace_recent_blockhash=replace_recent_blockhash,
            inner_instructions=inner_instructions,
        )

    forensics_description = (
        "Inspect a Solana transaction with deterministic on-chain forensics: status, "
        "programs, parsed instructions, fees, compute usage, logs, lamport deltas, and USDC deltas."
    )
    forensics_wrapper = wrapper(
        tool_name="solana_tx_forensics",
        description=forensics_description,
        price_key="tool_solana_forensics",
        input_schema={
            "type": "object",
            "properties": {"signature": {"type": "string"}},
            "required": ["signature"],
        },
        example={"signature": "5" + "1" * 87},
        output_example={
            "success": True,
            "confirmation_status": "confirmed",
            "fee_lamports": 5000,
            "programs": ["system"],
            "instruction_count": 2,
        },
    )

    @mcp.tool(name="solana_tx_forensics", description=forensics_description)
    @forensics_wrapper
    async def solana_tx_forensics(signature: str) -> dict[str, Any]:
        from solana_tools import solana_transaction_forensics

        return await solana_transaction_forensics(signature)

    wallet_description = (
        "Read a Solana wallet's public SOL and USDC balances plus recent transaction signatures."
    )
    wallet_wrapper = wrapper(
        tool_name="solana_wallet",
        description=wallet_description,
        price_key="tool_solana_wallet",
        input_schema={
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "recent_limit": {"type": "integer", "minimum": 0, "maximum": 20},
            },
            "required": ["address"],
        },
        example={"address": "11111111111111111111111111111111", "recent_limit": 5},
        output_example={
            "address": "…",
            "sol": {"amount": "1.2"},
            "usdc": {"amount": "10.5"},
            "recent_signatures": [],
        },
    )

    @mcp.tool(name="solana_wallet", description=wallet_description)
    @wallet_wrapper
    async def solana_wallet(address: str, recent_limit: int = 5) -> dict[str, Any]:
        from solana_tools import solana_wallet_summary

        return await solana_wallet_summary(address, recent_limit=recent_limit)

    mcp_audit_description = (
        "Audit a public MCP endpoint with live initialize/tools-list negotiation, "
        "tool fingerprinting, change detection, and heuristic risk signals."
    )
    mcp_audit_wrapper = wrapper(
        tool_name="mcp_audit",
        description=mcp_audit_description,
        price_key="tool_mcp_audit",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "previous_fingerprint": {"type": "string"},
                "timeout_seconds": {"type": "number", "minimum": 3, "maximum": 30},
            },
            "required": ["url"],
        },
        example={"url": "https://example.com/mcp"},
        output_example={"status": "HEALTHY", "speaks_mcp": True, "tools_count": 8},
    )

    @mcp.tool(name="mcp_audit", description=mcp_audit_description)
    @mcp_audit_wrapper
    async def mcp_audit(
        url: str,
        previous_fingerprint: str | None = None,
        timeout_seconds: float = 12.0,
    ) -> dict[str, Any]:
        from agent_infra_tools import audit_mcp_server

        return await audit_mcp_server(
            url,
            previous_fingerprint=previous_fingerprint,
            timeout_seconds=timeout_seconds,
        )

    x402_audit_description = (
        "Audit a public x402 endpoint without paying: probe its 402 challenge, "
        "well-known manifest, OpenAPI payment metadata, and runtime/discovery consistency."
    )
    x402_audit_wrapper = wrapper(
        tool_name="x402_audit",
        description=x402_audit_description,
        price_key="tool_x402_audit",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "method": {"type": "string", "default": "auto"},
                "body": {"type": "object"},
                "timeout_seconds": {"type": "number", "minimum": 3, "maximum": 30},
            },
            "required": ["url"],
        },
        example={"url": "https://example.com/paid-tool", "method": "auto"},
        output_example={
            "status": "PASS",
            "paid_method": "POST",
            "well_known_manifest_found": True,
            "findings": [],
        },
    )

    @mcp.tool(name="x402_audit", description=x402_audit_description)
    @x402_audit_wrapper
    async def x402_audit(
        url: str,
        method: str = "auto",
        body: dict[str, Any] | None = None,
        timeout_seconds: float = 12.0,
    ) -> dict[str, Any]:
        from agent_infra_tools import audit_x402_endpoint

        return await audit_x402_endpoint(
            url,
            method=method,
            body=body,
            timeout_seconds=timeout_seconds,
        )

    prepay_description = (
        "Verify an x402 seller immediately before payment by re-fetching terms twice "
        "and enforcing caller budget, network, asset, recipient, origin, and timeout policy."
    )
    prepay_wrapper = wrapper(
        tool_name="x402_prepay_verify",
        description=prepay_description,
        price_key="tool_x402_prepay",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "policy": {"type": "object"},
                "method": {"type": "string", "default": "auto"},
                "body": {"type": "object"},
                "timeout_seconds": {"type": "number", "minimum": 3, "maximum": 30},
            },
            "required": ["url", "policy"],
        },
        example={
            "url": "https://example.com/paid-tool",
            "policy": {"max_amount_usdc": 0.05},
        },
        output_example={
            "approved": True,
            "decision": "APPROVE",
            "challenge_consistent": True,
        },
    )

    @mcp.tool(name="x402_prepay_verify", description=prepay_description)
    @prepay_wrapper
    async def x402_prepay_verify_tool(
        url: str,
        policy: dict[str, Any],
        method: str = "auto",
        body: dict[str, Any] | None = None,
        timeout_seconds: float = 12.0,
    ) -> dict[str, Any]:
        from agent_infra_tools import x402_prepay_verify

        return await x402_prepay_verify(
            url,
            policy=policy,
            method=method,
            body=body,
            timeout_seconds=timeout_seconds,
        )

    json_description = (
        "Repair common malformed JSON from LLMs or tools without another model call."
    )
    json_wrapper = wrapper(
        tool_name="json_repair",
        description=json_description,
        price_key="tool_json",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        example={"text": "{'status':'ok',}"},
        output_example={"valid": True, "json": {"status": "ok"}},
    )

    @mcp.tool(name="json_repair", description=json_description)
    @json_wrapper
    async def json_repair(text: str) -> dict[str, Any]:
        from agent_tools import repair_json

        return repair_json(text)

    @mcp.tool(
        name="cipher_catalog",
        description="Free list of CIPHER's paid MCP tools and their purpose.",
    )
    def cipher_catalog() -> dict[str, Any]:
        return {
            "service": "CIPHER Agent Tools",
            "payment": "x402 v2 / USDC on Solana",
            "tools": [
                {"name": "solana_tx_status", "price_usdc": 0.001},
                {"name": "solana_simulate", "price_usdc": 0.005},
                {"name": "solana_tx_forensics", "price_usdc": 0.01},
                {"name": "solana_wallet", "price_usdc": 0.003},
                {"name": "mcp_audit", "price_usdc": 0.01},
                {"name": "x402_audit", "price_usdc": 0.01},
                {"name": "x402_prepay_verify", "price_usdc": 0.005},
                {"name": "json_repair", "price_usdc": 0.001},
            ],
        }

    return mcp, _build_streamable_http_app(mcp, public_base_url)
