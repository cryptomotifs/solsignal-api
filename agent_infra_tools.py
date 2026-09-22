from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx

from agent_tools import ToolError, _validate_public_url


_MAX_AUDIT_RESPONSE_BYTES = 2_000_000
_MCP_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2024-11-05")
_SOLANA_USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def _decode_base64_json(value: str) -> dict[str, Any] | None:
    raw = value.strip()
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = raw + "=" * (-len(raw) % 4)
            decoded = decoder(padded.encode("ascii"))
            parsed = json.loads(decoded.decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None


def _parse_jsonrpc_response(
    body: bytes,
    content_type: str,
    *,
    expected_id: int | str | None = None,
) -> dict[str, Any] | None:
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return None

    candidates: list[Any] = []
    if "text/event-stream" in content_type.lower():
        data_lines: list[str] = []
        for line in text.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].strip())
        for item in data_lines:
            try:
                candidates.append(json.loads(item))
            except Exception:
                continue
    else:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                candidates.extend(parsed)
            else:
                candidates.append(parsed)
        except Exception:
            return None

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if expected_id is None or candidate.get("id") == expected_id:
            return candidate
    return None


def _tool_fingerprint(tools: list[dict[str, Any]]) -> str:
    normalized = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        normalized.append(
            {
                "name": tool.get("name"),
                "description": tool.get("description"),
                "inputSchema": tool.get("inputSchema"),
                "outputSchema": tool.get("outputSchema"),
            }
        )
    normalized.sort(key=lambda item: str(item.get("name") or ""))
    payload = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _mcp_tool_risk_signals(tools: list[dict[str, Any]]) -> dict[str, Any]:
    poisoning_patterns = (
        r"ignore (?:all |any )?(?:previous|prior) instructions",
        r"system prompt",
        r"reveal .*?(?:secret|password|token|private key|seed phrase)",
        r"send .*?(?:secret|password|token|private key|seed phrase)",
        r"exfiltrat",
    )
    powerful_name_terms = (
        "delete",
        "exec",
        "shell",
        "command",
        "transfer",
        "send",
        "pay",
        "sign",
        "admin",
        "write_file",
        "remove",
    )

    poisoning: list[dict[str, str]] = []
    powerful: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "")
        description = str(tool.get("description") or "")
        joined = f"{name}\n{description}".lower()

        for pattern in poisoning_patterns:
            if re.search(pattern, joined, re.I):
                poisoning.append(
                    {
                        "tool": name,
                        "indicator": pattern,
                    }
                )
                break

        lowered = name.lower()
        if any(term in lowered for term in powerful_name_terms):
            powerful.append(name)

    return {
        "tool_poisoning_indicators": poisoning[:50],
        "powerful_tool_names": sorted(set(powerful))[:100],
        "note": (
            "Indicators are heuristic review signals, not proof that a tool is malicious."
        ),
    }


async def _bounded_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: Any | None = None,
    timeout_seconds: float = 15.0,
    max_redirects: int = 2,
) -> tuple[httpx.Response, bytes, str]:
    current = url
    request_method = method.upper()

    for _ in range(max_redirects + 1):
        _validate_public_url(current)
        try:
            async with client.stream(
                request_method,
                current,
                headers=headers,
                json=json_body,
                timeout=timeout_seconds,
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise ToolError(502, "Redirect missing Location header")
                    current = urljoin(current, location)
                    if response.status_code == 303:
                        request_method = "GET"
                        json_body = None
                    continue

                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > _MAX_AUDIT_RESPONSE_BYTES:
                        raise ToolError(413, "Audit response is too large")
                    chunks.append(chunk)
                return response, b"".join(chunks), current
        except ToolError:
            raise
        except httpx.HTTPError as exc:
            raise ToolError(
                502,
                f"Unable to reach audit target: {type(exc).__name__}",
            ) from exc

    raise ToolError(502, "Too many redirects")


async def audit_mcp_server(
    url: str,
    *,
    previous_fingerprint: str | None = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Perform a live MCP initialize + tools/list audit without authentication."""
    _validate_public_url(url)
    timeout_seconds = min(max(float(timeout_seconds), 3.0), 30.0)
    started = time.perf_counter()

    default_headers = {
        "User-Agent": "CIPHER-MCP-Auditor/1.0",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout_seconds,
    ) as client:
        last_error: dict[str, Any] | None = None
        init_response: dict[str, Any] | None = None
        session_id: str | None = None
        final_url = url
        init_status: int | None = None
        selected_version: str | None = None

        for protocol_version in _MCP_PROTOCOL_VERSIONS:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": protocol_version,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "CIPHER MCP Auditor",
                        "version": "1.0",
                    },
                },
            }
            response, body, final_url = await _bounded_request(
                client,
                "POST",
                url,
                headers=default_headers,
                json_body=request,
                timeout_seconds=timeout_seconds,
            )
            init_status = response.status_code

            if response.status_code in {401, 403}:
                return {
                    "url": final_url,
                    "reachable": True,
                    "speaks_mcp": None,
                    "auth_required": True,
                    "http_status": response.status_code,
                    "status": "AUTH_REQUIRED",
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                    "note": (
                        "The endpoint requires authentication before MCP negotiation; "
                        "no credentials were collected or transmitted."
                    ),
                }

            parsed = _parse_jsonrpc_response(
                body,
                response.headers.get("content-type", ""),
                expected_id=1,
            )
            if response.status_code >= 500:
                last_error = {
                    "http_status": response.status_code,
                    "reason": "upstream_server_error",
                }
                continue
            if response.status_code not in {200, 201, 202} or not parsed:
                last_error = {
                    "http_status": response.status_code,
                    "reason": "no_valid_initialize_response",
                }
                continue
            if parsed.get("error"):
                last_error = {
                    "http_status": response.status_code,
                    "reason": "initialize_jsonrpc_error",
                    "jsonrpc_error": parsed.get("error"),
                }
                continue

            init_response = parsed
            selected_version = protocol_version
            session_id = response.headers.get("mcp-session-id")
            break

        if not init_response:
            return {
                "url": final_url,
                "reachable": True,
                "speaks_mcp": False,
                "auth_required": False,
                "http_status": init_status,
                "status": "BROKEN_OR_NOT_MCP",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "details": last_error,
            }

        result = init_response.get("result") or {}
        server_version = str(result.get("protocolVersion") or selected_version or "")
        headers = dict(default_headers)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        try:
            await _bounded_request(
                client,
                "POST",
                final_url,
                headers=headers,
                json_body=notification,
                timeout_seconds=timeout_seconds,
            )
        except ToolError:
            # Some implementations do not require/accept the notification.
            pass

        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        tools_response, tools_body, _ = await _bounded_request(
            client,
            "POST",
            final_url,
            headers=headers,
            json_body=tools_request,
            timeout_seconds=timeout_seconds,
        )
        tools_rpc = _parse_jsonrpc_response(
            tools_body,
            tools_response.headers.get("content-type", ""),
            expected_id=2,
        )

    if tools_response.status_code in {401, 403}:
        return {
            "url": final_url,
            "reachable": True,
            "speaks_mcp": True,
            "auth_required": True,
            "protocol_version": server_version,
            "server_info": result.get("serverInfo"),
            "status": "AUTH_REQUIRED_AFTER_INITIALIZE",
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    if not tools_rpc or tools_rpc.get("error"):
        return {
            "url": final_url,
            "reachable": True,
            "speaks_mcp": True,
            "auth_required": False,
            "protocol_version": server_version,
            "server_info": result.get("serverInfo"),
            "status": "MCP_TOOLS_LIST_FAILED",
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "tools_http_status": tools_response.status_code,
            "jsonrpc_error": (tools_rpc or {}).get("error"),
        }

    tools = (tools_rpc.get("result") or {}).get("tools") or []
    if not isinstance(tools, list):
        tools = []
    fingerprint = _tool_fingerprint(tools)
    risk = _mcp_tool_risk_signals(tools)
    changed = None
    if previous_fingerprint:
        changed = previous_fingerprint.strip().lower() != fingerprint.lower()

    return {
        "url": final_url,
        "reachable": True,
        "speaks_mcp": True,
        "auth_required": False,
        "protocol_version": server_version,
        "server_info": result.get("serverInfo"),
        "capabilities": result.get("capabilities") or {},
        "session_id_issued": bool(session_id),
        "tools_count": len(tools),
        "tool_names": [str(tool.get("name") or "") for tool in tools[:250] if isinstance(tool, dict)],
        "tool_fingerprint_sha256": fingerprint,
        "previous_fingerprint_changed": changed,
        "risk_signals": risk,
        "status": "HEALTHY" if not risk["tool_poisoning_indicators"] else "REVIEW",
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "scope_note": (
            "Live unauthenticated protocol/schema audit only; it does not execute tools "
            "and does not prove that a server or tool is trustworthy."
        ),
    }


def parse_x402_challenge(
    *,
    status_code: int,
    headers: dict[str, str],
    body: bytes = b"",
) -> dict[str, Any]:
    payment_required = None
    for key, value in headers.items():
        if key.lower() == "payment-required":
            payment_required = value
            break

    payload = _decode_base64_json(payment_required) if payment_required else None
    if payload is None and body:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict) and (
                "accepts" in parsed or parsed.get("x402Version")
            ):
                payload = parsed
        except Exception:
            pass

    result: dict[str, Any] = {
        "http_status": int(status_code),
        "challenge_found": isinstance(payload, dict),
        "payload": payload,
    }
    if not isinstance(payload, dict):
        return result

    accepts = payload.get("accepts")
    if not isinstance(accepts, list):
        accepts = []
    normalized = []
    for requirement in accepts:
        if not isinstance(requirement, dict):
            continue
        amount_raw = requirement.get("amount")
        amount_atomic: int | None = None
        try:
            amount_atomic = int(amount_raw) if amount_raw is not None else None
        except (TypeError, ValueError):
            pass
        item = {
            "scheme": requirement.get("scheme"),
            "network": requirement.get("network"),
            "asset": requirement.get("asset"),
            "amount": str(amount_raw) if amount_raw is not None else None,
            "amount_atomic": amount_atomic,
            "payTo": requirement.get("payTo"),
            "maxTimeoutSeconds": requirement.get("maxTimeoutSeconds"),
        }
        if (
            requirement.get("asset") == _SOLANA_USDC
            and amount_atomic is not None
        ):
            item["amount_usdc"] = amount_atomic / 1_000_000
        normalized.append(item)

    result.update(
        {
            "x402_version": payload.get("x402Version"),
            "resource": payload.get("resource"),
            "requirements": normalized,
        }
    )
    return result


def _openapi_template_match(template: str, actual_path: str) -> bool:
    pattern = "^" + re.sub(r"\{[^/{}]+\}", r"[^/]+", template) + "$"
    return re.fullmatch(pattern, actual_path) is not None


async def audit_x402_endpoint(
    url: str,
    *,
    method: str = "auto",
    body: dict[str, Any] | None = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Cold-probe an x402 endpoint. Never signs or settles a payment."""
    _validate_public_url(url)
    timeout_seconds = min(max(float(timeout_seconds), 3.0), 30.0)
    parsed_url = urlparse(url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    path = parsed_url.path or "/"

    candidate_methods: list[str]
    normalized_method = method.strip().upper()
    if normalized_method == "AUTO":
        candidate_methods = ["GET", "POST"]
    elif normalized_method in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        candidate_methods = [normalized_method]
    else:
        raise ToolError(400, "method must be auto, GET, POST, PUT, PATCH, or DELETE")

    probes: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    started = time.perf_counter()
    headers = {
        "User-Agent": "CIPHER-x402-Auditor/1.0",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds) as client:
        for candidate in candidate_methods:
            response, response_body, final_url = await _bounded_request(
                client,
                candidate,
                url,
                headers=headers,
                json_body=(body or {}) if candidate in {"POST", "PUT", "PATCH"} else None,
                timeout_seconds=timeout_seconds,
            )
            challenge = parse_x402_challenge(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response_body,
            )
            probe = {
                "method": candidate,
                "status": response.status_code,
                "challenge_found": challenge["challenge_found"],
            }
            probes.append(probe)
            if response.status_code == 402 and challenge["challenge_found"]:
                selected = {
                    "method": candidate,
                    "final_url": final_url,
                    "challenge": challenge,
                }
                break
            if normalized_method != "AUTO":
                break
            if response.status_code not in {400, 401, 404, 405, 415, 422}:
                # A healthy free endpoint or unusual response does not benefit from blind POST retry.
                break

        manifest: dict[str, Any] | None = None
        openapi: dict[str, Any] | None = None
        for manifest_path in ("/.well-known/x402", "/.well-known/x402.json"):
            try:
                response, data, _ = await _bounded_request(
                    client,
                    "GET",
                    origin + manifest_path,
                    headers={"User-Agent": "CIPHER-x402-Auditor/1.0", "Accept": "application/json"},
                    timeout_seconds=timeout_seconds,
                )
                if response.status_code == 200:
                    candidate = json.loads(data.decode("utf-8", errors="replace"))
                    if isinstance(candidate, dict):
                        manifest = candidate
                        break
            except Exception:
                continue

        try:
            response, data, _ = await _bounded_request(
                client,
                "GET",
                origin + "/openapi.json",
                headers={"User-Agent": "CIPHER-x402-Auditor/1.0", "Accept": "application/json"},
                timeout_seconds=timeout_seconds,
            )
            if response.status_code == 200:
                candidate = json.loads(data.decode("utf-8", errors="replace"))
                if isinstance(candidate, dict):
                    openapi = candidate
        except Exception:
            pass

    findings: list[dict[str, str]] = []
    if not selected:
        findings.append(
            {
                "severity": "error",
                "code": "NO_VALID_402_CHALLENGE",
                "message": "Cold probe did not find a valid HTTP 402 x402 challenge.",
            }
        )

    manifest_match = None
    if manifest:
        resources = manifest.get("resources") or manifest.get("endpoints") or []
        if isinstance(resources, list):
            for item in resources:
                if not isinstance(item, dict):
                    continue
                item_url = str(item.get("url") or "")
                item_path = str(item.get("path") or item.get("route") or "")
                if item_url == url or item_path == path or (
                    "{" in item_path and _openapi_template_match(item_path, path)
                ):
                    manifest_match = item
                    break
        if manifest_match is None:
            findings.append(
                {
                    "severity": "warning",
                    "code": "NOT_IN_WELL_KNOWN_MANIFEST",
                    "message": "Endpoint was not matched in /.well-known/x402 discovery metadata.",
                }
            )
    else:
        findings.append(
            {
                "severity": "warning",
                "code": "NO_WELL_KNOWN_MANIFEST",
                "message": "No readable /.well-known/x402 discovery document was found.",
            }
        )

    openapi_match: dict[str, Any] | None = None
    if openapi:
        paths = openapi.get("paths") or {}
        if isinstance(paths, dict):
            for template, path_item in paths.items():
                if not isinstance(path_item, dict) or not _openapi_template_match(str(template), path):
                    continue
                methods = [selected["method"].lower()] if selected else [m.lower() for m in candidate_methods]
                for candidate_method in methods:
                    operation = path_item.get(candidate_method)
                    if isinstance(operation, dict):
                        openapi_match = operation
                        break
                if openapi_match:
                    break
        if openapi_match is None:
            findings.append(
                {
                    "severity": "warning",
                    "code": "NOT_IN_OPENAPI",
                    "message": "Endpoint/method was not matched in /openapi.json.",
                }
            )
        elif not openapi_match.get("x-payment-info"):
            findings.append(
                {
                    "severity": "warning",
                    "code": "OPENAPI_PAYMENT_METADATA_MISSING",
                    "message": "OpenAPI operation does not declare x-payment-info.",
                }
            )
    else:
        findings.append(
            {
                "severity": "info",
                "code": "NO_OPENAPI",
                "message": "No readable /openapi.json was found.",
            }
        )

    if selected and manifest_match:
        requirement = (selected["challenge"].get("requirements") or [{}])[0]
        comparisons = (
            ("network", "network"),
            ("asset", "asset"),
            ("payTo", "payTo"),
            ("amount", "amount"),
        )
        for challenge_key, manifest_key in comparisons:
            challenge_value = requirement.get(challenge_key)
            manifest_value = manifest_match.get(manifest_key)
            if manifest_value is None and manifest_key == "amount":
                manifest_value = manifest_match.get("amount")
            if (
                challenge_value is not None
                and manifest_value is not None
                and str(challenge_value) != str(manifest_value)
            ):
                findings.append(
                    {
                        "severity": "error",
                        "code": f"MANIFEST_{challenge_key.upper()}_MISMATCH",
                        "message": (
                            f"Runtime challenge {challenge_key} does not match discovery metadata."
                        ),
                    }
                )

    severities = {item["severity"] for item in findings}
    audit_status = "FAIL" if "error" in severities else "WARN" if "warning" in severities else "PASS"

    return {
        "url": url,
        "status": audit_status,
        "paid_method": selected["method"] if selected else None,
        "challenge": selected["challenge"] if selected else None,
        "cold_probes": probes,
        "well_known_manifest_found": manifest is not None,
        "well_known_endpoint_matched": manifest_match is not None,
        "openapi_found": openapi is not None,
        "openapi_operation_matched": openapi_match is not None,
        "findings": findings,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "payment_attempted": False,
        "note": "This audit never signs or settles a payment.",
    }


def _normalize_payment_terms(challenge: dict[str, Any]) -> dict[str, Any]:
    payload = challenge
    if "payload" in payload and isinstance(payload.get("payload"), dict):
        payload = payload["payload"]

    if "accepts" in payload:
        accepts = payload.get("accepts")
        if not isinstance(accepts, list) or not accepts:
            raise ToolError(422, "Challenge has no usable payment requirements")
        requirement = accepts[0]
        resource = payload.get("resource")
    else:
        requirement = payload
        resource = payload.get("resource")

    if not isinstance(requirement, dict):
        raise ToolError(422, "Payment requirement must be an object")

    amount_atomic = None
    try:
        amount_atomic = int(requirement.get("amount"))
    except (TypeError, ValueError):
        pass

    amount_usdc = None
    if requirement.get("asset") == _SOLANA_USDC and amount_atomic is not None:
        amount_usdc = amount_atomic / 1_000_000

    resource_url = None
    if isinstance(resource, dict):
        resource_url = resource.get("url")
    elif isinstance(resource, str):
        resource_url = resource

    return {
        "scheme": requirement.get("scheme"),
        "network": requirement.get("network"),
        "asset": requirement.get("asset"),
        "amount_atomic": amount_atomic,
        "amount_usdc": amount_usdc,
        "payTo": requirement.get("payTo"),
        "maxTimeoutSeconds": requirement.get("maxTimeoutSeconds"),
        "resource_url": resource_url,
    }


def evaluate_payment_policy(
    challenge: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Deterministically approve/reject an x402 payment request without signing it."""
    terms = _normalize_payment_terms(challenge)
    violations: list[dict[str, Any]] = []

    def _allowed(field: str, allowed_key: str) -> None:
        allowed = policy.get(allowed_key)
        if allowed is None:
            return
        if not isinstance(allowed, list):
            raise ToolError(400, f"{allowed_key} must be a list")
        if terms.get(field) not in allowed:
            violations.append(
                {
                    "code": f"{field.upper()}_NOT_ALLOWED",
                    "actual": terms.get(field),
                    "allowed": allowed,
                }
            )

    _allowed("network", "allowed_networks")
    _allowed("asset", "allowed_assets")
    _allowed("payTo", "allowed_pay_to")
    _allowed("scheme", "allowed_schemes")

    max_atomic = policy.get("max_amount_atomic")
    if max_atomic is not None:
        try:
            ceiling = int(max_atomic)
        except (TypeError, ValueError) as exc:
            raise ToolError(400, "max_amount_atomic must be an integer") from exc
        if terms["amount_atomic"] is None or terms["amount_atomic"] > ceiling:
            violations.append(
                {
                    "code": "AMOUNT_ATOMIC_EXCEEDED_OR_UNKNOWN",
                    "actual": terms["amount_atomic"],
                    "maximum": ceiling,
                }
            )

    max_usdc = policy.get("max_amount_usdc")
    if max_usdc is not None:
        try:
            ceiling_usdc = float(max_usdc)
        except (TypeError, ValueError) as exc:
            raise ToolError(400, "max_amount_usdc must be numeric") from exc
        if terms["amount_usdc"] is None or terms["amount_usdc"] > ceiling_usdc:
            violations.append(
                {
                    "code": "USDC_BUDGET_EXCEEDED_OR_UNKNOWN",
                    "actual": terms["amount_usdc"],
                    "maximum": ceiling_usdc,
                }
            )

    max_timeout = policy.get("max_timeout_seconds")
    if max_timeout is not None:
        try:
            timeout_ceiling = int(max_timeout)
        except (TypeError, ValueError) as exc:
            raise ToolError(400, "max_timeout_seconds must be an integer") from exc
        actual_timeout = terms.get("maxTimeoutSeconds")
        if actual_timeout is None or int(actual_timeout) > timeout_ceiling:
            violations.append(
                {
                    "code": "TIMEOUT_EXCEEDS_POLICY_OR_UNKNOWN",
                    "actual": actual_timeout,
                    "maximum": timeout_ceiling,
                }
            )

    allowed_origins = policy.get("allowed_origins")
    if allowed_origins is not None:
        if not isinstance(allowed_origins, list):
            raise ToolError(400, "allowed_origins must be a list")
        resource_url = terms.get("resource_url")
        origin = None
        if resource_url:
            parsed = urlparse(str(resource_url))
            if parsed.scheme and parsed.netloc:
                origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in allowed_origins:
            violations.append(
                {
                    "code": "RESOURCE_ORIGIN_NOT_ALLOWED",
                    "actual": origin,
                    "allowed": allowed_origins,
                }
            )

    require_https = bool(policy.get("require_https_resource", True))
    if require_https and terms.get("resource_url"):
        if not str(terms["resource_url"]).startswith("https://"):
            violations.append(
                {
                    "code": "RESOURCE_NOT_HTTPS",
                    "actual": terms["resource_url"],
                }
            )

    required_pay_to = policy.get("expected_pay_to")
    if required_pay_to is not None and terms.get("payTo") != required_pay_to:
        violations.append(
            {
                "code": "PAY_TO_MISMATCH",
                "actual": terms.get("payTo"),
                "expected": required_pay_to,
            }
        )

    return {
        "approved": not violations,
        "decision": "APPROVE" if not violations else "REJECT",
        "violations": violations,
        "terms": terms,
        "payment_signed": False,
        "payment_settled": False,
        "note": (
            "Deterministic pre-payment policy evaluation only. "
            "CIPHER never needs the payer's private key."
        ),
    }


_CURRENT_MCP_REGISTRY_SCHEMA = (
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
)
_REGISTRY_SCHEMA_CACHE: dict[str, Any] = {}


async def bulk_mcp_audit(
    urls: list[str],
    *,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Audit up to 10 MCP endpoints with bounded concurrency."""
    if not isinstance(urls, list) or not urls:
        raise ToolError(400, "urls must be a non-empty list")
    if len(urls) > 10:
        raise ToolError(400, "A bulk MCP audit supports at most 10 URLs")
    if any(not isinstance(url, str) or not url.strip() for url in urls):
        raise ToolError(400, "Every MCP URL must be a non-empty string")

    semaphore = asyncio.Semaphore(4)

    async def run(url: str) -> dict[str, Any]:
        async with semaphore:
            try:
                return await audit_mcp_server(
                    url.strip(),
                    timeout_seconds=timeout_seconds,
                )
            except ToolError as exc:
                return {
                    "url": url,
                    "status": "ERROR",
                    "error": exc.message,
                    "http_status": exc.status_code,
                }
            except Exception as exc:
                return {
                    "url": url,
                    "status": "ERROR",
                    "error": type(exc).__name__,
                }

    results = await asyncio.gather(*(run(url) for url in urls))
    healthy = sum(1 for item in results if item.get("status") == "HEALTHY")
    review = sum(1 for item in results if item.get("status") == "REVIEW")
    auth = sum(1 for item in results if str(item.get("status", "")).startswith("AUTH_REQUIRED"))
    errors = len(results) - healthy - review - auth

    return {
        "count": len(results),
        "summary": {
            "healthy": healthy,
            "review": review,
            "auth_required": auth,
            "other_or_error": errors,
        },
        "results": results,
    }


async def bulk_x402_audit(
    urls: list[str],
    *,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Cold-probe up to 10 x402 endpoints without paying any of them."""
    if not isinstance(urls, list) or not urls:
        raise ToolError(400, "urls must be a non-empty list")
    if len(urls) > 10:
        raise ToolError(400, "A bulk x402 audit supports at most 10 URLs")
    if any(not isinstance(url, str) or not url.strip() for url in urls):
        raise ToolError(400, "Every x402 URL must be a non-empty string")

    semaphore = asyncio.Semaphore(4)

    async def run(url: str) -> dict[str, Any]:
        async with semaphore:
            try:
                return await audit_x402_endpoint(
                    url.strip(),
                    method="auto",
                    timeout_seconds=timeout_seconds,
                )
            except ToolError as exc:
                return {
                    "url": url,
                    "status": "ERROR",
                    "error": exc.message,
                    "http_status": exc.status_code,
                    "payment_attempted": False,
                }
            except Exception as exc:
                return {
                    "url": url,
                    "status": "ERROR",
                    "error": type(exc).__name__,
                    "payment_attempted": False,
                }

    results = await asyncio.gather(*(run(url) for url in urls))
    summary = {
        "pass": sum(1 for item in results if item.get("status") == "PASS"),
        "warn": sum(1 for item in results if item.get("status") == "WARN"),
        "fail": sum(1 for item in results if item.get("status") == "FAIL"),
        "error": sum(1 for item in results if item.get("status") == "ERROR"),
    }
    return {
        "count": len(results),
        "summary": summary,
        "results": results,
        "payment_attempted": False,
    }


async def agent_adoption_preflight(
    *,
    repo: str | None = None,
    mcp_url: str | None = None,
    x402_url: str | None = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """One-call adoption preflight combining repo, MCP, and x402 evidence."""
    if not any((repo, mcp_url, x402_url)):
        raise ToolError(400, "Provide at least one of repo, mcp_url, or x402_url")

    tasks: dict[str, Any] = {}
    if repo:
        from agent_tools import repo_preflight

        tasks["repository"] = repo_preflight(repo)
    if mcp_url:
        tasks["mcp"] = audit_mcp_server(
            mcp_url,
            timeout_seconds=timeout_seconds,
        )
    if x402_url:
        tasks["x402"] = audit_x402_endpoint(
            x402_url,
            method="auto",
            timeout_seconds=timeout_seconds,
        )

    keys = list(tasks)
    gathered = await asyncio.gather(
        *(tasks[key] for key in keys),
        return_exceptions=True,
    )

    evidence: dict[str, Any] = {}
    reasons: list[str] = []
    fail = False
    review = False

    for key, value in zip(keys, gathered):
        if isinstance(value, Exception):
            message = (
                value.message
                if isinstance(value, ToolError)
                else type(value).__name__
            )
            evidence[key] = {"status": "ERROR", "error": message}
            reasons.append(f"{key}_audit_error")
            review = True
            continue

        evidence[key] = value
        if key == "repository":
            recommendation = str(value.get("recommendation") or "")
            if recommendation == "AVOID_OR_FORK":
                fail = True
                reasons.append("repository_archived_or_stale")
            elif recommendation != "ADAPT_AFTER_TECHNICAL_REVIEW":
                review = True
                reasons.append("repository_requires_review")
        elif key == "mcp":
            status = str(value.get("status") or "")
            if status in {"BROKEN_OR_NOT_MCP", "MCP_TOOLS_LIST_FAILED"}:
                fail = True
                reasons.append("mcp_unusable")
            elif status != "HEALTHY":
                review = True
                reasons.append("mcp_requires_review")
        elif key == "x402":
            status = str(value.get("status") or "")
            if status == "FAIL":
                fail = True
                reasons.append("x402_discovery_or_challenge_failure")
            elif status != "PASS":
                review = True
                reasons.append("x402_requires_review")

    decision = "REJECT" if fail else "REVIEW" if review else "ADOPT_CANDIDATE"
    return {
        "decision": decision,
        "reasons": reasons,
        "evidence": evidence,
        "note": (
            "This is an engineering preflight, not a guarantee of security, "
            "correctness, profitability, or legal/license compatibility."
        ),
    }


async def _load_registry_schema(schema_url: str) -> dict[str, Any]:
    if schema_url in _REGISTRY_SCHEMA_CACHE:
        return _REGISTRY_SCHEMA_CACHE[schema_url]

    parsed = urlparse(schema_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "static.modelcontextprotocol.io"
        or not parsed.path.endswith("/server.schema.json")
    ):
        raise ToolError(
            400,
            "Only official static.modelcontextprotocol.io server schemas are supported",
        )

    async with httpx.AsyncClient(follow_redirects=False, timeout=12.0) as client:
        response, body, _ = await _bounded_request(
            client,
            "GET",
            schema_url,
            headers={
                "User-Agent": "CIPHER-MCP-Registry-Doctor/1.0",
                "Accept": "application/schema+json, application/json",
            },
            timeout_seconds=12.0,
        )
    if response.status_code != 200:
        raise ToolError(
            502,
            f"Official MCP schema returned HTTP {response.status_code}",
        )
    try:
        schema = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise ToolError(502, "Official MCP schema was not valid JSON") from exc
    if not isinstance(schema, dict):
        raise ToolError(502, "Official MCP schema had an unexpected shape")
    _REGISTRY_SCHEMA_CACHE[schema_url] = schema
    return schema


async def mcp_registry_doctor(
    server_json: dict[str, Any],
    *,
    probe_remote: bool = True,
) -> dict[str, Any]:
    """Validate server.json against the official schema and optionally probe remotes."""
    if not isinstance(server_json, dict):
        raise ToolError(400, "server_json must be a JSON object")

    schema_url = str(
        server_json.get("$schema") or _CURRENT_MCP_REGISTRY_SCHEMA
    ).strip()
    schema = await _load_registry_schema(schema_url)

    try:
        from jsonschema import validators

        validator_cls = validators.validator_for(schema)
        validator_cls.check_schema(schema)
        validator = validator_cls(schema)
        raw_errors = sorted(
            validator.iter_errors(server_json),
            key=lambda err: list(err.absolute_path),
        )
    except Exception as exc:
        raise ToolError(502, "Unable to execute official MCP JSON Schema validation") from exc

    errors = []
    for err in raw_errors[:100]:
        path = ".".join(str(item) for item in err.absolute_path) or "$"
        errors.append(
            {
                "path": path,
                "message": err.message,
                "validator": err.validator,
            }
        )

    warnings: list[dict[str, str]] = []
    if schema_url != _CURRENT_MCP_REGISTRY_SCHEMA:
        warnings.append(
            {
                "code": "NON_CURRENT_SCHEMA",
                "message": (
                    f"Manifest declares {schema_url}; current registry schema is "
                    f"{_CURRENT_MCP_REGISTRY_SCHEMA}."
                ),
            }
        )

    name = str(server_json.get("name") or "")
    description = str(server_json.get("description") or "")
    if len(description) > 100:
        warnings.append(
            {
                "code": "DESCRIPTION_OVER_100",
                "message": "Registry descriptions are limited to 100 characters.",
            }
        )
    if name and not re.fullmatch(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+", name):
        warnings.append(
            {
                "code": "NAME_SHAPE",
                "message": "Server name should be namespace/name in the registry pattern.",
            }
        )

    packages = server_json.get("packages")
    remotes = server_json.get("remotes")
    if not packages and not remotes:
        warnings.append(
            {
                "code": "NO_PACKAGE_OR_REMOTE",
                "message": "Manifest declares neither a package nor a remote endpoint.",
            }
        )

    remote_results: list[dict[str, Any]] = []
    if probe_remote and isinstance(remotes, list):
        remote_urls = []
        for remote in remotes[:5]:
            if isinstance(remote, dict) and isinstance(remote.get("url"), str):
                remote_urls.append(remote["url"])

        semaphore = asyncio.Semaphore(3)

        async def probe(url: str) -> dict[str, Any]:
            async with semaphore:
                try:
                    return await audit_mcp_server(url, timeout_seconds=10.0)
                except ToolError as exc:
                    return {
                        "url": url,
                        "status": "ERROR",
                        "error": exc.message,
                    }
                except Exception as exc:
                    return {
                        "url": url,
                        "status": "ERROR",
                        "error": type(exc).__name__,
                    }

        if remote_urls:
            remote_results = await asyncio.gather(*(probe(url) for url in remote_urls))

    registry_lookup: dict[str, Any] | None = None
    if name:
        try:
            lookup_url = (
                "https://registry.modelcontextprotocol.io/v0.1/servers?search="
                + quote(name, safe="")
                + "&limit=10"
            )
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=10.0,
            ) as client:
                response, body, _ = await _bounded_request(
                    client,
                    "GET",
                    lookup_url,
                    headers={
                        "User-Agent": "CIPHER-MCP-Registry-Doctor/1.0",
                        "Accept": "application/json",
                    },
                    timeout_seconds=10.0,
                )
            if response.status_code == 200:
                data = json.loads(body.decode("utf-8", errors="replace"))
                rows = data.get("servers") if isinstance(data, dict) else None
                if isinstance(rows, list):
                    exact = [
                        row
                        for row in rows
                        if isinstance(row, dict)
                        and (
                            row.get("name") == name
                            or (row.get("server") or {}).get("name") == name
                        )
                    ]
                    registry_lookup = {
                        "exact_name_matches": len(exact),
                        "already_present": bool(exact),
                    }
        except Exception:
            registry_lookup = {"lookup_available": False}

    remote_failures = [
        item
        for item in remote_results
        if item.get("status") not in {"HEALTHY", "REVIEW", "AUTH_REQUIRED"}
    ]
    publish_readiness = (
        "BLOCKED"
        if errors
        else "REVIEW"
        if warnings or remote_failures
        else "READY"
    )

    return {
        "valid_against_declared_schema": not errors,
        "schema_url": schema_url,
        "current_schema_url": _CURRENT_MCP_REGISTRY_SCHEMA,
        "errors": errors,
        "warnings": warnings,
        "remote_probes": remote_results,
        "registry_lookup": registry_lookup,
        "publish_readiness": publish_readiness,
        "note": (
            "Schema validation uses the official MCP Registry schema. "
            "Authentication/namespace ownership failures can still occur at publish time."
        ),
    }



def _www_authenticate_param(value: str, name: str) -> str | None:
    if not value:
        return None
    match = re.search(
        rf'(?:^|[,\s]){re.escape(name)}\s*=\s*"([^"]+)"',
        value,
        re.I,
    )
    if match:
        return match.group(1).strip()
    match = re.search(
        rf'(?:^|[,\s]){re.escape(name)}\s*=\s*([^,\s]+)',
        value,
        re.I,
    )
    return match.group(1).strip() if match else None


def _oauth_metadata_candidates(issuer: str) -> list[str]:
    parsed = urlparse(issuer)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    candidates = []
    if path:
        candidates.append(origin + "/.well-known/oauth-authorization-server" + path)
        candidates.append(origin + path + "/.well-known/openid-configuration")
    candidates.append(origin + "/.well-known/oauth-authorization-server")
    candidates.append(origin + "/.well-known/openid-configuration")

    seen: set[str] = set()
    ordered: list[str] = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


async def _fetch_json_document(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout_seconds: float,
) -> tuple[dict[str, Any] | None, int | None, str]:
    try:
        response, body, final_url = await _bounded_request(
            client,
            "GET",
            url,
            headers={
                "User-Agent": "CIPHER-MCP-OAuth-Doctor/1.0",
                "Accept": "application/json",
            },
            timeout_seconds=timeout_seconds,
        )
    except ToolError:
        return None, None, url

    if response.status_code != 200:
        return None, response.status_code, final_url
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return None, response.status_code, final_url
    return (parsed if isinstance(parsed, dict) else None), response.status_code, final_url


async def mcp_oauth_doctor(
    url: str,
    *,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Audit MCP OAuth discovery without requesting credentials or tokens."""
    _validate_public_url(url)
    timeout_seconds = min(max(float(timeout_seconds), 3.0), 30.0)
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    started = time.perf_counter()

    findings: list[dict[str, str]] = []
    headers = {
        "User-Agent": "CIPHER-MCP-OAuth-Doctor/1.0",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "CIPHER OAuth Doctor", "version": "1.0"},
        },
    }

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout_seconds) as client:
        response, _, final_url = await _bounded_request(
            client,
            "POST",
            url,
            headers=headers,
            json_body=initialize,
            timeout_seconds=timeout_seconds,
        )
        www_authenticate = response.headers.get("www-authenticate", "")
        header_metadata_url = _www_authenticate_param(
            www_authenticate,
            "resource_metadata",
        )
        header_scope = _www_authenticate_param(www_authenticate, "scope")

        candidate_urls: list[str] = []
        if header_metadata_url:
            candidate_urls.append(header_metadata_url)

        path_suffix = path if path.startswith("/") else "/" + path
        if path_suffix != "/":
            candidate_urls.append(
                origin + "/.well-known/oauth-protected-resource" + path_suffix
            )
        candidate_urls.append(origin + "/.well-known/oauth-protected-resource")

        seen: set[str] = set()
        prm_url = None
        prm = None
        prm_status = None
        for candidate in candidate_urls:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                _validate_public_url(candidate)
            except ToolError:
                findings.append(
                    {
                        "severity": "error",
                        "code": "INVALID_RESOURCE_METADATA_URL",
                        "message": "Protected-resource metadata URL is not a valid public HTTP(S) URL.",
                    }
                )
                continue
            document, status, discovered_url = await _fetch_json_document(
                client,
                candidate,
                timeout_seconds=timeout_seconds,
            )
            if document is not None:
                prm = document
                prm_url = discovered_url
                prm_status = status
                break

        if response.status_code == 401 and not header_metadata_url:
            findings.append(
                {
                    "severity": "warning",
                    "code": "WWW_AUTHENTICATE_RESOURCE_METADATA_MISSING",
                    "message": (
                        "401 challenge did not advertise resource_metadata; clients must rely "
                        "on RFC 9728 well-known fallback discovery."
                    ),
                }
            )
        elif response.status_code not in {401, 403}:
            findings.append(
                {
                    "severity": "info",
                    "code": "INITIAL_REQUEST_NOT_AUTH_CHALLENGED",
                    "message": (
                        f"Initial MCP request returned HTTP {response.status_code}; "
                        "the endpoint may be public or use a different authorization gate."
                    ),
                }
            )

        if prm is None:
            findings.append(
                {
                    "severity": "error",
                    "code": "PROTECTED_RESOURCE_METADATA_NOT_FOUND",
                    "message": "No usable RFC 9728 protected-resource metadata document was found.",
                }
            )
            return {
                "url": final_url,
                "status": "FAIL",
                "initial_http_status": response.status_code,
                "www_authenticate_present": bool(www_authenticate),
                "resource_metadata_url": None,
                "findings": findings,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "credentials_requested": False,
                "tokens_requested": False,
            }

        resource_value = prm.get("resource")
        if resource_value != final_url and resource_value != url:
            findings.append(
                {
                    "severity": "error",
                    "code": "RESOURCE_IDENTIFIER_MISMATCH",
                    "message": (
                        "Protected-resource metadata resource value does not exactly match "
                        "the MCP resource URL."
                    ),
                }
            )

        authorization_servers = prm.get("authorization_servers")
        if not isinstance(authorization_servers, list) or not authorization_servers:
            findings.append(
                {
                    "severity": "error",
                    "code": "AUTHORIZATION_SERVERS_MISSING",
                    "message": "Protected-resource metadata has no authorization_servers entry.",
                }
            )
            authorization_servers = []

        server_results: list[dict[str, Any]] = []
        for issuer in authorization_servers[:5]:
            if not isinstance(issuer, str):
                continue
            metadata = None
            metadata_url = None
            metadata_status = None
            try:
                _validate_public_url(issuer)
            except ToolError:
                server_results.append(
                    {
                        "issuer": issuer,
                        "metadata_found": False,
                        "error": "issuer_not_public_https_or_http",
                    }
                )
                continue

            for candidate in _oauth_metadata_candidates(issuer):
                document, status, discovered_url = await _fetch_json_document(
                    client,
                    candidate,
                    timeout_seconds=timeout_seconds,
                )
                if document is not None:
                    metadata = document
                    metadata_url = discovered_url
                    metadata_status = status
                    break

            if metadata is None:
                findings.append(
                    {
                        "severity": "error",
                        "code": "AUTH_SERVER_METADATA_NOT_FOUND",
                        "message": f"No OAuth/OIDC metadata found for authorization server {issuer}.",
                    }
                )
                server_results.append(
                    {
                        "issuer": issuer,
                        "metadata_found": False,
                        "metadata_status": metadata_status,
                    }
                )
                continue

            missing = [
                field
                for field in ("authorization_endpoint", "token_endpoint")
                if not metadata.get(field)
            ]
            if missing:
                findings.append(
                    {
                        "severity": "error",
                        "code": "AUTH_SERVER_ENDPOINTS_MISSING",
                        "message": (
                            f"Authorization server {issuer} is missing required metadata: "
                            + ", ".join(missing)
                        ),
                    }
                )

            pkce = metadata.get("code_challenge_methods_supported")
            if isinstance(pkce, list) and "S256" not in pkce:
                findings.append(
                    {
                        "severity": "warning",
                        "code": "PKCE_S256_NOT_ADVERTISED",
                        "message": f"Authorization server {issuer} does not advertise PKCE S256.",
                    }
                )

            server_results.append(
                {
                    "issuer": issuer,
                    "metadata_found": True,
                    "metadata_url": metadata_url,
                    "authorization_endpoint": metadata.get("authorization_endpoint"),
                    "token_endpoint": metadata.get("token_endpoint"),
                    "registration_endpoint": metadata.get("registration_endpoint"),
                    "dynamic_client_registration_available": bool(
                        metadata.get("registration_endpoint")
                    ),
                    "scopes_supported": metadata.get("scopes_supported"),
                    "code_challenge_methods_supported": pkce,
                }
            )

    severities = {item["severity"] for item in findings}
    status = "FAIL" if "error" in severities else "WARN" if "warning" in severities else "PASS"
    return {
        "url": final_url,
        "status": status,
        "initial_http_status": response.status_code,
        "www_authenticate_present": bool(www_authenticate),
        "www_authenticate_scope": header_scope,
        "resource_metadata_url": prm_url,
        "resource_metadata_http_status": prm_status,
        "resource_metadata": {
            "resource": prm.get("resource"),
            "authorization_servers": authorization_servers,
            "scopes_supported": prm.get("scopes_supported"),
        },
        "authorization_servers": server_results,
        "findings": findings,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "credentials_requested": False,
        "tokens_requested": False,
        "note": (
            "Discovery/configuration audit only. CIPHER does not register OAuth clients, "
            "open user authorization pages, request access tokens, or collect credentials."
        ),
    }


def _x402_challenge_fingerprint(challenge: dict[str, Any]) -> str:
    normalized = {
        "x402_version": challenge.get("x402_version"),
        "resource": challenge.get("resource"),
        "requirements": challenge.get("requirements") or [],
    }
    raw = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


async def x402_prepay_verify(
    url: str,
    *,
    policy: dict[str, Any],
    method: str = "auto",
    body: dict[str, Any] | None = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Re-fetch x402 terms and apply caller policy before any payment is signed."""
    if not isinstance(policy, dict):
        raise ToolError(400, "policy must be a JSON object")

    first = await audit_x402_endpoint(
        url,
        method=method,
        body=body,
        timeout_seconds=timeout_seconds,
    )
    first_challenge = first.get("challenge")
    if not isinstance(first_challenge, dict) or not first_challenge.get("challenge_found"):
        return {
            "approved": False,
            "decision": "REJECT",
            "reason": "NO_VALID_402_CHALLENGE",
            "first_probe": first,
            "payment_signed": False,
            "payment_settled": False,
        }

    second = await audit_x402_endpoint(
        url,
        method=first.get("paid_method") or method,
        body=body,
        timeout_seconds=timeout_seconds,
    )
    second_challenge = second.get("challenge")
    if not isinstance(second_challenge, dict) or not second_challenge.get("challenge_found"):
        return {
            "approved": False,
            "decision": "REJECT",
            "reason": "CHALLENGE_DISAPPEARED_ON_REFETCH",
            "first_probe": first,
            "second_probe": second,
            "payment_signed": False,
            "payment_settled": False,
        }

    first_fp = _x402_challenge_fingerprint(first_challenge)
    second_fp = _x402_challenge_fingerprint(second_challenge)
    consistent = first_fp == second_fp

    policy_result = evaluate_payment_policy(
        second_challenge.get("payload") or second_challenge,
        policy,
    )

    reasons: list[str] = []
    if not consistent:
        reasons.append("PAYMENT_TERMS_CHANGED_BETWEEN_FETCHES")
    if not policy_result.get("approved"):
        reasons.append("POLICY_REJECTED_PAYMENT")

    approved = consistent and bool(policy_result.get("approved"))
    return {
        "approved": approved,
        "decision": "APPROVE" if approved else "REJECT",
        "reasons": reasons,
        "challenge_consistent": consistent,
        "first_challenge_fingerprint": first_fp,
        "second_challenge_fingerprint": second_fp,
        "terms": policy_result.get("terms"),
        "policy": policy_result,
        "runtime_discovery_status": second.get("status"),
        "paid_method": second.get("paid_method"),
        "payment_signed": False,
        "payment_settled": False,
        "note": (
            "Verify-before-pay only. CIPHER re-fetches the live payment terms and applies "
            "the caller's constraints but never receives or uses a private key."
        ),
    }
