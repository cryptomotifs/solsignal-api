from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

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
