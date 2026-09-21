from __future__ import annotations

import ast
import asyncio
import ipaddress
import json
import re
import socket
import time
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from io import BytesIO
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from pypdf import PdfReader


class ToolError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


_CACHE: dict[str, tuple[float, Any]] = {}


def _cache_get(key: str, ttl: int) -> Any | None:
    item = _CACHE.get(key)
    if not item:
        return None
    ts, value = item
    if time.time() - ts > ttl:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: Any) -> None:
    _CACHE[key] = (time.time(), value)
    if len(_CACHE) > 256:
        for key, _ in sorted(_CACHE.items(), key=lambda kv: kv[1][0])[:64]:
            _CACHE.pop(key, None)


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ToolError(400, "Only http:// and https:// URLs are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ToolError(400, "Invalid public URL")

    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ToolError(400, "Private/local destinations are not allowed")

    try:
        infos = socket.getaddrinfo(
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ToolError(400, "Host could not be resolved") from exc

    addresses = {info[4][0] for info in infos}
    if not addresses or any(not _is_public_ip(addr) for addr in addresses):
        raise ToolError(400, "Private, reserved, or non-public destinations are not allowed")


async def _safe_fetch(
    url: str,
    *,
    max_bytes: int,
    allowed_types: tuple[str, ...],
    timeout_seconds: float = 15.0,
) -> tuple[bytes, str, str]:
    current = url
    headers = {"User-Agent": "CIPHER-Agent-Tools/1.0"}

    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        headers=headers,
    ) as client:
        for _ in range(4):
            _validate_public_url(current)
            try:
                async with client.stream("GET", current) as resp:
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        location = resp.headers.get("location")
                        if not location:
                            raise ToolError(502, "Redirect missing Location header")
                        current = urljoin(current, location)
                        continue

                    if resp.status_code >= 400:
                        raise ToolError(502, f"Upstream returned HTTP {resp.status_code}")

                    content_type = (
                        resp.headers.get("content-type", "")
                        .split(";", 1)[0]
                        .strip()
                        .lower()
                    )
                    if not any(
                        content_type == allowed or content_type.startswith(allowed)
                        for allowed in allowed_types
                    ):
                        raise ToolError(
                            415,
                            f"Unsupported content type: {content_type or 'unknown'}",
                        )

                    content_length = resp.headers.get("content-length")
                    if (
                        content_length
                        and content_length.isdigit()
                        and int(content_length) > max_bytes
                    ):
                        raise ToolError(413, "Resource is too large")

                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            raise ToolError(413, "Resource is too large")
                        chunks.append(chunk)
                    return b"".join(chunks), content_type, current
            except ToolError:
                raise
            except httpx.HTTPError as exc:
                raise ToolError(
                    502,
                    f"Unable to fetch upstream resource: {type(exc).__name__}",
                ) from exc

    raise ToolError(502, "Too many redirects")


class ReadableHTML(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "canvas", "template"}
    BLOCKS = {
        "p", "div", "section", "article", "main", "header", "footer",
        "aside", "br", "li", "ul", "ol", "pre", "blockquote", "table", "tr",
    }

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.description = ""
        self.text_parts: list[str] = []
        self.links: list[dict[str, str]] = []
        self.skip_depth = 0
        self.in_title = False
        self.link_href: str | None = None
        self.link_text: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        tag = tag.lower()
        attr = {k.lower(): v for k, v in attrs}
        if tag in self.SKIP:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "title":
            self.in_title = True
        if tag == "meta":
            name = (attr.get("name") or attr.get("property") or "").lower()
            if name in {"description", "og:description"} and not self.description:
                self.description = (attr.get("content") or "").strip()
        if tag.startswith("h") and len(tag) == 2 and tag[1].isdigit():
            level = min(max(int(tag[1]), 1), 6)
            self.text_parts.append("\n" + "#" * level + " ")
        elif tag == "li":
            self.text_parts.append("\n- ")
        elif tag in self.BLOCKS:
            self.text_parts.append("\n")
        if tag == "a":
            href = attr.get("href")
            if href:
                absolute = urljoin(self.base_url, href)
                if urlparse(absolute).scheme in {"http", "https"}:
                    self.link_href = absolute
                    self.link_text = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if self.skip_depth:
            return
        if tag == "title":
            self.in_title = False
        if tag.startswith("h") and len(tag) == 2:
            self.text_parts.append("\n")
        if tag == "a" and self.link_href:
            label = " ".join("".join(self.link_text).split())[:240]
            self.links.append({"text": label, "url": self.link_href})
            self.link_href = None
            self.link_text = []

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        cleaned = unescape(data).strip()
        if not cleaned:
            return
        if self.in_title:
            self.title = (self.title + " " + cleaned).strip()
            return
        self.text_parts.append(cleaned + " ")
        if self.link_href:
            self.link_text.append(cleaned)

    def markdown(self) -> str:
        raw = "".join(self.text_parts)
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r" *\n *", "\n", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


async def read_url(url: str, *, max_chars: int = 50_000) -> dict[str, Any]:
    max_chars = min(max(max_chars, 1_000), 100_000)
    body, content_type, final_url = await _safe_fetch(
        url,
        max_bytes=1_500_000,
        allowed_types=("text/html", "application/xhtml+xml", "text/plain"),
    )

    text = body.decode("utf-8", errors="replace")
    if content_type == "text/plain":
        title = ""
        description = ""
        markdown = text.strip()
        links: list[dict[str, str]] = []
    else:
        parser = ReadableHTML(final_url)
        parser.feed(text)
        title = parser.title
        description = parser.description
        markdown = parser.markdown()
        links = parser.links[:100]

    truncated = len(markdown) > max_chars
    markdown = markdown[:max_chars]
    return {
        "url": final_url,
        "title": title,
        "description": description,
        "markdown": markdown,
        "links": links,
        "characters": len(markdown),
        "truncated": truncated,
        "source": "public_web",
    }


async def pdf_to_markdown(
    url: str,
    *,
    max_pages: int = 20,
    max_chars: int = 80_000,
) -> dict[str, Any]:
    max_pages = min(max(max_pages, 1), 40)
    max_chars = min(max(max_chars, 1_000), 150_000)

    body, _, final_url = await _safe_fetch(
        url,
        max_bytes=10_000_000,
        allowed_types=("application/pdf",),
        timeout_seconds=25.0,
    )
    try:
        reader = PdfReader(BytesIO(body))
    except Exception as exc:
        raise ToolError(422, "The resource could not be parsed as a PDF") from exc

    pages: list[str] = []
    char_count = 0
    processed = 0
    for idx, page in enumerate(reader.pages[:max_pages]):
        try:
            text = (page.extract_text() or "").strip()
        except Exception:
            text = ""
        block = f"## Page {idx + 1}\n\n{text}\n"
        if char_count + len(block) > max_chars:
            remaining = max_chars - char_count
            if remaining > 0:
                pages.append(block[:remaining])
            break
        pages.append(block)
        char_count += len(block)
        processed += 1

    markdown = "\n".join(pages).strip()
    return {
        "url": final_url,
        "pages_total": len(reader.pages),
        "pages_processed": processed,
        "markdown": markdown,
        "characters": len(markdown),
        "truncated": processed < min(len(reader.pages), max_pages),
        "ocr_used": False,
        "source": "public_pdf",
        "note": "Text-layer extraction only; image-only scanned PDFs may return little text.",
    }


def repair_json(raw: str) -> dict[str, Any]:
    if len(raw) > 200_000:
        raise ToolError(413, "Input is too large")

    original = raw
    value = raw.strip().lstrip("\ufeff")
    repairs: list[str] = []

    fence = re.match(r"^\`\`\`(?:json|JSON)?\s*(.*?)\s*\`\`\`$", value, re.S)
    if fence:
        value = fence.group(1).strip()
        repairs.append("removed_markdown_fence")

    try:
        parsed: Any = json.loads(value)
    except Exception:
        starts = [i for i in (value.find("{"), value.find("[")) if i >= 0]
        if starts:
            start = min(starts)
            end = max(value.rfind("}"), value.rfind("]"))
            if end > start:
                candidate = value[start : end + 1]
                if candidate != value:
                    value = candidate
                    repairs.append("removed_surrounding_text")

        without_trailing = re.sub(r",\s*([}\]])", r"\1", value)
        if without_trailing != value:
            value = without_trailing
            repairs.append("removed_trailing_commas")

        value = (
            value.replace("“", '"')
            .replace("”", '"')
            .replace("’", "'")
        )

        try:
            parsed = json.loads(value)
        except Exception:
            try:
                parsed = ast.literal_eval(value)
                repairs.append("parsed_python_literal")
            except Exception as exc:
                raise ToolError(
                    422,
                    "Unable to repair input into valid JSON safely",
                ) from exc

    try:
        normalized = json.loads(json.dumps(parsed, ensure_ascii=False))
    except Exception as exc:
        raise ToolError(422, "Repaired value is not JSON-serializable") from exc

    return {
        "valid": True,
        "value": normalized,
        "json": json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        "repairs": repairs,
        "changed": original.strip() != json.dumps(normalized, ensure_ascii=False),
    }


def _parse_repo(repo: str) -> tuple[str, str]:
    value = repo.strip()
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        if parsed.hostname not in {"github.com", "www.github.com"}:
            raise ToolError(400, "Only github.com repository URLs are supported")
        parts = [part for part in parsed.path.split("/") if part]
    else:
        parts = [part for part in value.split("/") if part]

    if len(parts) < 2:
        raise ToolError(400, "Use owner/repository or a GitHub repository URL")

    owner = parts[0]
    name = parts[1].removesuffix(".git")
    valid = r"[A-Za-z0-9_.-]{1,100}"
    if not re.fullmatch(valid, owner) or not re.fullmatch(valid, name):
        raise ToolError(400, "Invalid GitHub owner or repository name")
    return owner, name


async def repo_preflight(
    repo: str,
    *,
    github_token: str = "",
) -> dict[str, Any]:
    owner, name = _parse_repo(repo)
    cache_key = f"repo:{owner.lower()}/{name.lower()}"
    cached = _cache_get(cache_key, 300)
    if cached is not None:
        return {**cached, "cached": True}

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CIPHER-Agent-Tools/1.0",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        resp = await client.get(f"https://api.github.com/repos/{owner}/{name}")
        if resp.status_code == 404:
            raise ToolError(404, "Repository not found or not public")
        if resp.status_code == 403:
            raise ToolError(429, "GitHub API rate limit reached; retry later")
        if resp.status_code >= 400:
            raise ToolError(502, f"GitHub API returned HTTP {resp.status_code}")
        data = resp.json()

        async def exists(path: str) -> bool:
            result = await client.get(
                f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
            )
            return result.status_code == 200

        checks = await asyncio.gather(
            exists("SECURITY.md"),
            exists(".github/SECURITY.md"),
            exists("requirements.txt"),
            exists("pyproject.toml"),
            exists("package.json"),
            exists("Cargo.toml"),
            exists("go.mod"),
            exists("Dockerfile"),
            exists(".github/workflows"),
        )

    security_policy = checks[0] or checks[1]
    manifests = [
        manifest
        for manifest, present in zip(
            ["requirements.txt", "pyproject.toml", "package.json", "Cargo.toml", "go.mod"],
            checks[2:7],
        )
        if present
    ]
    dockerfile = checks[7]
    workflows = checks[8]

    pushed_at = data.get("pushed_at") or data.get("updated_at")
    days_since_push: int | None = None
    if pushed_at:
        try:
            pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            days_since_push = max(
                0,
                (datetime.now(timezone.utc) - pushed).days,
            )
        except Exception:
            pass

    license_id = (
        ((data.get("license") or {}).get("spdx_id") or "NOASSERTION")
        .upper()
    )
    permissive = {
        "MIT",
        "APACHE-2.0",
        "BSD-2-CLAUSE",
        "BSD-3-CLAUSE",
        "ISC",
        "0BSD",
        "UNLICENSE",
    }
    copyleft = {
        "GPL-2.0",
        "GPL-3.0",
        "AGPL-3.0",
        "LGPL-2.1",
        "LGPL-3.0",
    }

    risks: list[str] = []
    if data.get("archived"):
        risks.append("repository_archived")
    if days_since_push is not None and days_since_push > 365:
        risks.append("no_push_in_over_1_year")
    elif days_since_push is not None and days_since_push > 180:
        risks.append("no_push_in_over_6_months")
    if license_id in {"NOASSERTION", "OTHER", ""}:
        risks.append("license_not_machine_verifiable")
    elif license_id in copyleft:
        risks.append("copyleft_license_review_required")
    if not security_policy:
        risks.append("no_security_policy_detected")

    if data.get("archived") or "no_push_in_over_1_year" in risks:
        recommendation = "AVOID_OR_FORK"
    elif license_id in copyleft or license_id in {"NOASSERTION", "OTHER", ""}:
        recommendation = "ISOLATE_AND_REVIEW_LICENSE"
    elif license_id in permissive:
        recommendation = "ADAPT_AFTER_TECHNICAL_REVIEW"
    else:
        recommendation = "REVIEW"

    result = {
        "repository": f"{owner}/{name}",
        "url": data.get("html_url"),
        "description": data.get("description"),
        "license": license_id,
        "archived": bool(data.get("archived")),
        "fork": bool(data.get("fork")),
        "stars": int(data.get("stargazers_count") or 0),
        "forks": int(data.get("forks_count") or 0),
        "open_issues": int(data.get("open_issues_count") or 0),
        "default_branch": data.get("default_branch"),
        "primary_language": data.get("language"),
        "pushed_at": pushed_at,
        "days_since_push": days_since_push,
        "security_policy": security_policy,
        "ci_workflows": workflows,
        "dockerfile": dockerfile,
        "dependency_manifests": manifests,
        "topics": data.get("topics") or [],
        "risk_flags": risks,
        "recommendation": recommendation,
        "scope_note": (
            "Metadata/licensing/maintenance preflight only; "
            "not a source-code security audit."
        ),
        "cached": False,
    }
    _cache_set(cache_key, result)
    return result


async def defi_yields(
    *,
    chain: str | None = None,
    token: str | None = None,
    min_tvl: float = 0,
    min_apy: float = 0,
    stablecoin_only: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    limit = min(max(limit, 1), 100)
    pools = _cache_get("defi:yields", 60)

    if pools is None:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                "https://yields.llama.fi/pools",
                headers={"User-Agent": "CIPHER-Agent-Tools/1.0"},
            )
            if resp.status_code >= 400:
                raise ToolError(
                    502,
                    f"DefiLlama yields API returned HTTP {resp.status_code}",
                )
            pools = resp.json().get("data", [])
        _cache_set("defi:yields", pools)

    chain_l = chain.lower() if chain else None
    token_u = token.upper() if token else None
    rows = []

    for pool in pools:
        pool_chain = str(pool.get("chain") or "")
        symbol = str(pool.get("symbol") or "")
        tvl = float(pool.get("tvlUsd") or 0)
        apy = float(pool.get("apy") or 0)

        if chain_l and pool_chain.lower() != chain_l:
            continue
        if token_u:
            symbols = {
                item.strip().upper()
                for item in re.split(r"[-/,+ ]+", symbol)
                if item.strip()
            }
            if token_u not in symbols:
                continue
        if tvl < min_tvl or apy < min_apy:
            continue
        if stablecoin_only and not bool(pool.get("stablecoin")):
            continue

        rows.append(
            {
                "pool": pool.get("pool"),
                "chain": pool_chain,
                "project": pool.get("project"),
                "symbol": symbol,
                "tvl_usd": tvl,
                "apy": apy,
                "apy_base": pool.get("apyBase"),
                "apy_reward": pool.get("apyReward"),
                "stablecoin": bool(pool.get("stablecoin")),
                "exposure": pool.get("exposure"),
                "il_risk": pool.get("ilRisk"),
                "pool_meta": pool.get("poolMeta"),
            }
        )

    rows.sort(
        key=lambda row: (row["apy"], row["tvl_usd"]),
        reverse=True,
    )
    return {
        "source": "DefiLlama public yields API",
        "filters": {
            "chain": chain,
            "token": token,
            "min_tvl": min_tvl,
            "min_apy": min_apy,
            "stablecoin_only": stablecoin_only,
        },
        "count": min(len(rows), limit),
        "results": rows[:limit],
        "note": "APY is observational market data, not a recommendation or guarantee.",
    }


async def defi_protocols(
    *,
    chain: str | None = None,
    category: str | None = None,
    min_tvl: float = 0,
    limit: int = 20,
) -> dict[str, Any]:
    limit = min(max(limit, 1), 100)
    protocols = _cache_get("defi:protocols", 120)

    if protocols is None:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                "https://api.llama.fi/protocols",
                headers={"User-Agent": "CIPHER-Agent-Tools/1.0"},
            )
            if resp.status_code >= 400:
                raise ToolError(
                    502,
                    f"DefiLlama protocols API returned HTTP {resp.status_code}",
                )
            protocols = resp.json()
        _cache_set("defi:protocols", protocols)

    chain_l = chain.lower() if chain else None
    category_l = category.lower() if category else None
    rows = []

    for protocol in protocols:
        tvl = float(protocol.get("tvl") or 0)
        chains = [str(item) for item in (protocol.get("chains") or [])]
        protocol_category = str(protocol.get("category") or "")

        if chain_l and chain_l not in {item.lower() for item in chains}:
            continue
        if category_l and protocol_category.lower() != category_l:
            continue
        if tvl < min_tvl:
            continue

        rows.append(
            {
                "name": protocol.get("name"),
                "slug": protocol.get("slug"),
                "symbol": protocol.get("symbol"),
                "category": protocol_category,
                "chains": chains,
                "tvl_usd": tvl,
                "change_1d_pct": protocol.get("change_1d"),
                "change_7d_pct": protocol.get("change_7d"),
                "mcap_usd": protocol.get("mcap"),
                "url": protocol.get("url"),
            }
        )

    rows.sort(key=lambda row: row["tvl_usd"], reverse=True)
    return {
        "source": "DefiLlama public API",
        "filters": {
            "chain": chain,
            "category": category,
            "min_tvl": min_tvl,
        },
        "count": min(len(rows), limit),
        "results": rows[:limit],
    }
