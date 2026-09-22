from __future__ import annotations

import pytest

import app as solsignal


@pytest.mark.asyncio
async def test_x402scan_registration_posts_public_origin(monkeypatch, capsys) -> None:
    calls = []

    class FakeResponse:
        status_code = 200
        text = ""

        def json(self):
            return {
                "result": {
                    "data": {
                        "json": {
                            "success": True,
                            "registered": 8,
                            "failed": 0,
                            "total": 8,
                            "source": "openapi",
                        }
                    }
                }
            }

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, *, json, headers):
            calls.append((url, json, headers))
            return FakeResponse()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(solsignal, "X402SCAN_AUTO_REGISTER", True)
    monkeypatch.setattr(
        solsignal,
        "PUBLIC_BASE_URL",
        "https://solsignal-api.onrender.com",
    )
    monkeypatch.setattr(
        solsignal,
        "X402SCAN_REGISTER_URL",
        "https://x402scan.com/api/trpc/public.resources.registerFromOrigin",
    )

    await solsignal._register_x402scan_origin()

    assert calls == [(
        "https://x402scan.com/api/trpc/public.resources.registerFromOrigin",
        {"json": {"origin": "https://solsignal-api.onrender.com"}},
        {
            "User-Agent": "CIPHER-Agent-Tools/1.0",
            "Content-Type": "application/json",
        },
    )]
    output = capsys.readouterr().out
    assert '"event": "x402scan_registration"' in output
    assert '"ok": true' in output


@pytest.mark.asyncio
async def test_x402scan_registration_defaults_to_disabled(monkeypatch) -> None:
    monkeypatch.setattr(solsignal, "X402SCAN_AUTO_REGISTER", False)
    await solsignal._register_x402scan_origin()
