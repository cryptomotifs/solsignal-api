from __future__ import annotations

import pytest

import app as solsignal


@pytest.mark.asyncio
async def test_agent402_registration_posts_only_public_origin(monkeypatch) -> None:
    calls = []

    class FakeResponse:
        status_code = 200

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, *, json, headers):
            calls.append((url, json, headers))
            return FakeResponse()

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            self.client = FakeClient()
            return self.client

        async def __aexit__(self, exc_type, exc, tb):
            return None

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(solsignal, "AGENT402_AUTO_REGISTER", True)
    monkeypatch.setattr(
        solsignal,
        "PUBLIC_BASE_URL",
        "https://solsignal-api.onrender.com",
    )
    monkeypatch.setattr(
        solsignal,
        "AGENT402_REGISTER_URL",
        "https://agent402.tools/api/index/register",
    )

    await solsignal._register_agent402_origin()

    assert len(calls) == 1
    url, payload, headers = calls[0]
    assert url == "https://agent402.tools/api/index/register"
    assert payload == {"origin": "https://solsignal-api.onrender.com"}
    assert headers["User-Agent"] == "CIPHER-Agent-Tools/1.0"


@pytest.mark.asyncio
async def test_agent402_registration_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setattr(solsignal, "AGENT402_AUTO_REGISTER", False)
    await solsignal._register_agent402_origin()
