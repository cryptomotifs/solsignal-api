import app as solsignal


def test_openapi_declares_paid_transform_route() -> None:
    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    operation = schema["paths"]["/tools/transform"]["post"]

    payment = operation["x-payment-info"]
    assert payment["price"] == {
        "mode": "fixed",
        "currency": "USD",
        "amount": "0.001000",
    }
    assert payment["protocols"] == [{"x402": {}}]
    assert "402" in operation["responses"]

    body = operation["requestBody"]["content"]["application/json"]["schema"]
    assert set(body["required"]) == {"operation", "value"}


def test_openapi_does_not_mislabel_free_quota_scan_as_always_paid() -> None:
    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    operation = schema["paths"]["/scan/{mint}"]["get"]
    assert "x-payment-info" not in operation


def test_openapi_repo_preflight_has_required_example() -> None:
    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    operation = schema["paths"]["/tools/repo/preflight"]["get"]
    repo = next(
        p for p in operation["parameters"]
        if p["in"] == "query" and p["name"] == "repo"
    )
    assert repo["required"] is True
    assert repo["schema"]["example"] == "openai/openai-agents-python"


def test_openapi_has_agent_guidance() -> None:
    solsignal.app.openapi_schema = None
    schema = solsignal._cipher_openapi()
    assert "x-guidance" in schema["info"]
    assert "x402" in schema["info"]["x-guidance"]
