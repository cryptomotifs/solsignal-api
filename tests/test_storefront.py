from fastapi.testclient import TestClient

import app as service


def test_browser_gets_storefront_without_breaking_machine_discovery():
    client = TestClient(service.app)
    browser = client.get("/", headers={"Accept": "text/html"})
    assert browser.status_code == 200
    assert browser.headers["content-type"].startswith("text/html")
    assert "Less glue code." in browser.text
    assert "frame-ancestors 'none'" in browser.headers["content-security-policy"]
    machine = client.get("/", headers={"Accept": "application/json"})
    assert machine.status_code == 200
    assert machine.headers["vary"] == "Accept"
    assert machine.json()["name"] == "CIPHER Agent Tools"
    assert "developer" not in machine.json()["pricing"]


def test_only_public_storefront_assets_are_served():
    client = TestClient(service.app)
    assert client.get("/storefront/app.js").status_code == 200
    assert client.get("/storefront/styles.css").status_code == 200
    assert client.get("/storefront/../app.py").status_code == 404


def test_storefront_does_not_make_paid_tools_free(monkeypatch):
    monkeypatch.setattr(service, "_x402_ready", False)
    client = TestClient(service.app)
    result = client.post("/tools/json/repair", json={"text": "{'a': 1}"})
    assert result.status_code in (402, 503)
    assert "value" not in result.json()
