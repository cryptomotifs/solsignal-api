import app as solsignal


def test_well_known_manifest_has_machine_readable_resources() -> None:
    manifest = solsignal._x402_manifest_payload()
    assert manifest["name"] == "CIPHER Agent Tools"
    assert manifest["payTo"] == solsignal.SOLANA_WALLET
    resources = manifest["resources"]
    assert resources
    assert all(isinstance(item, dict) for item in resources)
    transform = next(item for item in resources if item["path"] == "/tools/transform")
    assert transform["method"] == "POST"
    assert transform["amount"] == "1000"
    assert transform["description"]
    assert transform["url"].startswith(solsignal.PUBLIC_BASE_URL)


def test_bazaar_extension_describes_post_body() -> None:
    extensions = solsignal._bazaar_extensions("/tools/transform", "tool_transform")
    bazaar = extensions["bazaar"]
    assert bazaar["info"]["input"]["method"] == "POST"
    assert bazaar["info"]["input"]["body"]["operation"] == "sha256"
    required = bazaar["schema"]["properties"]["input"]["properties"]["body"]["required"]
    assert "operation" in required
    assert "value" in required


def test_bazaar_extension_describes_dynamic_route() -> None:
    extensions = solsignal._bazaar_extensions("/scan/example-mint", "scan")
    bazaar = extensions["bazaar"]
    assert bazaar["info"]["input"]["method"] == "GET"
    assert bazaar["info"]["input"]["pathParams"]["mint"] == "example-mint"
    assert bazaar["routeTemplate"] == "/scan/:mint"
