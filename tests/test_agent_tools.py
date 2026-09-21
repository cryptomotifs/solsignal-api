from agent_tools import ReadableHTML, _parse_repo, repair_json, transform_value


def test_json_repair_common_llm_output() -> None:
    output = repair_json("""```json
{'a': 1, 'b': [2, 3,],}
```""")
    assert output["valid"] is True
    assert output["value"] == {"a": 1, "b": [2, 3]}


def test_html_reader_extracts_heading_and_link() -> None:
    parser = ReadableHTML("https://example.com/base")
    parser.feed(
        '<html><head><title>Example</title></head>'
        '<body><h1>Hello</h1><p>World</p><a href="/docs">Docs</a></body></html>'
    )
    assert parser.title == "Example"
    assert "# Hello" in parser.markdown()
    assert parser.links[0]["url"] == "https://example.com/docs"


def test_repo_parser_accepts_github_url() -> None:
    assert _parse_repo(
        "https://github.com/openai/openai-agents-python"
    ) == ("openai", "openai-agents-python")


def test_transform_value_hash_and_base64() -> None:
    hashed = transform_value("sha256", "hello")
    assert hashed["result"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    encoded = transform_value("base64_encode", "hello")
    assert encoded["result"] == "aGVsbG8="

    decoded = transform_value("base64_decode", encoded["result"])
    assert decoded["result"] == "hello"


def test_transform_value_jwt_decode_does_not_claim_verification() -> None:
    token = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiJhZ2VudC0xMjMifQ."
    )
    result = transform_value("jwt_decode", token)
    assert result["payload"]["sub"] == "agent-123"
    assert result["verified"] is False
