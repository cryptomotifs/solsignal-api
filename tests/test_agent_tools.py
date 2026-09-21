from agent_tools import ReadableHTML, _parse_repo, repair_json


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
