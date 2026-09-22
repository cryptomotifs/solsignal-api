from steve_strategy import SentinelPolicy, decision_from_scan


def base_scan(**overrides):
    scan = {
        "mint": "ExampleMint111111111111111111111111111111",
        "symbol": "SAFE",
        "verdict": "SAFE",
        "safety_score": 90,
        "liquidity_usd": 100_000,
        "risk_flags": [],
        "sources": {
            "dexscreener": True,
            "rugcheck": True,
            "goplus": True,
            "jupiter_sim": True,
        },
    }
    scan.update(overrides)
    return scan


def test_safe_candidate_is_approved_with_small_notional():
    result = decision_from_scan(base_scan(), requested_notional_usd=5)
    assert result["decision"] == "APPROVE"
    assert result["eligible_for_execution"] is True
    assert result["reasons"] == ["ALL_SENTINEL_GATES_PASSED"]


def test_critical_flag_blocks_even_with_high_score():
    result = decision_from_scan(
        base_scan(risk_flags=["LP_UNLOCKED"]),
        requested_notional_usd=5,
    )
    assert result["decision"] == "BLOCK"
    assert result["eligible_for_execution"] is False
    assert "CRITICAL_LP_UNLOCKED" in result["reasons"]


def test_caution_is_watch_not_execution():
    result = decision_from_scan(
        base_scan(verdict="CAUTION", safety_score=68),
        requested_notional_usd=5,
    )
    assert result["decision"] == "WATCH"
    assert result["eligible_for_execution"] is False


def test_low_liquidity_blocks():
    result = decision_from_scan(
        base_scan(liquidity_usd=4_000),
        requested_notional_usd=1,
    )
    assert result["decision"] == "BLOCK"
    assert "LIQUIDITY_BELOW_FLOOR" in result["reasons"]


def test_position_size_is_capped_by_liquidity():
    policy = SentinelPolicy(max_notional_usd=25, max_liquidity_share_bps=5)
    result = decision_from_scan(
        base_scan(liquidity_usd=20_000),
        requested_notional_usd=20,
        policy=policy,
    )
    assert result["max_allowed_notional_usd"] == 10.0
    assert result["decision"] == "WATCH"
    assert "REQUESTED_SIZE_ABOVE_POLICY_CAP" in result["reasons"]


def test_scan_error_blocks():
    result = decision_from_scan({"error": "unavailable"}, requested_notional_usd=5)
    assert result["decision"] == "BLOCK"
    assert result["reasons"] == ["SCAN_UNAVAILABLE"]
