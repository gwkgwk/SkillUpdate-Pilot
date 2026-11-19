from skillupdate.dynamic_verification import RiskGuidedPlanner


def test_low_risk_skips_execution(low_graph, policy, context, fixture_digests):
    plan = RiskGuidedPlanner().plan(low_graph, policy, context, *fixture_digests)
    assert plan.risk_level == "LOW"
    assert plan.depth == "SKIP"
    assert plan.execution_required is False
    assert plan.selected_event_categories == []


def test_medium_risk_selects_directed_categories(
    medium_graph, policy, context, fixture_digests
):
    plan = RiskGuidedPlanner().plan(medium_graph, policy, context, *fixture_digests)
    assert plan.risk_level == "MEDIUM"
    assert plan.depth == "DIRECTED"
    assert set(plan.selected_event_categories) == {
        "MOCK_TRANSFER_EVENT",
        "NETWORK_EVENT",
        "TOOL_INVOCATION",
    }


def test_high_risk_selects_deep_categories(
    high_graph, policy, context, fixture_digests
):
    plan = RiskGuidedPlanner().plan(high_graph, policy, context, *fixture_digests)
    assert plan.risk_level == "HIGH"
    assert plan.depth == "DEEP"
    assert len(plan.selected_event_categories) == 6
    assert "MOCK_DATA_ACCESS" in plan.selected_event_categories
    assert "PROCESS_CREATION" in plan.selected_event_categories
