from typing import Any

from tracewarden.detectors.base import ScanContext
from tracewarden.detectors.cost_loop import CostLoopDetector
from tracewarden.detectors.sequence import SequenceDetector
from tracewarden.schema import EventType, Surface


def tool_ctx(text: str, tool: str, state: dict[str, Any]) -> ScanContext:
    return ScanContext(
        surface=Surface.TOOL_INPUT, text=text, meta={"tool_name": tool}, trace_state=state
    )


def prompt_ctx(text: str, state: dict[str, Any]) -> ScanContext:
    return ScanContext(surface=Surface.USER_PROMPT, text=text, trace_state=state)


def test_repeated_identical_call_flagged_once() -> None:
    detector = SequenceDetector(repeat_threshold=3)
    state: dict[str, Any] = {}
    events = []
    for _ in range(5):
        events.extend(detector.scan(tool_ctx('{"q": "x"}', "search", state)))
    flagged = [e for e in events if e.rule == "repeated_identical_call"]
    assert len(flagged) == 1  # deduped per trace
    assert flagged[0].type is EventType.ANOMALOUS_SEQUENCE


def test_distinct_inputs_do_not_trip_repeat() -> None:
    detector = SequenceDetector(repeat_threshold=3)
    state: dict[str, Any] = {}
    events = []
    for i in range(5):
        events.extend(detector.scan(tool_ctx(f'{{"q": "{i}"}}', "search", state)))
    assert not [e for e in events if e.rule == "repeated_identical_call"]


def test_ping_pong_detected() -> None:
    detector = SequenceDetector(repeat_threshold=99)
    state: dict[str, Any] = {}
    events = []
    for tool in ["a", "b", "a", "b"]:
        events.extend(detector.scan(tool_ctx('{"n": 1}', tool, state)))
    assert any(e.rule == "tool_ping_pong" for e in events)


def test_tool_fanout_detected() -> None:
    detector = SequenceDetector(repeat_threshold=99, fanout_threshold=5)
    state: dict[str, Any] = {}
    events = []
    for i in range(7):
        events.extend(detector.scan(tool_ctx('{"n": 1}', f"tool_{i}", state)))
    assert any(e.rule == "tool_fanout" for e in events)


def test_cost_budget_exceeded() -> None:
    detector = CostLoopDetector(llm_call_budget=3, repeat_threshold=99)
    state: dict[str, Any] = {}
    events = []
    for i in range(5):
        events.extend(detector.scan(prompt_ctx(f"question {i}", state)))
    cost = [e for e in events if e.type is EventType.COST_ANOMALY]
    assert len(cost) == 1
    assert cost[0].rule == "llm_call_budget_exceeded"


def test_repeated_prompt_loop() -> None:
    detector = CostLoopDetector(llm_call_budget=99, repeat_threshold=3)
    state: dict[str, Any] = {}
    events = []
    for _ in range(4):
        events.extend(detector.scan(prompt_ctx("same prompt every time", state)))
    loops = [e for e in events if e.type is EventType.LOOP_ANOMALY]
    assert len(loops) == 1


def test_cost_only_counts_user_prompts() -> None:
    detector = CostLoopDetector(llm_call_budget=1, repeat_threshold=99)
    state: dict[str, Any] = {}
    events = detector.scan(ScanContext(surface=Surface.COMPLETION, text="x", trace_state=state))
    assert events == []
