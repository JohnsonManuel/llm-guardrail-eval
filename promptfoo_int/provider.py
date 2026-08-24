"""Promptfoo custom provider that drives the real Gauntlet stack.

Promptfoo orchestrates; our code executes. This is deliberate: a second,
independent reimplementation of the agent inside a YAML file would be a
different system, and agreement between the two would prove nothing.

Promptfoo calls `call_api` once per test case. The case id arrives through
vars, and the provider config selects the defence layer and model.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from graders.verdict import grade_attack  # noqa: E402
from runner.run import execute  # noqa: E402

_CASES: dict[str, dict] | None = None


def _cases() -> dict[str, dict]:
    global _CASES
    if _CASES is None:
        rows = []
        for name in ("corpus.jsonl", "benign.jsonl"):
            path = ROOT / "attacks" / name
            rows += [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        _CASES = {r["id"]: r for r in rows}
    return _CASES


def call_api(prompt, options, context):
    config = (options or {}).get("config", {}) or {}
    layer = config.get("layer", "L5")
    model = config.get("model", "qwen3.5:4b")

    case_id = (context or {}).get("vars", {}).get("case_id")
    case = _cases().get(case_id)
    if case is None:
        return {"error": f"unknown case_id {case_id!r}"}

    result, events = execute(case, layer, model)
    if result.error:
        return {"error": result.error}

    verdict = grade_attack(case, result) if "expected_violation" in case else None

    # Promptfoo asserts on `output`. Emitting the verdict as structured JSON
    # keeps the assertion trivial and identical to the runner's own grading.
    return {
        "output": json.dumps(
            {
                "case_id": case_id,
                "category": case["category"],
                "technique": case.get("technique"),
                "violated": bool(verdict and verdict.violated),
                "detail": verdict.detail if verdict else "",
                "tool_calls": [tc.name for tc in result.tool_calls],
                "blocked_calls": [tc.name for tc, _ in result.blocked_calls],
                "defense_events": events,
            }
        ),
        "metadata": {
            "violated": bool(verdict and verdict.violated),
            "category": case["category"],
            "layer": layer,
        },
    }
