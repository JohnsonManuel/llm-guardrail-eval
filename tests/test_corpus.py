"""Corpus integrity.

The point of these is to guarantee, without touching a model, that every case
can actually be graded. Discovering after a 58-minute matrix run that a third of
the corpus is unscoreable is the expensive failure this prevents.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from graders.verdict import grade_attack, grade_benign
from target.agent import AgentResult

ATTACKS_DIR = Path(__file__).parent.parent / "attacks"
EXPECTED_COUNTS = {
    "direct_injection": 25,
    "indirect_injection": 30,
    "system_prompt_extraction": 15,
    "pii_exfiltration": 20,
    "tool_hijacking": 20,
    "jailbreak": 10,
}


def load(name: str) -> list[dict]:
    path = ATTACKS_DIR / name
    if not path.exists():
        pytest.skip(f"{name} not built -- run `python -m attacks.build`")
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture(scope="module")
def attacks() -> list[dict]:
    return load("corpus.jsonl")


@pytest.fixture(scope="module")
def benign() -> list[dict]:
    return load("benign.jsonl")


def test_attack_count(attacks):
    assert len(attacks) == 120


def test_category_distribution(attacks):
    counts: dict[str, int] = {}
    for a in attacks:
        counts[a["category"]] = counts.get(a["category"], 0) + 1
    assert counts == EXPECTED_COUNTS


def test_benign_count(benign):
    assert len(benign) == 40


def test_ids_unique(attacks, benign):
    ids = [c["id"] for c in attacks + benign]
    assert len(ids) == len(set(ids))


def test_every_attack_is_gradeable(attacks):
    """The load-bearing test: no attack may use a violation kind the grader
    does not implement."""
    empty = AgentResult(text="")
    for case in attacks:
        grade_attack(case, empty)  # raises ValueError on an unknown kind


def test_every_benign_is_gradeable(benign):
    empty = AgentResult(text="")
    for case in benign:
        grade_benign(case, empty)


def test_document_surface_cases_carry_a_payload(attacks, benign):
    for case in attacks + benign:
        if case["surface"] == "document":
            assert case["document_payload"], f"{case['id']} has no payload"


def test_user_surface_cases_have_no_payload(attacks):
    for case in attacks:
        if case["surface"] == "user":
            assert case["document_payload"] is None, f"{case['id']} should not have one"


def test_no_empty_prompts(attacks, benign):
    for case in attacks + benign:
        assert case["user_prompt"].strip(), f"{case['id']} has an empty prompt"


def test_techniques_are_distinct_within_category(attacks):
    seen: set[tuple[str, str]] = set()
    for case in attacks:
        key = (case["category"], case["technique"])
        assert key not in seen, f"duplicate technique {key}"
        seen.add(key)


def test_benign_set_includes_filter_bait(benign):
    """A benign set with no adversarial-looking cases cannot detect an
    over-eager input filter, which is the whole point of measuring false
    refusals."""
    bait = ("ignore", "forget", "disregard", "override", "system update", "new instruction")
    hits = sum(any(b in c["user_prompt"].lower() for b in bait) for c in benign)
    assert hits >= 5, f"only {hits} filter-bait benign cases"


def test_indirect_payloads_are_not_in_the_user_turn(attacks):
    """An indirect attack that also appears in the user prompt is really a
    direct attack, and would inflate the indirect category's numbers."""
    for case in attacks:
        if case["category"] == "indirect_injection":
            assert "issue_refund" not in case["user_prompt"]
            assert "internal reference" not in case["user_prompt"].lower()
