"""Promptfoo and the native runner must agree, case by case.

Both paths drive the same agent and the same graders, so this is not testing
whether two implementations happen to match -- it is guarding against the
integration silently drifting: a stale generated config, a provider that stops
passing `case_id`, an assertion inverted.

An aggregate-only check would pass while individual verdicts disagreed, so this
compares per case.

Regenerate the artifacts with:

    python -m promptfoo_int.build_config --layer L5 --limit 24
    npx promptfoo eval -c promptfooconfig.yaml --output results/promptfoo.json --no-cache
    python -m runner.run --layer L5 --limit 24
    cp results/L5_qwen35-4b.json results/parity_L5_qwen35-4b.json
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

RESULTS = Path(__file__).parent.parent / "results"
PROMPTFOO = RESULTS / "promptfoo.json"
NATIVE = RESULTS / "parity_L5_qwen35-4b.json"


def _promptfoo_verdicts() -> dict[str, bool]:
    """case_id -> did the attack land, per promptfoo."""
    if not PROMPTFOO.exists():
        pytest.skip("results/promptfoo.json not present -- run the promptfoo eval")
    blob = json.loads(PROMPTFOO.read_text())
    results = blob.get("results", {}).get("results", blob.get("results", []))

    verdicts: dict[str, bool] = {}
    for row in results:
        raw = row.get("response", {}).get("output") or row.get("output")
        if not raw:
            continue
        payload = json.loads(raw) if isinstance(raw, str) else raw
        verdicts[payload["case_id"]] = bool(payload["violated"])
    return verdicts


def _native_verdicts() -> dict[str, bool]:
    if not NATIVE.exists():
        pytest.skip("results/parity_L5_qwen35-4b.json not present")
    blob = json.loads(NATIVE.read_text())
    return {r["id"]: bool(r["violated"]) for r in blob["rows"] if r["is_attack"]}


def test_both_paths_cover_the_same_cases():
    p, n = _promptfoo_verdicts(), _native_verdicts()
    assert p, "promptfoo produced no parseable verdicts"
    assert set(p) == set(n), (
        f"case mismatch -- only in promptfoo: {sorted(set(p) - set(n))}, "
        f"only in runner: {sorted(set(n) - set(p))}"
    )


def test_verdicts_agree_case_by_case():
    p, n = _promptfoo_verdicts(), _native_verdicts()
    disagreements = {k: (p[k], n[k]) for k in p if k in n and p[k] != n[k]}
    assert not disagreements, f"promptfoo vs runner disagree on {disagreements}"


def test_attack_success_rates_match():
    p, n = _promptfoo_verdicts(), _native_verdicts()
    p_asr = sum(p.values()) / len(p)
    n_asr = sum(n.values()) / len(n)
    assert p_asr == pytest.approx(n_asr), f"promptfoo {p_asr:.1%} vs runner {n_asr:.1%}"


def test_generated_config_matches_the_corpus():
    """The config is generated, not hand-maintained. If the corpus changed
    without regenerating, the suites are no longer testing the same thing."""
    config = Path(__file__).parent.parent / "promptfooconfig.yaml"
    if not config.exists():
        pytest.skip("promptfooconfig.yaml not generated")
    text = config.read_text()
    for case_id in _promptfoo_verdicts():
        assert f"case_id: {case_id}" in text, f"{case_id} missing from generated config"
