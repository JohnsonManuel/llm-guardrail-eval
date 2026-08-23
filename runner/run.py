"""Matrix runner: layers x models x cases.

Caches every result keyed on (case, layer, model, prompt) and resumes from the
cache on restart. A full matrix is ~960 model calls at ~3.7s, so a crash at
minute 50 must not cost the run.

    python -m runner.run --layer L0
    python -m runner.run --layer L0 --limit 10        # smoke it first
    python -m runner.run --layer L0 --no-cache        # force a fresh run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path

from defenses import Blocked, Context, LAYERS
from graders.verdict import grade_attack, grade_benign
from target.agent import AgentResult, run as run_agent
from target import tools

ROOT = Path(__file__).parent.parent
CACHE_DIR = ROOT / ".cache"
RESULTS_DIR = ROOT / "results"
ATTACKS_DIR = ROOT / "attacks"


def load_cases() -> tuple[list[dict], list[dict]]:
    def read(name: str) -> list[dict]:
        path = ATTACKS_DIR / name
        if not path.exists():
            raise SystemExit(f"{path} missing -- run `python -m attacks.build` first")
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]

    return read("corpus.jsonl"), read("benign.jsonl")


def cache_key(case: dict, layer: str, model: str) -> str:
    blob = json.dumps(
        {
            "id": case["id"],
            "prompt": case["user_prompt"],
            "payload": case.get("document_payload"),
            "layer": layer,
            "model": model,
        },
        sort_keys=True,
    )
    return hashlib.sha256(blob.encode()).hexdigest()[:20]


def execute(case: dict, layer: str, model: str) -> tuple[AgentResult, list[str]]:
    """Run one case through the given defence stack."""
    ctx = Context(
        user_prompt=case["user_prompt"],
        document_payload=case.get("document_payload"),
        system_prompt=tools.SYSTEM_PROMPT,
    )

    for defense in LAYERS[layer]:
        outcome = defense.pre(ctx)
        if isinstance(outcome, Blocked):
            # Blocked before reaching the model: no violation possible, but it
            # counts as a refusal, which is what the benign set measures.
            blocked = AgentResult(text=f"[blocked by {outcome.layer}] {outcome.reason}")
            blocked.defense_events = ctx.events + [f"{outcome.layer}:blocked"]
            return blocked, blocked.defense_events
        ctx = outcome

    result = run_agent(
        ctx.user_prompt,
        model=model,
        document_payload=ctx.document_payload,
        system_prompt=ctx.system_prompt,
    )

    for defense in LAYERS[layer]:
        outcome = defense.post(ctx, result)
        if isinstance(outcome, Blocked):
            result.text = f"[blocked by {outcome.layer}] {outcome.reason}"
            ctx.events.append(f"{outcome.layer}:blocked")
        elif outcome is not None:
            result = outcome

    result.defense_events = ctx.events
    return result, ctx.events


def run_case(case: dict, layer: str, model: str, use_cache: bool) -> dict:
    key = cache_key(case, layer, model)
    cached = CACHE_DIR / f"{key}.json"
    if use_cache and cached.exists():
        row = json.loads(cached.read_text())
        row["cached"] = True
        return row

    result, events = execute(case, layer, model)
    is_attack = "expected_violation" in case
    verdict = (grade_attack if is_attack else grade_benign)(case, result)

    row = {
        "id": case["id"],
        "category": case["category"],
        "technique": case.get("technique"),
        "surface": case["surface"],
        "severity": case.get("severity"),
        "layer": layer,
        "model": model,
        "is_attack": is_attack,
        "violated": verdict.violated,
        "handled": verdict.handled,
        "refused": verdict.refused,
        "detail": verdict.detail,
        "latency_ms": round(result.latency_ms, 1),
        "tokens_in": result.tokens_in,
        "tokens_out": result.tokens_out,
        "tool_calls": [asdict(tc) for tc in result.tool_calls],
        "text": (result.text or "")[:600],
        "error": result.error,
        "defense_events": events,
        "cached": False,
    }
    CACHE_DIR.mkdir(exist_ok=True)
    cached.write_text(json.dumps(row))
    return row


def summarise(rows: list[dict]) -> dict:
    attacks = [r for r in rows if r["is_attack"]]
    benign = [r for r in rows if not r["is_attack"]]
    errors = [r for r in rows if r["error"]]

    landed = sum(r["violated"] for r in attacks)
    served = sum(r["handled"] for r in benign)

    per_category: dict[str, dict] = {}
    for r in attacks:
        bucket = per_category.setdefault(r["category"], {"n": 0, "landed": 0})
        bucket["n"] += 1
        bucket["landed"] += r["violated"]
    for bucket in per_category.values():
        bucket["asr"] = bucket["landed"] / bucket["n"]

    return {
        "n_attacks": len(attacks),
        "n_benign": len(benign),
        "asr": landed / len(attacks) if attacks else 0.0,
        "frr": 1 - (served / len(benign)) if benign else 0.0,
        "errors": len(errors),
        "mean_latency_ms": round(sum(r["latency_ms"] for r in rows) / len(rows), 1) if rows else 0,
        "per_category": per_category,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layer", default="L0", choices=list(LAYERS))
    ap.add_argument("--model", default="qwen3.5:4b")
    ap.add_argument("--limit", type=int, default=0, help="cases per set, for smoke runs")
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args()

    attacks, benign = load_cases()
    if args.limit:
        attacks, benign = attacks[: args.limit], benign[: args.limit]
    cases = attacks + benign

    print(f"layer {args.layer}  model {args.model}  {len(cases)} cases\n")
    rows, started, hits = [], time.perf_counter(), 0

    for i, case in enumerate(cases, 1):
        row = run_case(case, args.layer, args.model, not args.no_cache)
        rows.append(row)

        if row["is_attack"]:
            mark = "LANDED" if row["violated"] else "  --  "
            hits += row["violated"]
        else:
            mark = "  ok  " if row["handled"] else "REFUSED"

        tag = "c" if row["cached"] else " "
        elapsed = time.perf_counter() - started
        eta = (elapsed / i) * (len(cases) - i)
        print(
            f"  [{i:3}/{len(cases)}]{tag} {mark} {row['id']:9} {row['category'][:22]:22}"
            f" {row['technique'] or '':22} eta {eta/60:4.1f}m"
        )

    summary = summarise(rows)
    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"{args.layer}_{args.model.replace(':', '-').replace('.', '')}.json"
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))

    print(f"\n{'='*64}")
    print(f"  attack success rate (ASR)   {summary['asr']:.1%}  ({summary['n_attacks']} attacks)")
    print(f"  false refusal rate  (FRR)   {summary['frr']:.1%}  ({summary['n_benign']} benign)")
    print(f"  errors                      {summary['errors']}")
    print(f"  mean latency                {summary['mean_latency_ms']:.0f}ms")
    print(f"\n  by category:")
    for category, bucket in sorted(
        summary["per_category"].items(), key=lambda kv: -kv[1]["asr"]
    ):
        bar = "#" * round(bucket["asr"] * 30)
        print(f"    {category:26} {bucket['asr']:5.1%}  {bucket['landed']:2}/{bucket['n']:2} {bar}")
    print(f"\n  written to {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
