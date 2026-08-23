"""Bootstrap confidence intervals and paired significance tests.

Single-run point estimates invite over-reading. At n=120, a 2.5-point ASR
difference is roughly three cases -- possibly noise. This module says so
explicitly rather than leaving the reader to assume every delta is real.

Uses McNemar's test for paired layer comparisons, since the same cases run
against every layer.

    python -m runner.stats
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
LAYER_ORDER = ["L0", "L1", "L2", "L3", "L4", "L5"]
N_BOOT = 10_000
SEED = 42


def load(slug: str = "qwen35-4b") -> dict[str, dict]:
    out = {}
    for layer in LAYER_ORDER:
        path = RESULTS / f"{layer}_{slug}.json"
        if path.exists():
            out[layer] = json.loads(path.read_text())
    return out


def bootstrap_ci(flags: list[bool], n: int = N_BOOT, alpha: float = 0.05) -> tuple[float, float]:
    """Percentile bootstrap CI for a proportion."""
    if not flags:
        return (0.0, 0.0)
    rng = random.Random(SEED)
    k = len(flags)
    means = sorted(
        sum(flags[rng.randrange(k)] for _ in range(k)) / k for _ in range(n)
    )
    lo = means[int((alpha / 2) * n)]
    hi = means[int((1 - alpha / 2) * n) - 1]
    return (lo, hi)


def mcnemar_exact(a: list[bool], b: list[bool]) -> tuple[int, int, float]:
    """Exact two-sided McNemar test on paired binary outcomes.

    Returns (b01, b10, p). b01 = cases a=0,b=1; b10 = cases a=1,b=0.
    Only discordant pairs carry information.
    """
    b01 = sum(1 for x, y in zip(a, b) if not x and y)
    b10 = sum(1 for x, y in zip(a, b) if x and not y)
    n = b01 + b10
    if n == 0:
        return (0, 0, 1.0)

    # Exact binomial tail at p=0.5, doubled for two-sided.
    from math import comb

    k = min(b01, b10)
    tail = sum(comb(n, i) for i in range(k + 1)) / (2 ** n)
    return (b01, b10, min(1.0, 2 * tail))


def main() -> int:
    data = load()
    if len(data) < 2:
        raise SystemExit("need at least two layers -- run the ablation first")

    print(f"Bootstrap {N_BOOT:,} resamples, seed {SEED}, 95% percentile CIs.\n")

    # Keep case order aligned across layers so pairing is valid.
    series: dict[str, dict[str, bool]] = {}
    benign: dict[str, dict[str, bool]] = {}
    for layer, blob in data.items():
        series[layer] = {r["id"]: r["violated"] for r in blob["rows"] if r["is_attack"]}
        benign[layer] = {r["id"]: not r["handled"] for r in blob["rows"] if not r["is_attack"]}

    attack_ids = sorted(set.intersection(*(set(s) for s in series.values())))
    benign_ids = sorted(set.intersection(*(set(s) for s in benign.values())))

    print("| Layer | ASR | 95% CI | FRR | 95% CI |")
    print("|---|---|---|---|---|")
    for layer in LAYER_ORDER:
        if layer not in data:
            continue
        a = [series[layer][i] for i in attack_ids]
        f = [benign[layer][i] for i in benign_ids]
        alo, ahi = bootstrap_ci(a)
        flo, fhi = bootstrap_ci(f)
        print(
            f"| {layer} | {sum(a)/len(a):.1%} | [{alo:.1%}, {ahi:.1%}] | "
            f"{sum(f)/len(f):.1%} | [{flo:.1%}, {fhi:.1%}] |"
        )

    print("\nPaired McNemar tests, each layer vs the one before:\n")
    print("| Comparison | discordant | p | significant at 0.05 |")
    print("|---|---|---|---|")
    present = [l for l in LAYER_ORDER if l in data]
    for prev, curr in zip(present, present[1:]):
        a = [series[prev][i] for i in attack_ids]
        b = [series[curr][i] for i in attack_ids]
        b01, b10, p = mcnemar_exact(a, b)
        verdict = "**yes**" if p < 0.05 else "no"
        print(f"| ASR {prev} -> {curr} | {b10}+/{b01}- | {p:.4f} | {verdict} |")

    for prev, curr in zip(present, present[1:]):
        a = [benign[prev][i] for i in benign_ids]
        b = [benign[curr][i] for i in benign_ids]
        b01, b10, p = mcnemar_exact(a, b)
        if b01 or b10:
            verdict = "**yes**" if p < 0.05 else "no"
            print(f"| FRR {prev} -> {curr} | {b01}+/{b10}- | {p:.4f} | {verdict} |")

    print(
        "\nRead this before quoting any single-layer delta: a change that is not "
        "significant here is not evidence that the layer helped."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
