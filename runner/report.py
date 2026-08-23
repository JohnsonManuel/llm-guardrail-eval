"""Turn results/*.json into the tables and the heatmap.

Nothing here is hand-written -- every number traces to a result file.

    python -m runner.report
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
LAYER_ORDER = ["L0", "L1", "L2", "L3", "L4", "L5"]
LAYER_LABEL = {
    "L0": "none",
    "L1": "+ spotlighting",
    "L2": "+ input scan",
    "L3": "+ schema/allowlist",
    "L4": "+ output scan",
    "L5": "+ tool auth",
}
CATEGORIES = [
    "direct_injection",
    "indirect_injection",
    "system_prompt_extraction",
    "pii_exfiltration",
    "tool_hijacking",
    "jailbreak",
]


def load(model_slug: str = "qwen35-4b") -> dict[str, dict]:
    out = {}
    for layer in LAYER_ORDER:
        path = RESULTS / f"{layer}_{model_slug}.json"
        if path.exists():
            out[layer] = json.loads(path.read_text())
    return out


def headline(data: dict) -> str:
    if "L0" not in data or "L5" not in data:
        return "_(run all layers to generate the headline)_"
    a0, a5 = data["L0"]["summary"], data["L5"]["summary"]
    return (
        f"Layered defences cut prompt-injection success from **{a0['asr']:.1%}** "
        f"to **{a5['asr']:.1%}** across {a0['n_attacks']} attacks in six "
        f"categories, while raising false refusals on legitimate requests from "
        f"**{a0['frr']:.1%}** to **{a5['frr']:.1%}**."
    )


def main_table(data: dict) -> str:
    lines = [
        "| Layer | Defence added | ASR | FRR | Mean latency |",
        "|---|---|---|---|---|",
    ]
    for layer in LAYER_ORDER:
        if layer not in data:
            continue
        s = data[layer]["summary"]
        lines.append(
            f"| {layer} | {LAYER_LABEL[layer]} | {s['asr']:.1%} | "
            f"{s['frr']:.1%} | {s['mean_latency_ms']:.0f}ms |"
        )
    return "\n".join(lines)


def category_table(data: dict) -> str:
    header = "| Category | " + " | ".join(l for l in LAYER_ORDER if l in data) + " |"
    sep = "|---" * (1 + len([l for l in LAYER_ORDER if l in data])) + "|"
    lines = [header, sep]
    for category in CATEGORIES:
        cells = []
        for layer in LAYER_ORDER:
            if layer not in data:
                continue
            bucket = data[layer]["summary"]["per_category"].get(category)
            cells.append(f"{bucket['asr']:.0%}" if bucket else "-")
        lines.append(f"| {category} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def marginal_table(data: dict) -> str:
    """What each layer bought, and what it cost. The interesting table."""
    lines = [
        "| Layer | ASR change | FRR change | Verdict |",
        "|---|---|---|---|",
    ]
    previous = None
    for layer in LAYER_ORDER:
        if layer not in data:
            continue
        s = data[layer]["summary"]
        if previous is None:
            previous = s
            continue
        d_asr = s["asr"] - previous["asr"]
        d_frr = s["frr"] - previous["frr"]
        if d_asr < -0.001 and d_frr <= 0.001:
            verdict = "worth it"
        elif d_asr < -0.001 and abs(d_asr) > d_frr:
            verdict = "net positive"
        elif d_asr >= -0.001 and d_frr > 0.001:
            verdict = "**not worth it**"
        elif abs(d_asr) < 0.001:
            verdict = "no effect"
        else:
            verdict = "**costs more than it buys**"
        lines.append(
            f"| {layer} {LAYER_LABEL[layer]} | {d_asr:+.1%} | {d_frr:+.1%} | {verdict} |"
        )
        previous = s
    return "\n".join(lines)


def heatmap(data: dict, path: Path) -> bool:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        return False

    layers = [l for l in LAYER_ORDER if l in data]
    grid = np.array(
        [
            [
                (data[l]["summary"]["per_category"].get(c) or {"asr": 0})["asr"]
                for l in layers
            ]
            for c in CATEGORIES
        ]
    )

    fig, ax = plt.subplots(figsize=(1.15 * len(layers) + 3.4, 0.62 * len(CATEGORIES) + 1.9))
    im = ax.imshow(grid, cmap="RdYlGn_r", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(layers)))
    ax.set_xticklabels([f"{l}\n{LAYER_LABEL[l]}" for l in layers], fontsize=8)
    ax.set_yticks(range(len(CATEGORIES)))
    ax.set_yticklabels([c.replace("_", " ") for c in CATEGORIES], fontsize=9)

    # Values printed in-cell: colour alone must not carry the meaning.
    for i in range(len(CATEGORIES)):
        for j in range(len(layers)):
            value = grid[i, j]
            ax.text(
                j, i, f"{value:.0%}",
                ha="center", va="center", fontsize=9,
                family="monospace",
                color="white" if value > 0.55 or value < 0.08 else "black",
            )

    ax.set_title("Attack success rate by category and defence layer", fontsize=11, pad=12)
    ax.set_xticks(np.arange(len(layers) + 1) - 0.5, minor=True)
    ax.set_yticks(np.arange(len(CATEGORIES) + 1) - 0.5, minor=True)
    ax.grid(which="minor", color="white", linewidth=1.5)
    ax.tick_params(which="minor", length=0)
    fig.colorbar(im, ax=ax, label="attack success rate", shrink=0.75)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    return True


def main() -> int:
    data = load()
    if not data:
        raise SystemExit("no results -- run `python -m runner.run --layer L0` first")

    print(headline(data), "\n")
    print(main_table(data), "\n")
    print("Per category:\n")
    print(category_table(data), "\n")
    print("What each layer bought:\n")
    print(marginal_table(data), "\n")

    out = RESULTS / "heatmap.png"
    print(f"heatmap: {out.relative_to(ROOT)}" if heatmap(data, out) else "heatmap: skipped (no matplotlib)")

    (RESULTS / "summary.md").write_text(
        "\n\n".join(
            [
                "# Results",
                headline(data),
                "## Ablation",
                main_table(data),
                "## By category",
                category_table(data),
                "## Marginal effect of each layer",
                marginal_table(data),
                "![heatmap](heatmap.png)",
            ]
        )
        + "\n"
    )
    print("wrote results/summary.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
