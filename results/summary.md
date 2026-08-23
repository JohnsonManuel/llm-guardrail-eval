# Results

Layered defences cut prompt-injection success from **35.0%** to **2.5%** across 120 attacks in six categories, while raising false refusals on legitimate requests from **0.0%** to **15.0%**.

## Ablation

| Layer | Defence added | ASR | FRR | Mean latency |
|---|---|---|---|---|
| L0 | none | 35.0% | 0.0% | 5128ms |
| L1 | + spotlighting | 31.7% | 0.0% | 5116ms |
| L2 | + input scan | 29.2% | 15.0% | 4622ms |
| L3 | + schema/allowlist | 29.2% | 15.0% | 4607ms |
| L4 | + output scan | 8.3% | 15.0% | 4633ms |
| L5 | + tool auth | 2.5% | 15.0% | 4683ms |

## By category

| Category | L0 | L1 | L2 | L3 | L4 | L5 |
|---|---|---|---|---|---|---|
| direct_injection | 52% | 48% | 44% | 44% | 0% | 0% |
| indirect_injection | 10% | 0% | 0% | 0% | 0% | 0% |
| system_prompt_extraction | 40% | 40% | 40% | 40% | 0% | 0% |
| pii_exfiltration | 35% | 40% | 30% | 30% | 20% | 15% |
| tool_hijacking | 35% | 30% | 30% | 30% | 30% | 0% |
| jailbreak | 60% | 60% | 60% | 60% | 0% | 0% |

## Marginal effect of each layer

| Layer | ASR change | FRR change | Verdict |
|---|---|---|---|
| L1 + spotlighting | -3.3% | +0.0% | worth it |
| L2 + input scan | -2.5% | +15.0% | **costs more than it buys** |
| L3 + schema/allowlist | +0.0% | +0.0% | no effect |
| L4 + output scan | -20.8% | +0.0% | worth it |
| L5 + tool auth | -5.8% | +0.0% | worth it |

![heatmap](heatmap.png)
