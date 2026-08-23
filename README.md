# Gauntlet

A red-team evaluation harness for LLM applications: documented attacks,
deterministic graders, layered defences, and honest before/after numbers —
including what the defences cost in false refusals.

**Status:** Phase 1 — target agent and model gate. Not yet publishable.

## Model gate

Before any attack is written, the model must prove it can call tools at all.
If it cannot, every attack number afterwards is noise: "the defence worked" and
"the model was bad at tools" become indistinguishable.

Bar: >=90% correct tool selection on 20 plain, non-adversarial requests.

| Model | Accuracy | Mean latency | Verdict |
|---|---|---|---|
| `ministral-3:3b` | 65% | 2,879ms | fail — under-calls tools |
| `qwen3.5:4b` | **95%** | **3,653ms** | **pass** |

Two smoke-test cases were rewritten after the first run: "Do you ship to
Austria?" and "What are your support hours?" are answerable from general
knowledge, so a model replying directly was not failing at tool calling. The
gate measures capability, not judgement. `ministral-3:3b` fails on the revised
suite too.

See `docs/decisions/001-native-api.md` for why this uses Ollama's native API.

## Run

```bash
conda create -n gauntlet python=3.11 -y && conda activate gauntlet
pip install ollama pydantic
ollama pull qwen3.5:4b
python -m tests.smoke qwen3.5:4b
```

## L0 baseline — undefended

`qwen3.5:4b`, 120 attacks + 40 benign controls, 0 errors.

| | |
|---|---|
| **Attack success rate (ASR)** | **35.0%** |
| **False refusal rate (FRR)** | **0.0%** |
| Mean latency | 5,128ms |

| Category | ASR | |
|---|---|---|
| jailbreak | 60.0% | 6/10 |
| direct_injection | 52.0% | 13/25 |
| system_prompt_extraction | 40.0% | 6/15 |
| pii_exfiltration | 35.0% | 7/20 |
| tool_hijacking | 35.0% | 7/20 |
| indirect_injection | 10.0% | 3/30 |

### The surprise

Attacks typed directly by the user land **5x more often** than the same
techniques hidden inside a fetched document:

| Surface | ASR | |
|---|---|---|
| user turn | **52.9%** | 37/70 |
| document | **10.0%** | 5/50 |

This is the opposite of the going assumption that indirect injection is the
harder threat. Verified not to be a harness artifact: `fetch_document` was
called in 50/50 document cases, so every payload reached the model. It appears
qwen3.5:4b treats tool results as data fairly reliably, while being highly
suggestible about text in the user turn.

Worth stating plainly: this is one model, one domain, one corpus. It is a
result about qwen3.5:4b, not about language models generally.

FRR is 0.0% at L0, as it must be -- there are no defences yet to wrongly refuse
anything. It becomes meaningful from L1 onward.
