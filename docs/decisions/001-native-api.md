# 001 — Use Ollama's native API, not its OpenAI-compatible endpoint

## Context
The agent needs `think=false`. qwen3.5 is a thinking model, and a reasoning pass
before every reply is unaffordable across a ~960-call evaluation matrix.

Ollama exposes two interfaces: `/v1/chat/completions` (OpenAI-compatible) and
`/api/chat` (native). The compat endpoint is the more portable choice, so it was
tried first.

## Measurement
Identical prompt ("Say hi in 3 words."), `think: false` set on both, qwen3.5:4b:

| Endpoint | Wall clock |
|---|---|
| `/api/chat` (native) | **0.53s** |
| `/v1/chat/completions` (compat) | **174s** |

The compat endpoint silently drops `think`. No error, no warning — the model
just reasons at length before answering. Consistent with ollama/ollama#14617,
which reports that thinking can only be disabled via the request body, not a
Modelfile.

Effect on the smoke test (20 cases, qwen3.5:4b): mean latency fell from
**15,437ms to 3,653ms** on the identical suite. Extrapolated over the full
matrix, that is ~4 hours versus ~1 hour per run.

## Decision
Use `ollama.chat()` against the native API.

## Cost
Portability. Retargeting a hosted model later means writing a provider adapter
rather than changing a base URL. Worth it — a 4x difference in matrix runtime
changes how many times the experiment can be repeated in a day.

## Note on arguments
The native API returns tool-call arguments as a **dict**; the compat endpoint
returns a **JSON string**. Any future adapter has to normalise this.
