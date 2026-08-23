"""The agent under test.

Returns a transcript, not a string. Graders need to inspect tool calls, so
`AgentResult.tool_calls` is the load-bearing field -- if this were a plain
string, half the attack categories would be ungradeable.

Uses Ollama's *native* API rather than its OpenAI-compatible endpoint. The
compat endpoint silently drops the `think` parameter, which left qwen3.5:4b
reasoning before every reply: 15.4s/call instead of 0.5s. Measured, see
docs/decisions/001-native-api.md.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import ollama

from target import tools

MAX_TOOL_ROUNDS = 4


@dataclass
class ToolCall:
    name: str
    args: dict


@dataclass
class AgentResult:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    blocked_calls: list[tuple[ToolCall, str]] = field(default_factory=list)
    latency_ms: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    defense_events: list[str] = field(default_factory=list)
    error: str | None = None


def run(
    user_prompt: str,
    model: str = "qwen3.5:4b",
    document_payload: str | None = None,
    system_prompt: str | None = None,
    think: bool = False,
    tool_guard=None,
) -> AgentResult:
    """Run one conversation to completion, executing tools as requested."""
    messages: list[dict] = [
        {"role": "system", "content": system_prompt or tools.SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    result = AgentResult()
    started = time.perf_counter()

    try:
        for _ in range(MAX_TOOL_ROUNDS):
            response = ollama.chat(
                model=model,
                messages=messages,
                tools=tools.SCHEMAS,
                think=think,
                options={"temperature": 0.0, "seed": 42},
            )
            result.tokens_in += response.get("prompt_eval_count", 0) or 0
            result.tokens_out += response.get("eval_count", 0) or 0

            message = response["message"]
            calls = message.get("tool_calls") or []

            if not calls:
                result.text = message.get("content") or ""
                break

            messages.append(dict(message))
            for call in calls:
                name = call["function"]["name"]
                # Native API hands back a dict; the compat endpoint hands back a
                # JSON string. This path only ever sees the dict.
                args = dict(call["function"].get("arguments") or {})
                tc = ToolCall(name, args)

                # The guard runs *before* execution. A defence that only
                # inspected the call afterwards would not be a defence -- the
                # refund would already have happened.
                reason = tool_guard(name, args) if tool_guard else None
                if reason:
                    result.blocked_calls.append((tc, reason))
                    messages.append(
                        {"role": "tool", "content": f"Refused: {reason}"}
                    )
                    continue

                result.tool_calls.append(tc)
                messages.append(
                    {
                        "role": "tool",
                        "content": tools.execute(name, args, document_payload),
                    }
                )
    except Exception as exc:  # noqa: BLE001 - surface any backend failure to the grader
        result.error = f"{type(exc).__name__}: {exc}"

    result.latency_ms = (time.perf_counter() - started) * 1000
    return result
