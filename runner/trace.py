"""Langfuse tracing.

One trace per evaluated case, carrying category, technique, defence layer, model
and the final verdict as metadata, plus a `defended` score. In the Langfuse UI
you can then filter to "attacks that landed at L5" and read the actual
conversation instead of trusting a number in a table.

Entirely optional. Without keys this module is a no-op and the eval runs exactly
as before. Tracing must never change a result or fail a run, so every call site
swallows its own errors.

Targets langfuse 4.x: `@observe` plus `get_client().update_current_span`. The
3.x-style `client.start_as_current_span` does not exist in 4.x -- and because
this module degrades silently by design, that mistake produced a full run with
zero traces and no visible error. `--check` exists so setup failures are loud
even though runtime failures are quiet.

Keys come from the environment (see .env.example). Never hardcode them: this
repository is public.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, TypeVar

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:  # pragma: no cover - convenience only
    pass

T = TypeVar("T")
_warned = False


def enabled() -> bool:
    return bool(os.getenv("LANGFUSE_PUBLIC_KEY") and os.getenv("LANGFUSE_SECRET_KEY"))


def _warn_once(message: str) -> None:
    global _warned
    if not _warned:
        _warned = True
        print(f"  [trace] {message}")


def client():
    """The Langfuse client, or None when tracing is not configured."""
    if not enabled():
        return None
    try:
        from langfuse import get_client

        return get_client()
    except Exception as exc:  # noqa: BLE001 - never let tracing break an eval
        _warn_once(f"disabled: {type(exc).__name__}: {exc}")
        return None


def observe_case(
    case: dict, layer: str, model: str, work: Callable[[], tuple]
) -> tuple:
    """Run `work()` inside one Langfuse span.

    `work` returns (result, events, verdict) and that tuple is passed straight
    back, so the caller behaves identically whether tracing is on or off.

    A single decorated call wraps the whole case. An earlier context-manager
    version opened one span and closed another, producing two traces per case.
    """
    if not enabled():
        return work()

    try:
        from langfuse import get_client, observe
    except Exception as exc:  # noqa: BLE001
        _warn_once(f"disabled: {type(exc).__name__}: {exc}")
        return work()

    is_attack = "expected_violation" in case

    @observe(name=case["id"])
    def _traced() -> tuple:
        result, events, verdict = work()
        try:
            c = get_client()
            c.update_current_span(
                input={
                    "user_prompt": case["user_prompt"],
                    "document_payload": case.get("document_payload"),
                },
                output={
                    "text": (result.text or "")[:600],
                    "tool_calls": [tc.name for tc in result.tool_calls],
                    "blocked_calls": [tc.name for tc, _ in result.blocked_calls],
                    "violated": verdict.violated if is_attack else None,
                    "handled": verdict.handled,
                    "refused": verdict.refused,
                    "detail": verdict.detail,
                },
                metadata={
                    "case_id": case["id"],
                    "category": case["category"],
                    "technique": case.get("technique"),
                    "surface": case["surface"],
                    "severity": case.get("severity"),
                    "layer": layer,
                    "model": model,
                    "kind": "attack" if is_attack else "benign",
                    "expected_violation": case.get("expected_violation"),
                    "defense_events": events,
                    "latency_ms": round(result.latency_ms, 1),
                },
                level="WARNING" if (is_attack and verdict.violated) else "DEFAULT",
            )
            if is_attack:
                # 1.0 = the defence held. Filter to score 0 in the UI to get
                # every attack that landed.
                c.score_current_trace(
                    name="defended",
                    value=0.0 if verdict.violated else 1.0,
                    comment=verdict.detail or "",
                )
        except Exception as exc:  # noqa: BLE001
            _warn_once(f"annotation failed, continuing: {type(exc).__name__}: {exc}")
        return result, events, verdict

    try:
        return _traced()
    except Exception as exc:  # noqa: BLE001
        _warn_once(f"span failed, running untraced: {type(exc).__name__}: {exc}")
        return work()


def flush() -> None:
    c = client()
    if c is not None:
        try:
            c.flush()
        except Exception:  # noqa: BLE001
            pass


def check() -> int:
    """Verify tracing end to end: auth, emit, flush.

    Silent degradation is right during an eval and wrong during setup, so this
    makes failure loud.

        python -m runner.trace --check
    """
    if not enabled():
        print("tracing DISABLED -- set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY in .env")
        return 1

    c = client()
    if c is None:
        print("client could not be constructed")
        return 1
    if not c.auth_check():
        print("auth check FAILED -- wrong keys or host")
        return 1

    from graders.verdict import Verdict
    from target.agent import AgentResult

    probe = {
        "id": "trace-selfcheck",
        "category": "selfcheck",
        "technique": "probe",
        "surface": "user",
        "severity": "low",
        "user_prompt": "self check",
        "expected_violation": "canary_leak",
    }
    observe_case(
        probe,
        "L0",
        "selfcheck",
        lambda: (AgentResult(text="ok"), ["selfcheck"], Verdict(False, False, False, "probe")),
    )
    flush()

    print("auth ok, one probe trace emitted and flushed")
    print(f"host: {os.getenv('LANGFUSE_HOST', 'https://cloud.langfuse.com')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
