"""Defence layers.

Each layer is a hook pair: `pre` runs before the model sees anything, `post`
runs on the model's output. Layers are cumulative -- L3 means L1+L2+L3 -- so the
ablation shows what each one actually bought.

Only L0 (no defence) exists so far. L1-L5 land next; the registry and the
Context/Blocked types are here so the runner does not need changing when they do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class Context:
    """Everything a defence may inspect or rewrite before the model runs."""

    user_prompt: str
    document_payload: str | None
    system_prompt: str | None = None
    events: list[str] = field(default_factory=list)


@dataclass
class Blocked:
    """A defence stopped the request. Counts as a refusal for benign cases."""

    layer: str
    reason: str


@runtime_checkable
class Defense(Protocol):
    name: str

    def pre(self, ctx: Context) -> Context | Blocked: ...

    def post(self, ctx: Context, out): ...


def build_layers() -> dict[str, list]:
    """Cumulative stacks: L3 means L1+L2+L3.

    Built fresh per call because some layers hold per-request state.
    """
    from defenses.layers import InputScan, OutputScan, SchemaAllowlist, Spotlight, ToolAuth

    order = [Spotlight(), InputScan(), SchemaAllowlist(), OutputScan(), ToolAuth()]
    return {"L0": [], **{f"L{i}": order[:i] for i in range(1, 6)}}


LAYERS = build_layers()
LAYER_ORDER = ["L0", "L1", "L2", "L3", "L4", "L5"]


def tool_guard_for(stack: list) -> "callable | None":
    """Compose the tool guards in a stack. First refusal wins."""
    guards = [d.tool_guard for d in stack if hasattr(d, "tool_guard")]
    if not guards:
        return None

    def guard(name: str, args: dict) -> str | None:
        for g in guards:
            reason = g(name, args)
            if reason:
                return reason
        return None

    return guard
