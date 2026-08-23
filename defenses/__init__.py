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


# Cumulative layer definitions. Keys are the layer names used in result files.
LAYERS: dict[str, list[Defense]] = {
    "L0": [],
}

LAYER_ORDER = ["L0"]
