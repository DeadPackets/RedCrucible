"""Dead code generator for polymorphic shellcode.

Inserts semantically neutral junk instructions to change the
byte signature of generated code.
"""

from __future__ import annotations

import random

_JUNK_REGS = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]


def generate_dead_code(
    count: int,
    rng: random.Random,
    avoid_regs: set[str] | None = None,
) -> list[str]:
    if avoid_regs is None:
        avoid_regs = set()

    safe_regs = [r for r in _JUNK_REGS if r not in avoid_regs]
    instructions: list[str] = []
    for _ in range(count):
        instructions.extend(_make_one_junk(rng, safe_regs))
    return instructions


def _make_one_junk(rng: random.Random, safe_regs: list[str]) -> list[str]:
    kind = rng.randint(0, 7)

    if kind == 0:
        return ["nop"]
    elif kind == 1:
        reg = rng.choice(_JUNK_REGS)
        return [f"push {reg}", f"pop {reg}"]
    elif kind == 2 and safe_regs:
        return [f"add {rng.choice(safe_regs)}, 0"]
    elif kind == 3 and safe_regs:
        return [f"sub {rng.choice(safe_regs)}, 0"]
    elif kind == 4 and safe_regs:
        return [f"xor {rng.choice(safe_regs)}, 0"]
    elif kind == 5 and safe_regs:
        reg = rng.choice(safe_regs)
        return [f"mov {reg}, {reg}"]
    elif kind == 6 and len(safe_regs) >= 2:
        r1, r2 = rng.sample(safe_regs, 2)
        return [f"xchg {r1}, {r2}", f"xchg {r1}, {r2}"]
    elif kind == 7 and safe_regs:
        reg = rng.choice(safe_regs)
        imm = rng.randint(1, 0xFF)
        op = rng.choice(["add", "sub", "xor"])
        return [f"push {reg}", f"{op} {reg}, {hex(imm)}", f"pop {reg}"]
    else:
        return ["nop"]
