"""Random register allocation for polymorphic code generation.

Assigns physical x86_64 registers to logical roles, ensuring each
invocation uses a different register mapping.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum, auto


class Role(Enum):
    COUNTER = auto()
    POINTER = auto()
    KEY = auto()
    TEMP1 = auto()
    TEMP2 = auto()
    SYSCALL_NUM = auto()
    NTDLL_BASE = auto()
    FUNC_ADDR = auto()


_ALL_REGS_64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
_REGS_32 = [
    "eax", "ebx", "ecx", "edx", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]
_REGS_8 = [
    "al", "bl", "cl", "dl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]

_RESERVED = {"rsp", "rbp"}


@dataclass(frozen=True)
class RegisterSet:
    mapping: dict[Role, str]

    def r64(self, role: Role) -> str:
        return self.mapping[role]

    def r32(self, role: Role) -> str:
        idx = _ALL_REGS_64.index(self.mapping[role])
        return _REGS_32[idx]

    def r8(self, role: Role) -> str:
        idx = _ALL_REGS_64.index(self.mapping[role])
        return _REGS_8[idx]

    @property
    def used_regs(self) -> set[str]:
        return set(self.mapping.values())


def allocate_registers(
    roles: list[Role], rng: random.Random | None = None
) -> RegisterSet:
    if rng is None:
        rng = random.Random()

    available = [r for r in _ALL_REGS_64 if r not in _RESERVED]
    if len(roles) > len(available):
        raise ValueError(f"Need {len(roles)} registers but only {len(available)} available")

    chosen = rng.sample(available, len(roles))
    return RegisterSet(mapping=dict(zip(roles, chosen)))
