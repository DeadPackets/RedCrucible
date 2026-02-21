"""Instruction substitution tables for polymorphic code generation.

Each function returns a list of assembly instructions that are semantically
equivalent to the requested operation, chosen randomly.
"""

from __future__ import annotations

import random


def zero_register(reg: str, rng: random.Random) -> list[str]:
    variants = [
        [f"xor {reg}, {reg}"],
        [f"sub {reg}, {reg}"],
        [f"mov {reg}, 0"],
        [f"push 0", f"pop {reg}"],
        [f"and {reg}, 0"],
    ]
    return rng.choice(variants)


def mov_imm(reg: str, value: int, rng: random.Random) -> list[str]:
    hex_val = hex(value)
    variants = [
        [f"mov {reg}, {hex_val}"],
    ]
    # push/pop only works for 32-bit signed immediates
    if -0x80000000 <= value <= 0x7FFFFFFF:
        variants.append([f"push {hex_val}", f"pop {reg}"])
    if 0 <= value <= 0x7FFFFFFF:
        variants.append([f"xor {reg}, {reg}", f"add {reg}, {hex_val}"])
        half = value // 2
        remainder = value - half
        if half > 0:
            variants.append([
                f"xor {reg}, {reg}",
                f"add {reg}, {hex(half)}",
                f"add {reg}, {hex(remainder)}",
            ])
    return rng.choice(variants)


def increment(reg: str, rng: random.Random) -> list[str]:
    variants = [
        [f"inc {reg}"],
        [f"add {reg}, 1"],
        [f"sub {reg}, -1"],
    ]
    return rng.choice(variants)


def decrement(reg: str, rng: random.Random) -> list[str]:
    variants = [
        [f"dec {reg}"],
        [f"sub {reg}, 1"],
        [f"add {reg}, -1"],
    ]
    return rng.choice(variants)


def compare_zero(reg: str, rng: random.Random) -> list[str]:
    variants = [
        [f"test {reg}, {reg}"],
        [f"cmp {reg}, 0"],
        [f"or {reg}, {reg}"],
    ]
    return rng.choice(variants)


def xor_byte_at_ptr(ptr_reg: str, key_reg_8bit: str, rng: random.Random) -> list[str]:
    return [f"xor byte ptr [{ptr_reg}], {key_reg_8bit}"]
