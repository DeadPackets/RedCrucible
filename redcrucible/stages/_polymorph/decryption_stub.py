"""Polymorphic decryption loop generator.

Generates x86_64 assembly for an in-place rolling XOR decryption loop.
Every invocation produces structurally different code through register
rotation, instruction substitution, and dead code insertion.
"""

from __future__ import annotations

import random

from . import dead_code, instruction_subs as isub
from .register_allocator import RegisterSet, Role


def generate_decryption_loop(
    regs: RegisterSet,
    payload_size: int,
    key_bytes: bytes,
    junk_density: int,
    rng: random.Random,
    payload_label: str = "payload_start",
    done_label: str = "decrypt_done",
) -> list[str]:
    """Generate a polymorphic rolling XOR decryption loop.

    Decrypts payload_size bytes starting at payload_label using
    a rolling key of len(key_bytes). Key data is embedded in the
    code stream via .byte directives.
    """
    r_ptr = regs.r64(Role.POINTER)
    r_ctr = regs.r64(Role.COUNTER)
    r_key = regs.r64(Role.KEY)
    r_tmp = regs.r64(Role.TEMP1)
    r_tmp_8 = regs.r8(Role.TEMP1)
    r_keyidx = regs.r64(Role.TEMP2)
    r_keyidx_32 = regs.r32(Role.TEMP2)

    key_len = len(key_bytes)
    loop_label = f"dec_loop_{rng.randint(0x1000, 0xFFFF):x}"
    wrap_label = f"no_wrap_{rng.randint(0x1000, 0xFFFF):x}"
    key_data_label = f"key_data_{rng.randint(0x1000, 0xFFFF):x}"
    key_jmp_label = f"key_skip_{rng.randint(0x1000, 0xFFFF):x}"

    lines: list[str] = []

    # Load pointer to payload (RIP-relative)
    lines.append(f"lea {r_ptr}, [{payload_label}]")
    lines.extend(_junk(junk_density, rng, regs))

    # Load counter = payload_size
    lines.extend(isub.mov_imm(r_ctr, payload_size, rng))
    lines.extend(_junk(junk_density, rng, regs))

    # Load key base address — key data is embedded below, skip over it
    lines.append(f"jmp {key_jmp_label}")
    lines.append(f"{key_data_label}:")
    # Emit key as .byte directives
    for i in range(0, len(key_bytes), 8):
        chunk = key_bytes[i:i + 8]
        db_values = ", ".join(f"0x{b:02x}" for b in chunk)
        lines.append(f".byte {db_values}")
    lines.append(f"{key_jmp_label}:")

    lines.append(f"lea {r_key}, [{key_data_label}]")
    lines.extend(_junk(junk_density, rng, regs))

    # Initialize key index to 0
    lines.extend(isub.zero_register(r_keyidx, rng))
    lines.extend(_junk(junk_density, rng, regs))

    # === Decryption loop ===
    lines.append(f"{loop_label}:")

    # Load key byte: mov tmp_8, byte [key + keyidx]
    lines.append(f"mov {r_tmp_8}, byte ptr [{r_key} + {r_keyidx}]")

    # XOR byte at [pointer] with key byte
    lines.extend(isub.xor_byte_at_ptr(r_ptr, r_tmp_8, rng))
    lines.extend(_junk(junk_density // 2, rng, regs))

    # Increment pointer
    lines.extend(isub.increment(r_ptr, rng))

    # Increment key index, wrap if == key_len
    lines.extend(isub.increment(r_keyidx, rng))
    lines.append(f"cmp {r_keyidx_32}, {key_len}")
    lines.append(f"jne {wrap_label}")
    lines.extend(isub.zero_register(r_keyidx, rng))
    lines.append(f"{wrap_label}:")

    # Decrement counter, loop if not zero
    lines.extend(isub.decrement(r_ctr, rng))
    lines.extend(isub.compare_zero(r_ctr, rng))
    lines.append(f"jnz {loop_label}")

    # Done — jump to execution
    lines.append(f"jmp {done_label}")

    return lines


def _junk(density: int, rng: random.Random, regs: RegisterSet) -> list[str]:
    if density <= 0:
        return []
    count = rng.randint(0, density)
    return dead_code.generate_dead_code(count, rng, avoid_regs=regs.used_regs)
