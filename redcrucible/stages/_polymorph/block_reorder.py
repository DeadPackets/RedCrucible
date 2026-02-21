"""Code block reordering for polymorphic shellcode.

Shuffles independent code blocks and connects them with jmp instructions,
changing the physical layout while preserving logical execution order.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class CodeBlock:
    label: str
    instructions: list[str]
    next_label: str | None  # None = final block


def reorder_blocks(
    blocks: list[CodeBlock], rng: random.Random
) -> list[str]:
    if len(blocks) <= 1:
        result: list[str] = []
        for b in blocks:
            result.append(f"{b.label}:")
            result.extend(b.instructions)
        return result

    entry = blocks[0]
    rest = blocks[1:]
    rng.shuffle(rest)
    shuffled = [entry] + rest

    output: list[str] = []
    for i, block in enumerate(shuffled):
        output.append(f"{block.label}:")
        output.extend(block.instructions)

        if block.next_label is not None:
            if i + 1 < len(shuffled) and shuffled[i + 1].label == block.next_label:
                pass  # Fall through naturally
            else:
                output.append(f"jmp {block.next_label}")

    return output


def make_unique_labels(count: int, rng: random.Random, prefix: str = "b") -> list[str]:
    labels = []
    for i in range(count):
        suffix = rng.randint(0x1000, 0xFFFF)
        labels.append(f"{prefix}_{suffix:x}_{i}")
    return labels
