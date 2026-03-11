"""
PacketForge Mutations – pluggable field-level mutation strategies.

Each Mutation subclass implements `apply(value, field_info) -> Any`.
The MutationEngine combines strategies and generates variant packets.
"""
from __future__ import annotations

import random
import struct
import string
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional, Sequence

from packetforge.engine import FieldInfo


# ── Boundary value libraries ──────────────────────────────────────────────────
INT_BOUNDARIES: List[int] = [
    0, 1, 2, 0x7F, 0x80, 0xFF,
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]
PORT_BOUNDARIES: List[int] = [0, 1, 21, 22, 23, 25, 53, 80, 110, 443, 1024,
                               8080, 8443, 65534, 65535]
FORMAT_STRINGS: List[bytes] = [
    b"%s%s%s%s%s%s%s%s%s%s",
    b"%n%n%n%n%n",
    b"%.256d",
    b"AAAA%x%x%x%x",
    b"%99999999s",
]
OVERFLOW_STRINGS: List[bytes] = [
    b"A" * 64,
    b"A" * 128,
    b"A" * 256,
    b"A" * 512,
    b"A" * 1024,
    b"\x00" * 64,
    b"\xff" * 64,
    b"\x90" * 64,  # NOP sled
    b"\x41\x42\x43\x44" * 16,
]
NULL_PAYLOADS: List[bytes] = [b"", b"\x00", b"\x00" * 4, b"\x00" * 16]


# ── Base class ────────────────────────────────────────────────────────────────
class Mutation(ABC):
    name: str = "base"
    description: str = ""

    def applies_to(self, fi: FieldInfo) -> bool:
        """Return True if this mutation makes sense for the field type."""
        return True

    @abstractmethod
    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        """Yield mutated values for a field."""
        ...

    def __repr__(self) -> str:
        return f"<Mutation:{self.name}>"


# ── Concrete mutations ────────────────────────────────────────────────────────
class BitFlipMutation(Mutation):
    name = "bit_flip"
    description = "Flip individual bits in integer/bytes fields"

    def __init__(self, max_bits: int = 8):
        self.max_bits = max_bits

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("int", "bytes")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        if fi.ftype == "int" and isinstance(fi.value, int):
            v = fi.value
            for bit in range(min(self.max_bits, 32)):
                yield v ^ (1 << bit)
        elif fi.ftype == "bytes" and isinstance(fi.value, (bytes, bytearray)):
            data = bytearray(fi.value)
            for i in range(min(len(data), 8)):
                for bit in range(8):
                    mutated = bytearray(data)
                    mutated[i] ^= (1 << bit)
                    yield bytes(mutated)


class BoundaryMutation(Mutation):
    name = "boundary"
    description = "Test integer boundary / edge-case values"

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("int", "enum")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        for v in INT_BOUNDARIES:
            yield v
        if "port" in fi.name.lower() or "dport" in fi.name or "sport" in fi.name:
            yield from PORT_BOUNDARIES


class RandomByteMutation(Mutation):
    name = "random_bytes"
    description = "Replace bytes fields with random data"

    def __init__(self, count: int = 20, seed: Optional[int] = None):
        self.count = count
        self.rng = random.Random(seed)

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("bytes", "str")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        orig_len = len(fi.value) if isinstance(fi.value, (bytes, str)) else 8
        for _ in range(self.count):
            yield bytes(self.rng.randint(0, 255) for _ in range(orig_len))


class RandomIntMutation(Mutation):
    name = "random_int"
    description = "Random integers across the full value space"

    def __init__(self, count: int = 20, seed: Optional[int] = None):
        self.count = count
        self.rng = random.Random(seed)

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("int", "enum")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        for _ in range(self.count):
            yield self.rng.randint(0, 0xFFFFFFFF)


class IncrementMutation(Mutation):
    name = "increment"
    description = "Walk integer field from 0 upward"

    def __init__(self, start: int = 0, steps: int = 256, stride: int = 1):
        self.start = start
        self.steps = steps
        self.stride = stride

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("int", "enum")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        for i in range(self.steps):
            yield self.start + i * self.stride


class FormatStringMutation(Mutation):
    name = "format_string"
    description = "Classic format-string attack payloads"

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("bytes", "str")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        yield from FORMAT_STRINGS


class OverflowMutation(Mutation):
    name = "overflow"
    description = "Buffer overflow & long-string payloads"

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("bytes", "str")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        yield from OVERFLOW_STRINGS


class NullByteMutation(Mutation):
    name = "null_byte"
    description = "Null-byte injection and empty payloads"

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("bytes", "str")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        yield from NULL_PAYLOADS


class ProtocolSpecificMutation(Mutation):
    """Mutation aware of the field's role in the protocol."""
    name = "proto_specific"
    description = "Protocol-field-aware mutations (TTL, flags, seq, etc.)"

    def applies_to(self, fi: FieldInfo) -> bool:
        return True

    def generate(self, fi: FieldInfo) -> Iterator[Any]:  # noqa: C901
        n = fi.name.lower()

        # TTL – interesting values
        if n == "ttl":
            yield from [0, 1, 2, 64, 128, 255]

        # TCP flags – all combinations
        elif n == "flags":
            for flags in range(64):  # 6 TCP flag bits
                yield flags
            yield 0xFF  # invalid

        # Window size – edge cases
        elif n == "window":
            yield from [0, 1, 512, 1024, 32767, 65535]

        # Sequence / ack – wrap-around and zero
        elif n in ("seq", "ack"):
            yield from [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

        # IP fragment offset
        elif n in ("frag", "fragment_offset"):
            yield from [0, 1, 8185, 8191]  # max valid offsets

        # IP options / padding
        elif n == "options":
            yield b""
            yield b"\x00" * 4
            yield b"\x94\x04\x00\x00"  # router alert

        # Protocol field
        elif n == "proto":
            yield from [0, 1, 6, 17, 41, 47, 58, 89, 132, 255]

        # IHL – invalid header lengths
        elif n == "ihl":
            yield from [0, 1, 2, 5, 15]

        # Version
        elif n == "version":
            yield from [0, 4, 5, 6, 15]

        # DNS query type
        elif n == "qtype":
            yield from [0, 1, 2, 5, 6, 12, 15, 16, 28, 255, 65535]

        # Generic: yield some boundary ints if integer type
        elif fi.ftype in ("int", "enum"):
            yield from [0, 1, fi.value if isinstance(fi.value, int) else 0,
                        0xFF, 0xFFFF, 0xFFFFFFFF]


class EnumCycleMutation(Mutation):
    name = "enum_cycle"
    description = "Iterate all known enum values for a field"

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype == "enum" and fi.choices is not None

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        if fi.choices:
            yield from fi.choices.keys()
            # Also try values just outside the valid set
            max_val = max(fi.choices.keys()) if fi.choices else 0
            yield max_val + 1
            yield 0xFFFF


# ── Registry of all built-in mutations ───────────────────────────────────────
ALL_MUTATIONS: List[Mutation] = [
    BitFlipMutation(),
    BoundaryMutation(),
    RandomByteMutation(),
    RandomIntMutation(),
    IncrementMutation(),
    FormatStringMutation(),
    OverflowMutation(),
    NullByteMutation(),
    ProtocolSpecificMutation(),
    EnumCycleMutation(),
]

MUTATION_REGISTRY: Dict[str, Mutation] = {m.name: m for m in ALL_MUTATIONS}


def get_mutation(name: str) -> Optional[Mutation]:
    return MUTATION_REGISTRY.get(name)


def list_mutations() -> List[Dict[str, str]]:
    return [{"name": m.name, "description": m.description} for m in ALL_MUTATIONS]
