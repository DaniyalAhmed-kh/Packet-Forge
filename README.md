# PacketForge

```
██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝███████║██║     █████╔╝ █████╗     ██║   █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-orange)](https://scapy.net)
[![Textual](https://img.shields.io/badge/TUI-Textual-purple)](https://textual.textualize.io)
[![Tests](https://img.shields.io/badge/Tests-52%2F52%20passing-brightgreen)](#testing)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Elite custom protocol fuzzer & interactive packet crafter**  
*Layer-by-layer TUI builder · 10 mutation strategies · 22 attack templates · PCAP replay*

</div>

---

> ⚠️ **For authorised security research, penetration testing labs, and educational use only.**  
> Sending crafted packets on networks you do not own or have explicit written permission to test is illegal in most jurisdictions.

---

## Overview

PacketForge is a complete protocol security research toolkit built on [Scapy](https://scapy.net) and [Textual](https://textual.textualize.io). It gives security engineers an interactive terminal UI to craft packets layer-by-layer, run structured fuzzing campaigns with real-time anomaly detection, replay PCAPs with mutations, and manage a library of attack templates — all from a single tool.

```
┌─────────────────────────────────────────────────────────────┐
│  PacketForge  [1:Craft] [2:Fuzz] [3:Templates] [4:Replay] [5:Capture]  │
├──────────────────┬───────────────────────────┬──────────────┤
│  ◈ LAYERS        │  ◈ FIELDS                 │  ◈ HEX DUMP  │
│                  │                           │              │
│  ▶ 0: Ether      │  version   4   int        │  0000: ff ff │
│    1: IP         │  ihl       5   int        │  0010: 45 00 │
│    2: TCP        │  ttl      64   int  ←     │  0020: ...   │
│                  │  src  0.0.0.0  ip         │              │
│  ⊕ Add           │  dst  0.0.0.0  ip         │  ◈ DECODE    │
│  ⊖ Remove        │  proto  tcp   enum        │  [Ether]     │
│  ↑ ↓ Reorder     │                           │  [IP]        │
│                  │  Click any row to edit    │  [TCP]       │
└──────────────────┴───────────────────────────┴──────────────┘
```

## Features

### 🖥️ Interactive TUI (5 screens)

| Screen | Key | What it does |
|--------|-----|--------------|
| **Craft** | `1` | Layer-by-layer packet builder with live hex dump and protocol decode |
| **Fuzz**  | `2` | Campaign dashboard — real-time PPS, anomaly counter, per-packet log |
| **Templates** | `3` | Searchable library of 22 attack templates |
| **Replay** | `4` | PCAP loader with mutation-on-replay (rnd src IP/MAC/port) |
| **Capture** | `5` | BPF-filtered live sniffer, one-click "send to Crafter" |

### 🔬 10 Mutation Strategies

| Strategy | Description |
|----------|-------------|
| `bit_flip` | Flip individual bits in integer/bytes fields |
| `boundary` | Edge-case values: `0`, `1`, `0x7F`, `0xFF`, `0xFFFF`, `0xFFFFFFFF` |
| `random_bytes` | Random byte-string replacements |
| `random_int` | Random integers across the full 32-bit value space |
| `increment` | Walk field value from `0` upward in configurable strides |
| `format_string` | `%s`, `%n`, `%.256d`, `AAAA%x%x` classic payloads |
| `overflow` | 64–1024 byte strings: `A×N`, `\x00×N`, `\x90×N` (NOP sled) |
| `null_byte` | Empty, `\x00`, `\x00\x00\x00\x00` injection |
| `proto_specific` | Protocol-aware: TTL edges, TCP flag combos, seq wrap, frag offsets |
| `enum_cycle` | All valid enum values + one out-of-range invalid value |

### 📦 22 Built-in Attack Templates

<details>
<summary><b>DoS / Flood</b></summary>

| ID | Name |
|----|------|
| `syn_flood` | TCP SYN Flood |
| `ack_flood` | TCP ACK Flood |
| `udp_flood` | UDP Flood |
| `icmp_flood` | ICMP Echo Flood (Ping Flood) |
| `arp_request_flood` | ARP Request Flood |
| `ipv6_ra_flood` | IPv6 Router Advertisement Flood |
</details>

<details>
<summary><b>Amplification</b></summary>

| ID | Name | CVE |
|----|------|-----|
| `dns_amplification` | DNS ANY Query Amplification | — |
| `ntp_monlist` | NTP MONLIST Amplification | CVE-2013-5211 |
| `smurf_attack` | Smurf (ICMP Broadcast Amplification) | — |
</details>

<details>
<summary><b>Spoofing / MITM</b></summary>

| ID | Name |
|----|------|
| `arp_spoof` | ARP Cache Poisoning / MITM |
| `dns_spoof` | DNS Response Spoofing |
| `icmp_redirect` | ICMP Redirect Injection |
</details>

<details>
<summary><b>Malformed / Historic</b></summary>

| ID | Name | CVE |
|----|------|-----|
| `teardrop` | Teardrop Fragmentation Attack | CVE-1997-0014 |
| `land_attack` | LAND Attack (src=dst loop) | CVE-1997-0016 |
| `ping_of_death` | Ping of Death (oversized ICMP) | CVE-1999-0128 |
| `malformed_ihl` | Invalid IP Header Length (IHL < 5) | — |
| `malformed_flags` | All TCP Flags Set (0xFF) | — |
| `frag_overlap` | Overlapping IP Fragments (evasion) | — |
</details>

<details>
<summary><b>L2 / Recon</b></summary>

| ID | Name |
|----|------|
| `vlan_double_tag` | VLAN Hopping (Double 802.1Q Tagging) |
| `tcp_xmas` | TCP Xmas Scan (FIN+PSH+URG) |
| `tcp_null` | TCP NULL Scan |
| `tcp_rst_inject` | TCP RST Injection |
</details>

---

## Installation

```bash
# Prerequisites
pip install scapy textual click rich pyyaml

# Clone and install
git clone https://github.com/yourname/packetforge
cd packetforge
pip install -e .
```

**Requirements:** Python 3.10+, root/sudo for raw socket operations (send/capture).

---

## Usage

### Launch TUI
```bash
sudo packetforge          # launches TUI by default
sudo packetforge tui      # explicit
```

### TUI Keyboard Reference

| Key | Action |
|-----|--------|
| `1` – `5` | Switch screens |
| `a` | Add layer (Craft) |
| `d` | Delete layer (Craft) |
| `↑` / `↓` | Reorder layers (Craft) |
| `ctrl+p` | Send packet (Craft) |
| `ctrl+s` | Save as template |
| `ctrl+e` | Export PCAP |
| `f` | Send to Fuzzer |
| `ctrl+r` | Start fuzz/replay/capture |
| `ctrl+c` | Stop campaign |
| `?` | Help screen |
| `ctrl+q` | Quit |

### CLI Commands

```bash
# List all templates
packetforge template list
packetforge template list --query "flood"

# Show template details
packetforge template show ntp_monlist

# Craft & send from template (root required)
sudo packetforge craft --template syn_flood --count 10 --iface eth0
sudo packetforge craft --template arp_spoof --dry-run   # no root needed

# Fuzzing campaign
sudo packetforge fuzz \
  --template syn_flood \
  --target 192.168.1.1 \
  --port 80 \
  --count 2000 \
  --pps 500 \
  --mutations "bit_flip,boundary,proto_specific,overflow" \
  --output findings.json

# Replay a PCAP with mutations
sudo packetforge replay capture.pcap \
  --pps 1000 --loop 3 \
  --rnd-ip --rnd-mac --rnd-port

# Live packet capture
sudo packetforge capture \
  --iface eth0 \
  --bpf "tcp port 443" \
  --count 500 \
  --output session.pcap

# List mutation strategies
packetforge mutations
```

---

## Testing

PacketForge ships with a 52-test suite that runs **without root or a real network** — all packet operations are validated in dry-run/in-memory mode.

```bash
python test_packetforge.py
```

```
══ 1. ENGINE ══════════════════════════════════════════════════
  ✓ Scapy import
  ✓ Layer registry (Ether/IP/TCP/UDP/ICMP/ARP)
  ✓ Build stack: Ether/IP/TCP
  ✓ Hex dump output
  ✓ Protocol decode summary
  ✓ Set field value (IP.ttl=128)
  ✓ Set field hex value (TCP.dport=0x1F90)
  ✓ Field introspection (IP layer)
  ✓ Move layer (reorder)
  ✓ Stack clone (deep copy independence)
  ✓ Serialise / deserialise stack (dict round-trip)
  ✓ Export to PCAP file
  ... (52 total)

══════════════════════════════════════════════════════════════
  Results: 52/52 passed
  ✓ All tests passed!
══════════════════════════════════════════════════════════════
```

### What the tests cover

- **Engine** (14 tests): stack building, hex dump, field set/get, hex value parsing, layer reorder/remove, clone independence, dict serialisation, PCAP export
- **Mutations** (9 tests): all 10 strategies registered, bit_flip values, boundary edges, overflow sizes, format strings, proto-specific TTL/flags, increment sequence, applies_to() filtering
- **Templates** (17 tests): ≥20 templates, required categories, 12 individual templates validated, search, clone independence, YAML round-trip
- **Fuzzer** (5 tests): variant generation, multi-field coverage, field filter, summary dict, anomaly detector
- **Replay** (2 tests): PCAP load, packet summary, pcap_info()
- **CLI** (5 tests): template list/show, mutations, craft --dry-run

---

## Architecture

```
packetforge/
├── engine.py      PacketStack core: layers, field introspection, send/recv, PCAP I/O
├── mutations.py   10 pluggable mutation strategy classes
├── fuzzer.py      FuzzCampaign engine, AnomalyDetector, CampaignStats
├── templates.py   22 built-in templates, TemplateLibrary, YAML persistence
├── replay.py      ReplayEngine with mutation-on-replay
├── tui.py         Textual TUI: Craft/Fuzz/Templates/Replay/Capture screens
└── cli.py         Click CLI with all subcommands
```

### Key design decisions

- **PacketStack** is a mutable ordered list of Scapy layer instances, separate from Scapy's own `/` composition — this gives programmatic add/remove/reorder without rebuilding the whole object.
- **Mutations are pure generators** (`Iterator[Any]`) with no state coupling to the packet. The `FuzzCampaign` iterates the Cartesian product of (layers × fields × applicable mutations) and clones the template per variant.
- **AnomalyDetector** uses a baseline-comparison model: set a baseline response size on the first successful reply, then flag deviations >50% and >20 bytes, TCP RST, and ICMP error codes.
- **Templates are YAML-serialisable** (builtin Flag/Enum values coerced to `int` in `to_dict`). Custom user templates live in `~/.packetforge/templates/`.

---

## Extending PacketForge

### Add a custom mutation

```python
from packetforge.mutations import Mutation, MUTATION_REGISTRY
from packetforge.engine import FieldInfo
from typing import Iterator, Any

class MySQLFuzzMutation(Mutation):
    name = "mysql_fuzz"
    description = "MySQL-specific payload injection"

    def applies_to(self, fi: FieldInfo) -> bool:
        return fi.ftype in ("bytes", "str")

    def generate(self, fi: FieldInfo) -> Iterator[Any]:
        yield b"\x00" * 4                      # null header
        yield b"SELECT 1; DROP TABLE users;--"  # SQLi probe
        yield b"\xff\xfe" * 8                  # bad charset

MUTATION_REGISTRY["mysql_fuzz"] = MySQLFuzzMutation()
```

### Add a custom template

```python
from packetforge.templates import TemplateInfo, get_library
from packetforge.engine import PacketStack

ps = PacketStack(name="my_custom_attack")
ps.add_layer("Ether")
ps.add_layer("IP")
ps.add_layer("TCP")

get_library().save(TemplateInfo(
    id="my_custom_attack",
    name="My Custom Attack",
    description="Describe what it does and why it's interesting.",
    category="Custom",
    tags=["tcp", "custom"],
    stack=ps,
))
```

### Add a new protocol layer

```python
from packetforge.engine import LAYER_REGISTRY, LAYER_GROUPS
from scapy.layers.http import HTTP, HTTPRequest  # example

LAYER_REGISTRY["HTTP"]        = HTTP
LAYER_REGISTRY["HTTPRequest"] = HTTPRequest
LAYER_GROUPS.setdefault("Application", []).extend(["HTTP", "HTTPRequest"])
```

---

## Legal Notice

PacketForge is designed for **authorised security research, penetration testing labs, CTF challenges, and educational use.**

- Only use on networks and systems you own or have **explicit written permission** to test.
- The authors accept **no liability** for misuse or damages caused by this tool.
- Many of the attack templates generate traffic that is **illegal** to send on public networks.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
