"""
PacketForge CLI – command-line interface for non-TUI workflows.

Commands:
  tui           Launch interactive TUI (default)
  craft         Craft and send a single packet from a template
  fuzz          Run a fuzzing campaign from a template
  replay        Replay a PCAP file
  template list List all available templates
  template show Show template details
  capture       Sniff packets and optionally save to PCAP
"""
from __future__ import annotations

import sys
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

console = Console()


def _require_root() -> None:
    import os
    if os.geteuid() != 0:
        console.print("[bold red]⚠  Root privileges required for raw socket operations.[/]")
        console.print("   Run with: [bold]sudo packetforge[/] ...")
        sys.exit(1)


# ── Root command ──────────────────────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.version_option("1.0.0", prog_name="PacketForge")
@click.pass_context
def main(ctx: click.Context) -> None:
    """
    \b
    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
    ██████╔╝███████║██║     █████╔╝ █████╗     ██║
    ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║
    ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝
      ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
      ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
      █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
      ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
      ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
      ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

    Elite custom protocol fuzzer & interactive packet crafter.
    """
    if ctx.invoked_subcommand is None:
        # Default: launch TUI
        from packetforge.tui import run_tui
        run_tui()


# ── TUI command ───────────────────────────────────────────────────────────────
@main.command()
def tui() -> None:
    """Launch the interactive TUI."""
    from packetforge.tui import run_tui
    run_tui()


# ── Template commands ─────────────────────────────────────────────────────────
@main.group()
def template() -> None:
    """Manage packet templates."""
    pass


@template.command("list")
@click.option("--query", "-q", default="", help="Search query")
@click.option("--json-out", is_flag=True, help="Output as JSON")
def template_list(query: str, json_out: bool) -> None:
    """List all available templates."""
    from packetforge.templates import get_library
    lib = get_library()
    templates = lib.search(query) if query else lib.all()

    if json_out:
        print(json.dumps([
            {"id": t.id, "name": t.name, "category": t.category,
             "cve": t.cve, "tags": t.tags}
            for t in templates
        ], indent=2))
        return

    table = Table(title="PacketForge Templates", border_style="dim")
    table.add_column("ID",          style="cyan",      no_wrap=True)
    table.add_column("Name",        style="bold white")
    table.add_column("Category",    style="yellow")
    table.add_column("CVE",         style="red")
    table.add_column("Tags",        style="green")

    cats = {}
    for t in templates:
        cats.setdefault(t.category, []).append(t)

    for cat in sorted(cats):
        for t in cats[cat]:
            table.add_row(
                t.id,
                t.name,
                t.category,
                t.cve or "─",
                ", ".join(t.tags[:4]),
            )

    console.print(table)
    console.print(f"\n[dim]{len(templates)} templates[/]")


@template.command("show")
@click.argument("template_id")
def template_show(template_id: str) -> None:
    """Show details for a specific template."""
    from packetforge.templates import get_library
    t = get_library().get(template_id)
    if not t:
        console.print(f"[red]Template not found: {template_id}[/]")
        sys.exit(1)

    console.print(Panel(
        f"[bold green]{t.name}[/]\n\n"
        f"[dim]ID:[/] {t.id}\n"
        f"[dim]Category:[/] {t.category}\n"
        f"[dim]CVE:[/] {t.cve or '─'}\n"
        f"[dim]Tags:[/] {', '.join(t.tags)}\n\n"
        f"{t.description}\n\n"
        + (f"[dim]Layers:[/] {' / '.join(t.stack.layer_names())}\n"
           f"[dim]Size:[/] {t.stack.total_bytes()} bytes" if t.stack else ""),
        title="Template Detail",
        border_style="green",
    ))


# ── Craft command ─────────────────────────────────────────────────────────────
@main.command()
@click.option("--template", "-t", "tmpl_id", default=None, help="Template ID to use as base")
@click.option("--iface", "-i", default=None, help="Network interface")
@click.option("--count", "-c", default=1, show_default=True, help="Packets to send")
@click.option("--inter", default=0.0, show_default=True, help="Inter-packet delay (seconds)")
@click.option("--dry-run", is_flag=True, help="Build but do not send")
def craft(tmpl_id: Optional[str], iface: Optional[str],
          count: int, inter: float, dry_run: bool) -> None:
    """Craft and send a packet from a template."""
    from packetforge.templates import get_library
    from packetforge.engine import PacketStack, default_iface

    if tmpl_id:
        stack = get_library().load_stack(tmpl_id)
        if not stack:
            console.print(f"[red]Template not found: {tmpl_id}[/]")
            sys.exit(1)
    else:
        stack = PacketStack(name="cli_craft")

    console.print(f"[bold green]Packet:[/] {' / '.join(stack.layer_names())}")
    console.print(f"[bold green]Size:[/]   {stack.total_bytes()} bytes")
    for line in stack.hex_lines():
        console.print(f"  [dim]{line}[/]")

    if dry_run:
        console.print("[yellow]Dry run – not sending.[/]")
        return

    _require_root()
    iface = iface or default_iface()
    ok, msg = stack.send_packet(iface=iface, count=count, inter=inter)
    if ok:
        console.print(f"[green]✓ {msg}[/]")
    else:
        console.print(f"[red]✗ {msg}[/]")
        sys.exit(1)


# ── Fuzz command ──────────────────────────────────────────────────────────────
@main.command()
@click.option("--template", "-t", "tmpl_id", required=True, help="Template ID")
@click.option("--iface",    "-i", default=None,  help="Network interface")
@click.option("--target",   "-T", default="192.168.1.1", show_default=True)
@click.option("--port",     "-p", default=80,    show_default=True)
@click.option("--count",    "-n", default=500,   show_default=True, help="Max packets")
@click.option("--pps",      "-r", default=100.0, show_default=True, help="Packets per second")
@click.option("--timeout",        default=2.0,   show_default=True)
@click.option("--mutations", "-m", default="boundary,bit_flip,proto_specific",
              show_default=True, help="Comma-separated mutation names")
@click.option("--no-recv",   is_flag=True, help="Send-only, don't wait for responses")
@click.option("--output",    "-o", default=None,  help="Save interesting results to JSON file")
def fuzz(tmpl_id: str, iface: Optional[str], target: str, port: int,
         count: int, pps: float, timeout: float, mutations: str,
         no_recv: bool, output: Optional[str]) -> None:
    """Run a fuzzing campaign against a template."""
    from packetforge.templates import get_library
    from packetforge.fuzzer import FuzzCampaign, FuzzConfig
    from packetforge.engine import default_iface
    import time

    _require_root()

    stack = get_library().load_stack(tmpl_id)
    if not stack:
        console.print(f"[red]Template not found: {tmpl_id}[/]")
        sys.exit(1)

    mut_list = [m.strip() for m in mutations.split(",") if m.strip()]
    cfg = FuzzConfig(
        iface=iface or default_iface(),
        target_ip=target,
        target_port=port,
        max_packets=count,
        pps=pps,
        timeout=timeout,
        mutations=mut_list,
        capture_responses=not no_recv,
    )

    console.print(Panel(
        f"[bold]Template:[/] {tmpl_id}\n"
        f"[bold]Target:[/]   {target}:{port}\n"
        f"[bold]Rate:[/]     {pps} PPS / {count} max packets\n"
        f"[bold]Mutations:[/] {', '.join(mut_list)}",
        title="[green]Fuzzing Campaign[/]",
        border_style="green",
    ))

    table = Table(show_header=True, header_style="bold blue", border_style="dim")
    table.add_column("#",        width=5)
    table.add_column("Layer",    width=8)
    table.add_column("Field",    width=16)
    table.add_column("Mutation", width=16)
    table.add_column("Value",    width=24)
    table.add_column("Result",   width=12)
    table.add_column("RTT ms",   width=8)

    interesting = []

    def on_result(r: Any) -> None:  # type: ignore[name-defined]
        from packetforge.fuzzer import ResultType
        rtype = r.result_type
        style = "dim"
        rstr = "sent"
        if rtype == ResultType.RESPONSE:
            style = "blue"; rstr = "response"
        elif rtype == ResultType.ANOMALY:
            style = "bold red"; rstr = "ANOMALY"
            interesting.append(r)
        elif rtype == ResultType.ERROR:
            style = "red"; rstr = "error"

        table.add_row(
            str(r.seq),
            r.layer,
            r.field_name,
            r.mutation_desc,
            str(r.mutated_value)[:24],
            f"[{style}]{rstr}[/]",
            f"{r.rtt_ms:.0f}" if r.rtt_ms else "─",
        )
        if r.seq % 50 == 0:
            console.print(f"[dim]  … {r.seq} packets sent[/]")

    from packetforge.fuzzer import FuzzCampaign  # re-import to help type checker

    # Need Any for callback
    from typing import Any as _Any
    on_result2: _Any = on_result

    campaign = FuzzCampaign(stack, cfg, on_result=on_result2)
    console.print("[yellow]Starting campaign…[/]")
    t0 = time.time()
    campaign.start(blocking=True)
    elapsed = time.time() - t0

    s = campaign.summary()
    console.print(table)
    console.print(Panel(
        f"[bold]Sent:[/]       {s['total_sent']}\n"
        f"[bold]Responses:[/]  {s['total_responses']}\n"
        f"[bold]Anomalies:[/]  [bold red]{s['total_anomalies']}[/]\n"
        f"[bold]Errors:[/]     {s['total_errors']}\n"
        f"[bold]Elapsed:[/]    {s['elapsed_s']}s\n"
        f"[bold]Actual PPS:[/] {s['pps_actual']}",
        title="[green]Campaign Summary[/]",
        border_style="green",
    ))

    if output and interesting:
        import json as _json
        data = [
            {
                "seq": r.seq, "layer": r.layer, "field": r.field_name,
                "mutation": r.mutation_desc,
                "value": str(r.mutated_value),
                "response": r.response_summary,
                "rtt_ms": r.rtt_ms,
            }
            for r in interesting
        ]
        Path(output).write_text(_json.dumps(data, indent=2))
        console.print(f"[green]✓ Interesting results saved to {output}[/]")


# ── Replay command ────────────────────────────────────────────────────────────
@main.command()
@click.argument("pcap_file")
@click.option("--iface",  "-i", default=None,   help="Network interface")
@click.option("--pps",    "-r", default=100.0,  show_default=True)
@click.option("--loop",   "-l", default=1,      show_default=True)
@click.option("--rnd-ip",         is_flag=True, help="Randomise source IPs")
@click.option("--rnd-mac",        is_flag=True, help="Randomise source MACs")
@click.option("--rnd-port",       is_flag=True, help="Randomise source ports")
@click.option("--bpf",            default="",   help="BPF filter")
def replay(pcap_file: str, iface: Optional[str], pps: float, loop: int,
           rnd_ip: bool, rnd_mac: bool, rnd_port: bool, bpf: str) -> None:
    """Replay a PCAP file."""
    from packetforge.replay import ReplayEngine, ReplayConfig
    from packetforge.engine import default_iface

    _require_root()

    cfg = ReplayConfig(
        iface=iface or default_iface(),
        pps=pps, loop=loop,
        randomise_src_ip=rnd_ip,
        randomise_src_mac=rnd_mac,
        randomise_src_port=rnd_port,
        bpf_filter=bpf,
    )
    engine = ReplayEngine(pcap_file, config=cfg)
    ok, msg = engine.load()
    if not ok:
        console.print(f"[red]Load failed: {msg}[/]")
        sys.exit(1)
    info = engine.pcap_info()
    console.print(f"[green]Loaded {info['packets']} packets from {pcap_file}[/]")
    console.print(f"[dim]Protocols: {info['protocols']}[/]")
    console.print(f"[yellow]Replaying at {pps} PPS × {loop} pass(es)…[/]")
    engine.start(blocking=True)
    s = engine.summary()
    console.print(
        f"[green]Done:[/] sent={s['sent']} errors={s['errors']} "
        f"elapsed={s['elapsed_s']}s @ {s['pps_actual']} PPS"
    )


# ── Capture command ───────────────────────────────────────────────────────────
@main.command()
@click.option("--iface",  "-i", default=None,   help="Interface")
@click.option("--count",  "-n", default=100,    show_default=True)
@click.option("--bpf",    "-f", default="",     help="BPF filter")
@click.option("--output", "-o", default=None,   help="Save PCAP to file")
@click.option("--timeout","-t", default=None, type=float, help="Stop after N seconds")
def capture(iface: Optional[str], count: int, bpf: str,
            output: Optional[str], timeout: Optional[float]) -> None:
    """Live packet capture to screen (and optionally PCAP)."""
    from packetforge.engine import capture_packets, default_iface

    _require_root()
    iface = iface or default_iface()
    console.print(
        f"[yellow]Sniffing on [bold]{iface}[/] "
        f"count={count} filter='{bpf or 'none'}' …[/]"
    )

    table = Table(show_header=True, header_style="bold blue", border_style="dim")
    table.add_column("#",       width=5)
    table.add_column("Proto",   width=6)
    table.add_column("Src",     width=22)
    table.add_column("Dst",     width=22)
    table.add_column("Len",     width=6)
    table.add_column("Summary", width=50)

    packets = []

    def prn(pkt: Any) -> None:  # type: ignore[name-defined]
        packets.append(pkt)
        n = len(packets)
        try:
            from scapy.layers.inet import IP, TCP, UDP
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else type(pkt).__name__
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
        except Exception:
            proto = src = dst = "?"
        table.add_row(
            str(n), proto, src, dst,
            str(len(bytes(pkt))), pkt.summary()[:50]
        )

    from typing import Any as _Any
    prn2: _Any = prn

    capture_packets(iface=iface, count=count, bpf=bpf, timeout=timeout, prn=prn2)
    console.print(table)
    console.print(f"[green]{len(packets)} packets captured[/]")

    if output and packets:
        from scapy.all import wrpcap
        wrpcap(output, packets)
        console.print(f"[green]✓ Saved to {output}[/]")


# ── Mutations list ────────────────────────────────────────────────────────────
@main.command("mutations")
def mutations_list() -> None:
    """List all available mutation strategies."""
    from packetforge.mutations import ALL_MUTATIONS
    table = Table(title="Available Mutations", border_style="dim")
    table.add_column("Name",        style="cyan",  no_wrap=True)
    table.add_column("Description", style="white")
    for m in ALL_MUTATIONS:
        table.add_row(m.name, m.description)
    console.print(table)


if __name__ == "__main__":
    main()
