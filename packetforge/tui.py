"""
PacketForge TUI – Full interactive terminal UI powered by Textual.

Layout:
  ┌─ Header: PacketForge + nav tabs ───────────────────────┐
  │  [Craft] [Fuzz] [Templates] [Replay] [Capture] [Help]  │
  ├──────────────────────────────────────────────────────── │
  │  <active screen content>                                │
  ├──────────────────────────────────────────────────────── │
  │  Footer: key bindings + status                          │
  └─────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import asyncio
import copy
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from rich.text import Text
from rich.syntax import Syntax

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.screen import ModalScreen, Screen
from textual.widget import Widget
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Log,
    ProgressBar,
    Select,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)
from textual import events, work, on

from packetforge.engine import (
    LAYER_GROUPS,
    LAYER_REGISTRY,
    PacketStack,
    FieldInfo,
    default_iface,
    get_layer_fields,
    list_interfaces,
    set_layer_field,
    SCAPY_AVAILABLE,
)
from packetforge.mutations import ALL_MUTATIONS, MUTATION_REGISTRY
from packetforge.templates import get_library, TemplateInfo
from packetforge.fuzzer import FuzzCampaign, FuzzConfig, FuzzResult, ResultType


# ── CSS ───────────────────────────────────────────────────────────────────────
CSS = """
Screen {
    background: #0d1117;
    color: #c9d1d9;
}

Header {
    background: #161b22;
    color: #00ff41;
    text-style: bold;
    height: 1;
}

Footer {
    background: #161b22;
    color: #58a6ff;
    height: 1;
}

/* ── Craft Screen ─────────────────────── */
#craft-container {
    layout: horizontal;
    height: 1fr;
}

#layer-panel {
    width: 22;
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
}

#field-panel {
    width: 1fr;
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
}

#hex-panel {
    width: 46;
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
}

.panel-title {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

#craft-toolbar {
    height: 3;
    background: #161b22;
    padding: 0 1;
    layout: horizontal;
}

#craft-toolbar Button {
    margin-right: 1;
    min-width: 12;
}

/* ── Field table ─────────────────── */
#field-table {
    height: 1fr;
}

/* ── Hex view ────────────────────── */
#hex-content {
    color: #00ff41;
    height: 1fr;
}

#decode-content {
    color: #79c0ff;
    height: auto;
    border-top: solid #30363d;
    padding: 1 0;
}

/* ── Fuzz Screen ─────────────────────── */
#fuzz-container {
    layout: horizontal;
    height: 1fr;
}

#fuzz-config-panel {
    width: 40;
    border: solid #30363d;
    background: #0d1117;
    padding: 1 1;
}

#fuzz-right {
    width: 1fr;
    layout: vertical;
}

#fuzz-stats-panel {
    height: 12;
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
}

#fuzz-log {
    height: 1fr;
    border: solid #30363d;
    background: #0d1117;
}

.stat-box {
    border: solid #21262d;
    padding: 0 1;
    margin: 0;
    height: 3;
    width: 1fr;
    content-align: center middle;
}

.stat-value {
    color: #00ff41;
    text-style: bold;
}

.stat-label {
    color: #8b949e;
}

.stat-anomaly {
    color: #ff6600;
    text-style: bold;
}

/* ── Template Screen ───────────────────── */
#template-container {
    layout: horizontal;
    height: 1fr;
}

#template-list-panel {
    width: 35;
    border: solid #30363d;
    background: #0d1117;
}

#template-detail-panel {
    width: 1fr;
    border: solid #30363d;
    background: #0d1117;
    padding: 1 2;
}

.template-category {
    color: #f0883e;
    text-style: bold;
    margin-top: 1;
}

.template-name {
    color: #c9d1d9;
}

.detail-field {
    color: #8b949e;
}

.detail-value {
    color: #79c0ff;
}

.detail-desc {
    color: #c9d1d9;
    margin: 1 0;
}

.cve-badge {
    color: #f85149;
    text-style: bold;
}

.tag-badge {
    color: #3fb950;
    background: #1f3a1f;
    margin-right: 1;
}

/* ── Replay Screen ─────────────────────── */
#replay-container {
    layout: horizontal;
    height: 1fr;
}

#replay-config-panel {
    width: 38;
    border: solid #30363d;
    background: #0d1117;
    padding: 1 1;
}

#replay-right {
    width: 1fr;
    layout: vertical;
}

#replay-packet-list {
    height: 1fr;
    border: solid #30363d;
    background: #0d1117;
}

#replay-stats-bar {
    height: 5;
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
    layout: horizontal;
}

/* ── Capture Screen ────────────────────── */
#capture-container {
    layout: vertical;
    height: 1fr;
}

#capture-toolbar {
    height: 3;
    background: #161b22;
    layout: horizontal;
    padding: 0 1;
}

#capture-table {
    height: 1fr;
    border: solid #30363d;
}

#capture-detail {
    height: 10;
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
}

/* ── Modal ───────────────────────────── */
#modal-bg {
    align: center middle;
}

#modal-dialog {
    width: 60;
    height: auto;
    border: double #00ff41;
    background: #0d1117;
    padding: 1 2;
}

#modal-title {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

/* ── Shared ──────────────────────────── */
.section-header {
    color: #00ff41;
    text-style: bold;
    border-bottom: solid #30363d;
    margin-bottom: 1;
}

.warning { color: #f0883e; }
.error   { color: #f85149; }
.success { color: #3fb950; }
.muted   { color: #6e7681; }
.bright  { color: #e6edf3; text-style: bold; }

Button.-primary {
    background: #1f6feb;
    border: none;
    color: #ffffff;
}
Button.-danger {
    background: #8d1e1e;
    border: none;
    color: #ffa0a0;
}
Button.-success {
    background: #1a4a1f;
    border: none;
    color: #3fb950;
}
Button.-warning {
    background: #3d2800;
    border: none;
    color: #f0883e;
}

Input {
    border: solid #30363d;
    background: #0d1117;
    color: #c9d1d9;
    height: 3;
}
Input:focus {
    border: solid #1f6feb;
}

Select {
    border: solid #30363d;
    background: #0d1117;
    height: 3;
}

Checkbox {
    color: #c9d1d9;
}

ListView {
    background: #0d1117;
    border: none;
}
ListItem:hover {
    background: #21262d;
}
ListItem.--highlight {
    background: #1f3349;
    color: #79c0ff;
}

DataTable {
    background: #0d1117;
}
DataTable > .datatable--header {
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
}
DataTable > .datatable--cursor {
    background: #1f3349;
}
DataTable > .datatable--hover {
    background: #21262d;
}
"""


# ── Helper widgets ────────────────────────────────────────────────────────────
class SectionHeader(Static):
    def __init__(self, text: str, **kw: Any):
        super().__init__(f"▸ {text}", classes="section-header", **kw)


class StatusBar(Static):
    def update_status(self, msg: str, style: str = "success") -> None:
        self.update(Text(msg, style=style))


# ── Add Layer Modal ───────────────────────────────────────────────────────────
class AddLayerModal(ModalScreen):
    CSS = """
    AddLayerModal { align: center middle; }
    #add-layer-box {
        width: 50; height: auto;
        border: double #00ff41;
        background: #0d1117;
        padding: 1 2;
    }
    """
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        with Container(id="add-layer-box"):
            yield Static("⊕  Add Layer", classes="panel-title")
            for group, layers in LAYER_GROUPS.items():
                yield Static(f"\n[bold #f0883e]{group}[/]")
                for lname in layers:
                    yield Button(lname, id=f"add-{lname}", classes="")

    @on(Button.Pressed)
    def layer_chosen(self, event: Button.Pressed) -> None:
        lid = event.button.id or ""
        if lid.startswith("add-"):
            self.dismiss(lid[4:])


# ── Field Edit Modal ──────────────────────────────────────────────────────────
class EditFieldModal(ModalScreen):
    CSS = """
    EditFieldModal { align: center middle; }
    #edit-box {
        width: 60; height: auto;
        border: double #1f6feb;
        background: #0d1117;
        padding: 1 2;
    }
    """
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, fi: FieldInfo, **kw: Any):
        super().__init__(**kw)
        self._fi = fi

    def compose(self) -> ComposeResult:
        fi = self._fi
        with Container(id="edit-box"):
            yield Static(
                f"[bold #00ff41]Edit:[/] [bold]{fi.name}[/]  "
                f"[dim](type: {fi.ftype})[/]",
                classes="panel-title"
            )
            if fi.choices:
                choices = [(str(k), f"{k} – {v}") for k, v in sorted(fi.choices.items())]
                yield Static("[dim]Select value:[/]")
                for k, label in choices[:20]:
                    yield Button(label, id=f"choice-{k}", classes="")
            else:
                yield Static(f"[dim]Current: {fi.display_value}[/]")
                yield Input(value=fi.display_value, id="field-input",
                            placeholder="Enter value (hex: 0x... or decimal)")
            yield Button("✓  Apply", id="apply-btn", classes="-success")

    @on(Input.Submitted, "#field-input")
    @on(Button.Pressed, "#apply-btn")
    def apply_value(self, event: Any) -> None:
        inp = self.query_one("#field-input", Input)
        self.dismiss(inp.value)

    @on(Button.Pressed)
    def choice_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid.startswith("choice-"):
            self.dismiss(bid[7:])


# ═══════════════════════════════════════════════════════════════════════════════
# CRAFT SCREEN
# ═══════════════════════════════════════════════════════════════════════════════
class CraftScreen(Screen):
    BINDINGS = [
        Binding("a",      "add_layer",     "Add Layer"),
        Binding("d",      "del_layer",     "Del Layer"),
        Binding("ctrl+s", "save_template", "Save"),
        Binding("ctrl+p", "send_packet",   "Send"),
        Binding("ctrl+e", "export_pcap",   "Export PCAP"),
        Binding("f",      "fuzz_packet",   "Fuzz This"),
        Binding("r",      "refresh_hex",   "Refresh"),
    ]

    def __init__(self, stack: Optional[PacketStack] = None, **kw: Any):
        super().__init__(**kw)
        self.stack = stack or PacketStack(name="new_packet")
        self._selected_layer_idx: int = 0
        self._iface = default_iface()

    def compose(self) -> ComposeResult:
        with Container(id="craft-container"):
            # ── Layer panel ────────────────────────────────────────────────
            with Container(id="layer-panel"):
                yield Static("◈ LAYERS", classes="panel-title")
                yield ListView(id="layer-list")
                yield Button("⊕ Add",    id="btn-add-layer", classes="-primary")
                yield Button("⊖ Remove", id="btn-del-layer", classes="-danger")
                yield Button("↑ Up",     id="btn-move-up",   classes="")
                yield Button("↓ Down",   id="btn-move-down", classes="")

            # ── Field panel ────────────────────────────────────────────────
            with Container(id="field-panel"):
                yield Static("◈ FIELDS", classes="panel-title")
                yield DataTable(id="field-table", cursor_type="row")

            # ── Hex panel ─────────────────────────────────────────────────
            with Container(id="hex-panel"):
                yield Static("◈ HEX DUMP", classes="panel-title")
                yield Log(id="hex-content", auto_scroll=False)
                yield Static("◈ DECODE", classes="panel-title")
                yield Log(id="decode-content", auto_scroll=False)

        # ── Toolbar ────────────────────────────────────────────────────────
        with Container(id="craft-toolbar"):
            yield Button("⚡ Send",        id="btn-send",    classes="-success")
            yield Button("💾 Save",        id="btn-save",    classes="-primary")
            yield Button("📂 Load Tmpl",   id="btn-load",    classes="")
            yield Button("🎯 Fuzz This",   id="btn-fuzz",    classes="-warning")
            yield Button("📦 Export PCAP", id="btn-export",  classes="")
            yield Button("🗑 Clear",       id="btn-clear",   classes="-danger")
            yield StatusBar("Ready", id="craft-status")

    def on_mount(self) -> None:
        self._setup_field_table()
        self._refresh_all()

    def _setup_field_table(self) -> None:
        tbl = self.query_one("#field-table", DataTable)
        tbl.add_column("Field",   width=18)
        tbl.add_column("Value",   width=28)
        tbl.add_column("Type",    width=8)
        tbl.add_column("Default", width=20)

    def _refresh_all(self) -> None:
        self._refresh_layer_list()
        self._refresh_fields()
        self._refresh_hex()

    def _refresh_layer_list(self) -> None:
        lv = self.query_one("#layer-list", ListView)
        lv.clear()
        for i, name in enumerate(self.stack.layer_names()):
            icon = "▶" if i == self._selected_layer_idx else "  "
            lv.append(ListItem(Label(f"{icon} {i}: {name}")))

    def _refresh_fields(self) -> None:
        tbl = self.query_one("#field-table", DataTable)
        tbl.clear()
        layer = self.stack.get_layer(self._selected_layer_idx)
        if layer is None:
            return
        for fi in get_layer_fields(layer):
            style_val = "bright"
            if fi.value == fi.default:
                style_val = "muted"
            tbl.add_row(
                Text(fi.name, style="#79c0ff"),
                Text(fi.display_value, style=style_val),
                Text(fi.ftype, style="#6e7681"),
                Text(str(fi.default)[:20], style="dim"),
                key=fi.name,
            )

    def _refresh_hex(self) -> None:
        hex_log = self.query_one("#hex-content", Log)
        dec_log = self.query_one("#decode-content", Log)
        hex_log.clear()
        dec_log.clear()
        try:
            for line in self.stack.hex_lines():
                hex_log.write_line(line)
            size_kb = self.stack.total_bytes()
            hex_log.write_line(f"\n[dim]Total: {size_kb} bytes[/]")
            for line in self.stack.decode_summary():
                dec_log.write_line(line)
        except Exception as e:
            hex_log.write_line(f"[red]Build error: {e}[/]")

    # ── Events ────────────────────────────────────────────────────────────────
    @on(ListView.Selected, "#layer-list")
    def layer_selected(self, event: ListView.Selected) -> None:
        self._selected_layer_idx = event.list_view.index
        self._refresh_fields()
        self._refresh_hex()

    @on(DataTable.RowSelected, "#field-table")
    @work
    async def field_row_selected(self, event: DataTable.RowSelected) -> None:
        layer = self.stack.get_layer(self._selected_layer_idx)
        if layer is None:
            return
        row_key = event.row_key.value
        fields = {fi.name: fi for fi in get_layer_fields(layer)}
        fi = fields.get(str(row_key))
        if fi is None:
            return
        new_val = await self.app.push_screen_wait(EditFieldModal(fi))
        if new_val is not None:
            ok, err = set_layer_field(layer, fi.name, str(new_val))
            if ok:
                self._refresh_fields()
                self._refresh_hex()
                self._status(f"Set {fi.name} = {new_val}", "success")
            else:
                self._status(f"Error: {err}", "error")

    @on(Button.Pressed, "#btn-add-layer")
    @work
    async def action_add_layer(self) -> None:
        choice = await self.app.push_screen_wait(AddLayerModal())
        if choice:
            ok, err = self.stack.add_layer(choice)
            if ok:
                self._refresh_all()
                self._status(f"Added {choice}", "success")
            else:
                self._status(err, "error")

    @on(Button.Pressed, "#btn-del-layer")
    def action_del_layer(self) -> None:
        ok, err = self.stack.remove_layer(self._selected_layer_idx)
        if ok:
            self._selected_layer_idx = max(0, self._selected_layer_idx - 1)
            self._refresh_all()
            self._status("Layer removed", "warning")
        else:
            self._status(err, "error")

    @on(Button.Pressed, "#btn-move-up")
    def move_up(self) -> None:
        i = self._selected_layer_idx
        if i > 0:
            self.stack.move_layer(i, i - 1)
            self._selected_layer_idx = i - 1
            self._refresh_all()

    @on(Button.Pressed, "#btn-move-down")
    def move_down(self) -> None:
        i = self._selected_layer_idx
        if i < len(self.stack.layers) - 1:
            self.stack.move_layer(i, i + 1)
            self._selected_layer_idx = i + 1
            self._refresh_all()

    @on(Button.Pressed, "#btn-send")
    def action_send_packet(self) -> None:
        ok, msg = self.stack.send_packet(iface=self._iface, count=1)
        self._status(msg, "success" if ok else "error")

    @on(Button.Pressed, "#btn-save")
    @work
    async def action_save_template(self) -> None:
        name = await self.app.push_screen_wait(NameInputModal("Save Template", "Enter template name:"))
        if name:
            from packetforge.templates import TemplateInfo, get_library
            self.stack.name = name.replace(" ", "_")
            info = TemplateInfo(
                id=self.stack.name,
                name=name,
                description="Custom template",
                category="Custom",
                stack=self.stack.clone(),
            )
            get_library().save(info)
            self._status(f"Saved template '{name}'", "success")

    @on(Button.Pressed, "#btn-load")
    @work
    async def action_load_template(self) -> None:
        result = await self.app.push_screen_wait(TemplateBrowserModal())
        if result:
            stack = get_library().load_stack(result)
            if stack:
                self.stack = stack
                self._selected_layer_idx = 0
                self._refresh_all()
                self._status(f"Loaded: {result}", "success")

    @on(Button.Pressed, "#btn-fuzz")
    def action_fuzz_packet(self) -> None:
        self.app.switch_screen(
            FuzzScreen(template_stack=self.stack.clone())
        )

    @on(Button.Pressed, "#btn-export")
    def action_export_pcap(self) -> None:
        path = Path.home() / "packetforge_export.pcap"
        ok, msg = self.stack.export_pcap(str(path))
        self._status(msg, "success" if ok else "error")

    @on(Button.Pressed, "#btn-clear")
    def clear_stack(self) -> None:
        self.stack = PacketStack(name="new_packet")
        self._selected_layer_idx = 0
        self._refresh_all()
        self._status("Cleared", "muted")

    def _status(self, msg: str, style: str = "success") -> None:
        color_map = {
            "success": "#3fb950",
            "error": "#f85149",
            "warning": "#f0883e",
            "muted": "#6e7681",
        }
        c = color_map.get(style, "#c9d1d9")
        self.query_one("#craft-status", StatusBar).update(
            Text(f"● {msg}", style=c)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# FUZZ SCREEN
# ═══════════════════════════════════════════════════════════════════════════════
class FuzzScreen(Screen):
    BINDINGS = [
        Binding("ctrl+r", "start_fuzz",  "Start"),
        Binding("ctrl+c", "stop_fuzz",   "Stop"),
        Binding("ctrl+s", "save_report", "Save Report"),
    ]

    def __init__(self, template_stack: Optional[PacketStack] = None, **kw: Any):
        super().__init__(**kw)
        self._template = template_stack or PacketStack(name="fuzz_template")
        self._campaign: Optional[FuzzCampaign] = None
        self._result_queue: asyncio.Queue = asyncio.Queue()

    def compose(self) -> ComposeResult:
        with Container(id="fuzz-container"):
            # ── Config panel ────────────────────────────────────────────────
            with ScrollableContainer(id="fuzz-config-panel"):
                yield SectionHeader("TARGET")
                yield Label("Interface:")
                yield Input(value=default_iface(), id="fuzz-iface", placeholder="eth0")
                yield Label("Target IP:")
                yield Input(value="192.168.1.1", id="fuzz-target-ip")
                yield Label("Target Port:")
                yield Input(value="80", id="fuzz-target-port")

                yield SectionHeader("CAMPAIGN")
                yield Label("Max Packets:")
                yield Input(value="500", id="fuzz-max-pkt")
                yield Label("Rate (PPS):")
                yield Input(value="100", id="fuzz-pps")
                yield Label("Timeout (s):")
                yield Input(value="2", id="fuzz-timeout")
                yield Checkbox("Capture Responses", value=True, id="fuzz-capture")
                yield Checkbox("Stop on Response",  value=False, id="fuzz-stop-on")

                yield SectionHeader("MUTATIONS")
                for m in ALL_MUTATIONS:
                    yield Checkbox(
                        f"{m.name}", id=f"mut-{m.name}",
                        value=(m.name in ("boundary", "bit_flip", "proto_specific")),
                    )

                yield SectionHeader("LAYERS")
                for lname in self._template.layer_names():
                    yield Checkbox(f"Fuzz {lname}", id=f"fuzz-layer-{lname}", value=True)

                yield Button("⚡ START FUZZING", id="btn-start-fuzz", classes="-success")
                yield Button("⏹ STOP",          id="btn-stop-fuzz",  classes="-danger")

            # ── Right panel ─────────────────────────────────────────────────
            with Container(id="fuzz-right"):
                # Stats bar
                with Horizontal(id="fuzz-stats-panel"):
                    with Container(classes="stat-box"):
                        yield Static("0", id="stat-sent",    classes="stat-value")
                        yield Static("SENT",               classes="stat-label")
                    with Container(classes="stat-box"):
                        yield Static("0", id="stat-resp",    classes="stat-value")
                        yield Static("RESPONSES",          classes="stat-label")
                    with Container(classes="stat-box"):
                        yield Static("0", id="stat-anom",    classes="stat-anomaly")
                        yield Static("ANOMALIES",          classes="stat-label")
                    with Container(classes="stat-box"):
                        yield Static("0", id="stat-err",     classes="stat-value")
                        yield Static("ERRORS",             classes="stat-label")
                    with Container(classes="stat-box"):
                        yield Static("0.0", id="stat-pps",   classes="stat-value")
                        yield Static("PPS",                classes="stat-label")
                    with Container(classes="stat-box"):
                        yield Static("0%", id="stat-rate",   classes="stat-value")
                        yield Static("RESP RATE",          classes="stat-label")

                # Result log
                yield Log(id="fuzz-log", auto_scroll=True)

    def on_mount(self) -> None:
        log = self.query_one("#fuzz-log", Log)
        log.write_line(
            "[bold #00ff41]PacketForge Fuzzer[/] – configure campaign and press ⚡ START"
        )
        log.write_line(f"Template: [bold]{self._template.name}[/] "
                       f"({len(self._template.layers)} layers, "
                       f"{self._template.total_bytes()} bytes)")
        log.write_line(
            f"[dim]Available mutations: {', '.join(m.name for m in ALL_MUTATIONS)}[/]"
        )

    def _build_config(self) -> FuzzConfig:
        def _inp(id_: str, default: str = "") -> str:
            try:
                return self.query_one(f"#{id_}", Input).value or default
            except Exception:
                return default

        mutations = [
            m.name for m in ALL_MUTATIONS
            if self._checkbox(f"mut-{m.name}")
        ]
        fuzz_layers = [
            lname for lname in self._template.layer_names()
            if self._checkbox(f"fuzz-layer-{lname}")
        ]
        return FuzzConfig(
            iface=_inp("fuzz-iface", default_iface()),
            target_ip=_inp("fuzz-target-ip"),
            target_port=int(_inp("fuzz-target-port", "80")),
            max_packets=int(_inp("fuzz-max-pkt", "500")),
            pps=float(_inp("fuzz-pps", "100")),
            timeout=float(_inp("fuzz-timeout", "2")),
            capture_responses=self._checkbox("fuzz-capture"),
            stop_on_response=self._checkbox("fuzz-stop-on"),
            mutations=mutations,
            fuzz_layers=fuzz_layers,
        )

    def _checkbox(self, id_: str) -> bool:
        try:
            return self.query_one(f"#{id_}", Checkbox).value
        except Exception:
            return False

    @on(Button.Pressed, "#btn-start-fuzz")
    def start_fuzz(self) -> None:
        if self._campaign and self._campaign.is_running:
            self._log("Campaign already running", "warning")
            return
        if not SCAPY_AVAILABLE:
            self._log("Scapy not available – install with: pip install scapy", "error")
            return

        config = self._build_config()
        log = self.query_one("#fuzz-log", Log)
        log.write_line(
            f"\n[bold #00ff41]▶ Starting campaign[/] – "
            f"{config.max_packets} pkts @ {config.pps} PPS  "
            f"mutations: {', '.join(config.mutations)}"
        )

        def _on_result(result: FuzzResult) -> None:
            # Thread-safe push via call_from_thread
            try:
                self.app.call_from_thread(self._handle_result, result)
            except Exception:
                pass

        self._campaign = FuzzCampaign(
            template=self._template,
            config=config,
            on_result=_on_result,
        )
        self._campaign.start()
        self._start_stat_ticker()

    def _handle_result(self, result: FuzzResult) -> None:
        log = self.query_one("#fuzz-log", Log)
        stats = self._campaign.stats if self._campaign else None

        icon = "·"
        style = "dim"
        if result.result_type == ResultType.RESPONSE:
            icon = "◆"; style = "#79c0ff"
        elif result.result_type == ResultType.ANOMALY:
            icon = "⚠"; style = "#f0883e bold"
        elif result.result_type == ResultType.ERROR:
            icon = "✗"; style = "#f85149"

        msg = (
            f"[{style}]{icon}[/] "
            f"#{result.seq:04d} "
            f"[dim]{result.layer}[/].[bold]{result.field_name}[/] "
            f"← [#f0883e]{str(result.mutated_value)[:24]}[/]"
        )
        if result.response_summary:
            msg += f" → [#3fb950]{result.response_summary[:40]}[/]"
        if result.error:
            msg += f" [#f85149]{result.error}[/]"

        log.write_line(msg)

        # Update stats display
        if stats:
            self._update_stats(stats)

    def _update_stats(self, s: Any) -> None:
        try:
            self.query_one("#stat-sent", Static).update(str(s.total_sent))
            self.query_one("#stat-resp", Static).update(str(s.total_responses))
            self.query_one("#stat-anom", Static).update(str(s.total_anomalies))
            self.query_one("#stat-err",  Static).update(str(s.total_errors))
            self.query_one("#stat-pps",  Static).update(f"{s.pps_actual:.0f}")
            self.query_one("#stat-rate", Static).update(f"{s.response_rate:.0f}%")
        except Exception:
            pass

    def _start_stat_ticker(self) -> None:
        async def ticker() -> None:
            while self._campaign and self._campaign.is_running:
                await asyncio.sleep(1)
                if self._campaign:
                    self._update_stats(self._campaign.stats)
            if self._campaign:
                self._update_stats(self._campaign.stats)
                s = self._campaign.summary()
                self._log(
                    f"\n[bold #00ff41]■ Campaign complete[/] – "
                    f"sent={s['total_sent']} responses={s['total_responses']} "
                    f"anomalies={s['total_anomalies']} elapsed={s['elapsed_s']}s",
                    "success"
                )
        asyncio.create_task(ticker())

    @on(Button.Pressed, "#btn-stop-fuzz")
    def stop_fuzz(self) -> None:
        if self._campaign:
            self._campaign.stop()
            self._log("Campaign stopped", "warning")

    def _log(self, msg: str, style: str = "") -> None:
        log = self.query_one("#fuzz-log", Log)
        log.write_line(msg)


# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE SCREEN
# ═══════════════════════════════════════════════════════════════════════════════
class TemplateScreen(Screen):
    BINDINGS = [
        Binding("enter", "load_template", "Load"),
        Binding("d",     "delete_template", "Delete"),
        Binding("/",     "search",          "Search"),
    ]

    def compose(self) -> ComposeResult:
        with Container(id="template-container"):
            with Container(id="template-list-panel"):
                yield Static("◈ TEMPLATES", classes="panel-title")
                yield Input(placeholder="🔍 Search...", id="tmpl-search")
                yield ListView(id="tmpl-list")

            with ScrollableContainer(id="template-detail-panel"):
                yield Static("◈ DETAILS", classes="panel-title")
                yield Static("Select a template to view details", id="tmpl-detail")
                with Horizontal():
                    yield Button("⊕ Load to Crafter", id="btn-tmpl-load", classes="-success")
                    yield Button("🎯 Load to Fuzzer",  id="btn-tmpl-fuzz", classes="-warning")

    def on_mount(self) -> None:
        self._populate_list()

    def _populate_list(self, query: str = "") -> None:
        lib = get_library()
        lv = self.query_one("#tmpl-list", ListView)
        lv.clear()
        templates = lib.search(query) if query else lib.all()
        cats = {}
        for t in templates:
            cats.setdefault(t.category, []).append(t)
        for cat in sorted(cats):
            lv.append(ListItem(Label(f"[bold #f0883e]── {cat} ──[/]")))
            for t in cats[cat]:
                cve = f" [dim #f85149][{t.cve}][/]" if t.cve else ""
                lv.append(ListItem(Label(f"  {t.name}{cve}"), id=f"tmpl-{t.id}"))

    @on(Input.Changed, "#tmpl-search")
    def on_search(self, event: Input.Changed) -> None:
        self._populate_list(event.value)

    @on(ListView.Selected, "#tmpl-list")
    def on_template_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        if item_id.startswith("tmpl-"):
            tid = item_id[5:]
            self._show_detail(tid)

    def _show_detail(self, tid: str) -> None:
        t = get_library().get(tid)
        if not t:
            return
        tags = " ".join(f"[#3fb950][{tg}][/]" for tg in t.tags)
        cve_line = f"\n[bold]CVE:[/] [#f85149]{t.cve}[/]" if t.cve else ""
        layers = ""
        if t.stack:
            layers = "\n[bold]Layers:[/] " + " / ".join(t.stack.layer_names())
            layers += f"\n[bold]Size:[/] {t.stack.total_bytes()} bytes"
        detail = (
            f"[bold #00ff41]{t.name}[/]\n"
            f"[dim #6e7681]ID: {t.id}  Category: {t.category}[/]{cve_line}\n\n"
            f"[#c9d1d9]{t.description}[/]\n\n"
            f"[bold]Tags:[/] {tags}{layers}"
        )
        self.query_one("#tmpl-detail", Static).update(detail)
        self._selected_tid = tid

    @on(Button.Pressed, "#btn-tmpl-load")
    def load_to_crafter(self) -> None:
        tid = getattr(self, "_selected_tid", None)
        if tid:
            stack = get_library().load_stack(tid)
            if stack:
                self.app.switch_screen(CraftScreen(stack=stack))

    @on(Button.Pressed, "#btn-tmpl-fuzz")
    def load_to_fuzzer(self) -> None:
        tid = getattr(self, "_selected_tid", None)
        if tid:
            stack = get_library().load_stack(tid)
            if stack:
                self.app.switch_screen(FuzzScreen(template_stack=stack))


# ═══════════════════════════════════════════════════════════════════════════════
# REPLAY SCREEN
# ═══════════════════════════════════════════════════════════════════════════════
class ReplayScreen(Screen):
    BINDINGS = [
        Binding("ctrl+o", "open_pcap",    "Open PCAP"),
        Binding("ctrl+r", "start_replay", "Replay"),
        Binding("ctrl+c", "stop_replay",  "Stop"),
    ]

    def __init__(self, **kw: Any):
        super().__init__(**kw)
        self._engine: Optional[Any] = None
        self._pcap_loaded = False

    def compose(self) -> ComposeResult:
        with Container(id="replay-container"):
            with ScrollableContainer(id="replay-config-panel"):
                yield SectionHeader("PCAP FILE")
                yield Input(placeholder="/path/to/capture.pcap", id="replay-path")
                yield Button("📂 Load PCAP", id="btn-load-pcap", classes="-primary")

                yield SectionHeader("REPLAY CONFIG")
                yield Label("Interface:")
                yield Input(value=default_iface(), id="replay-iface")
                yield Label("Rate PPS (0=original timing):")
                yield Input(value="100", id="replay-pps")
                yield Label("Loop Count:")
                yield Input(value="1", id="replay-loop")
                yield Checkbox("Randomise Src IP",   id="replay-rnd-ip",   value=False)
                yield Checkbox("Randomise Src MAC",  id="replay-rnd-mac",  value=False)
                yield Checkbox("Randomise Src Port", id="replay-rnd-port", value=False)

                yield SectionHeader("CONTROLS")
                yield Button("▶ Start Replay", id="btn-start-replay", classes="-success")
                yield Button("⏹ Stop",         id="btn-stop-replay",  classes="-danger")

            with Container(id="replay-right"):
                with Horizontal(id="replay-stats-bar"):
                    yield Static("─── Load a PCAP to begin ───", id="replay-stats-text")

                yield DataTable(id="replay-packet-list", cursor_type="row")
                yield Log(id="replay-log", auto_scroll=True)

    def on_mount(self) -> None:
        tbl = self.query_one("#replay-packet-list", DataTable)
        tbl.add_column("#",        width=5)
        tbl.add_column("Summary",  width=70)

    @on(Button.Pressed, "#btn-load-pcap")
    def load_pcap(self) -> None:
        from packetforge.replay import ReplayEngine, ReplayConfig
        path = self.query_one("#replay-path", Input).value.strip()
        if not path:
            self._log("Enter a PCAP file path", "error")
            return
        engine = ReplayEngine(path)
        ok, msg = engine.load()
        if not ok:
            self._log(f"Load failed: {msg}", "error")
            return
        self._engine = engine
        self._pcap_loaded = True
        tbl = self.query_one("#replay-packet-list", DataTable)
        tbl.clear()
        for summary in engine.packet_summaries()[:500]:
            parts = summary.split("  ", 1)
            tbl.add_row(parts[0], parts[1] if len(parts) > 1 else "")
        info = engine.pcap_info()
        self.query_one("#replay-stats-text", Static).update(
            f"  Packets: [bold]{info['packets']}[/]  "
            f"Protocols: {', '.join(f'{k}:{v}' for k,v in list(info['protocols'].items())[:5])}"
        )
        self._log(f"Loaded: {path} ({info['packets']} packets)", "success")

    @on(Button.Pressed, "#btn-start-replay")
    def start_replay(self) -> None:
        if not self._engine:
            self._log("No PCAP loaded", "error")
            return
        from packetforge.replay import ReplayConfig
        try:
            pps = float(self.query_one("#replay-pps", Input).value or "100")
            loop = int(self.query_one("#replay-loop", Input).value or "1")
        except ValueError:
            pps, loop = 100.0, 1

        cfg = ReplayConfig(
            iface=self.query_one("#replay-iface", Input).value or default_iface(),
            pps=pps,
            loop=loop,
            randomise_src_ip=self.query_one("#replay-rnd-ip", Checkbox).value,
            randomise_src_mac=self.query_one("#replay-rnd-mac", Checkbox).value,
            randomise_src_port=self.query_one("#replay-rnd-port", Checkbox).value,
        )
        self._engine.config = cfg

        def on_result(r: Any) -> None:
            try:
                self.app.call_from_thread(
                    self._log,
                    f"#{r.seq:04d} {'✓' if r.ok else '✗'}  {r.error or ''}",
                    "success" if r.ok else "error",
                )
            except Exception:
                pass

        self._engine.on_result = on_result
        self._engine.start()
        self._log(f"Replaying at {pps} PPS × {loop} pass(es)…", "success")

    @on(Button.Pressed, "#btn-stop-replay")
    def stop_replay(self) -> None:
        if self._engine:
            self._engine.stop()
            self._log("Replay stopped", "warning")

    def _log(self, msg: str, style: str = "") -> None:
        log = self.query_one("#replay-log", Log)
        color = {"success": "#3fb950", "error": "#f85149",
                 "warning": "#f0883e"}.get(style, "#c9d1d9")
        log.write_line(f"[{color}]{msg}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# CAPTURE SCREEN
# ═══════════════════════════════════════════════════════════════════════════════
class CaptureScreen(Screen):
    BINDINGS = [
        Binding("ctrl+r", "start_capture", "Start"),
        Binding("ctrl+c", "stop_capture",  "Stop"),
        Binding("ctrl+s", "save_capture",  "Save PCAP"),
        Binding("enter",  "craft_from",    "→ Crafter"),
    ]

    def __init__(self, **kw: Any):
        super().__init__(**kw)
        self._captured: List[Any] = []
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_capture = threading.Event()

    def compose(self) -> ComposeResult:
        with Container(id="capture-container"):
            with Container(id="capture-toolbar"):
                yield Label("Interface:")
                yield Input(value=default_iface(), id="cap-iface", placeholder="eth0")
                yield Label("BPF Filter:")
                yield Input(value="", id="cap-bpf", placeholder="tcp port 80")
                yield Label("Count:")
                yield Input(value="200", id="cap-count", placeholder="200")
                yield Button("▶ Start",     id="btn-cap-start", classes="-success")
                yield Button("⏹ Stop",      id="btn-cap-stop",  classes="-danger")
                yield Button("💾 Save PCAP",id="btn-cap-save",  classes="-primary")
                yield Button("→ Crafter",   id="btn-cap-craft", classes="")

            yield DataTable(id="capture-table", cursor_type="row")
            yield Log(id="capture-detail", auto_scroll=True)

    def on_mount(self) -> None:
        tbl = self.query_one("#capture-table", DataTable)
        tbl.add_column("#",      width=5)
        tbl.add_column("Time",   width=12)
        tbl.add_column("Src",    width=22)
        tbl.add_column("Dst",    width=22)
        tbl.add_column("Proto",  width=8)
        tbl.add_column("Length", width=8)
        tbl.add_column("Info",   width=40)

    @on(Button.Pressed, "#btn-cap-start")
    def start_capture(self) -> None:
        if not SCAPY_AVAILABLE:
            self._detail("Scapy not available", "error")
            return
        iface = self.query_one("#cap-iface", Input).value or default_iface()
        bpf = self.query_one("#cap-bpf", Input).value.strip()
        try:
            count = int(self.query_one("#cap-count", Input).value or "200")
        except ValueError:
            count = 200

        self._stop_capture.clear()
        self._captured = []

        def _prn(pkt: Any) -> None:
            self._captured.append(pkt)
            try:
                self.app.call_from_thread(self._add_packet_row, pkt)
            except Exception:
                pass

        def _sniff() -> None:
            from packetforge.engine import capture_packets
            capture_packets(
                iface=iface, count=count, bpf=bpf, prn=_prn,
                timeout=None,
            )

        self._capture_thread = threading.Thread(target=_sniff, daemon=True)
        self._capture_thread.start()
        self._detail(f"Capturing on {iface} (bpf={bpf or 'none'}, count={count})…", "success")

    def _add_packet_row(self, pkt: Any) -> None:
        tbl = self.query_one("#capture-table", DataTable)
        n = len(self._captured)
        try:
            t = f"{pkt.time:.3f}"
        except Exception:
            t = "?"
        try:
            from scapy.layers.inet import IP, TCP, UDP
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else type(pkt).__name__
        except Exception:
            src = dst = proto = "?"
        length = len(bytes(pkt))
        info = pkt.summary()[:40]
        tbl.add_row(str(n), t, src, dst, proto, str(length), info)

    @on(Button.Pressed, "#btn-cap-stop")
    def stop_capture(self) -> None:
        self._stop_capture.set()
        self._detail(f"Capture stopped – {len(self._captured)} packets", "warning")

    @on(Button.Pressed, "#btn-cap-save")
    def save_capture(self) -> None:
        if not self._captured:
            self._detail("No packets captured", "error")
            return
        from scapy.all import wrpcap
        path = str(Path.home() / "packetforge_capture.pcap")
        try:
            wrpcap(path, self._captured)
            self._detail(f"Saved {len(self._captured)} packets to {path}", "success")
        except Exception as e:
            self._detail(f"Save failed: {e}", "error")

    @on(DataTable.RowSelected, "#capture-table")
    def show_packet_detail(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._captured):
            pkt = self._captured[idx]
            self._detail(pkt.show(dump=True) or str(pkt.summary()))

    @on(Button.Pressed, "#btn-cap-craft")
    def craft_from_packet(self) -> None:
        tbl = self.query_one("#capture-table", DataTable)
        idx = tbl.cursor_row
        if 0 <= idx < len(self._captured):
            pkt = self._captured[idx]
            # Convert live packet to PacketStack
            ps = PacketStack(name="from_capture")
            current = pkt
            while current and current.__class__.__name__ not in ("NoPayload", "Padding"):
                lname = current.__class__.__name__
                if lname in LAYER_REGISTRY:
                    ok, _ = ps.add_layer(lname)
                    if ok:
                        layer = ps.layers[-1]
                        for fd in current.fields_desc:
                            try:
                                setattr(layer, fd.name, getattr(current, fd.name))
                            except Exception:
                                pass
                current = current.payload
            self.app.switch_screen(CraftScreen(stack=ps))

    def _detail(self, msg: str, style: str = "") -> None:
        color = {"success": "#3fb950", "error": "#f85149",
                 "warning": "#f0883e"}.get(style, "#c9d1d9")
        self.query_one("#capture-detail", Log).write_line(f"[{color}]{msg}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# HELP SCREEN
# ═══════════════════════════════════════════════════════════════════════════════
HELP_TEXT = """
[bold #00ff41]PacketForge[/] – Elite Protocol Fuzzer & Packet Crafter

[bold #f0883e]CRAFT[/]
  Build packets layer-by-layer using the visual editor.
  Click any field row to edit its value (hex, decimal, or string).
  ⊕ Add / ⊖ Remove layers, reorder with ↑↓.
  Send directly via raw socket (requires root).
  Export as PCAP or load any built-in template.

[bold #f0883e]FUZZ[/]
  Select a packet template, choose mutation strategies and target fields.
  The campaign engine iterates all applicable mutations at configured PPS.
  Anomaly detection flags ICMP errors, TCP RSTs, and size deviations.
  Results logged live with colour-coded severity.

[bold #f0883e]TEMPLATES[/]
  20+ built-in attack templates covering:
  • DoS/Flood: SYN, ACK, UDP, ICMP, RA Flood
  • Amplification: DNS ANY, NTP MONLIST, Smurf
  • Spoofing: ARP MITM, DNS Spoof, ICMP Redirect
  • L2: VLAN Double-Tagging, ARP Flood
  • Malformed: Teardrop, Ping-of-Death, Land, Bad IHL
  • Recon: Xmas, NULL scan, TCP RST inject

[bold #f0883e]REPLAY[/]
  Load any PCAP file and replay at custom PPS with optional mutations:
  randomise source IP, MAC, or port on the fly.

[bold #f0883e]CAPTURE[/]
  Live packet sniffing with BPF filtering.
  Click any captured packet → send it to the Crafter for editing.

[bold #f0883e]KEY BINDINGS[/]
  Tab / Shift+Tab    Navigate tabs
  ctrl+q             Quit
  ctrl+d             Toggle dark mode
  ? / F1             This help
  (screen-specific bindings shown in footer)

[bold #f0883e]MUTATIONS[/]
  bit_flip           Flip individual bits in int/bytes fields
  boundary           Edge-case integer values (0, 127, 0xFF, 0xFFFF…)
  random_bytes       Random byte-string replacements
  random_int         Random integer values
  increment          Walk field from 0 upward
  format_string      Classic %n/%s/%x format string payloads
  overflow           Buffer-overflow strings (64–1024 bytes)
  null_byte          Null injection / empty payload tests
  proto_specific     Protocol-aware (TTL, flags, seq, frag offsets…)
  enum_cycle         Iterate all valid enum values + 1 invalid

[bold #f0883e]NOTES[/]
  Raw socket send/receive requires root privileges (sudo).
  Fuzzing can generate illegal traffic – use on your own lab network only.
  All templates are provided for research and authorised testing only.
"""


class HelpScreen(Screen):
    BINDINGS = [Binding("escape,q,?", "dismiss_help", "Close")]

    def compose(self) -> ComposeResult:
        with ScrollableContainer():
            yield Static(HELP_TEXT, id="help-text")

    def action_dismiss_help(self) -> None:
        self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# MISC MODALS
# ═══════════════════════════════════════════════════════════════════════════════
class NameInputModal(ModalScreen):
    CSS = """
    NameInputModal { align: center middle; }
    #name-box {
        width: 60; height: auto;
        border: double #1f6feb;
        background: #0d1117;
        padding: 1 2;
    }
    """
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, title: str, prompt: str, **kw: Any):
        super().__init__(**kw)
        self._title = title
        self._prompt = prompt

    def compose(self) -> ComposeResult:
        with Container(id="name-box"):
            yield Static(f"[bold #00ff41]{self._title}[/]")
            yield Static(self._prompt, classes="muted")
            yield Input(id="name-input")
            yield Button("✓ OK", id="name-ok", classes="-success")

    @on(Input.Submitted)
    @on(Button.Pressed, "#name-ok")
    def submit(self, event: Any) -> None:
        val = self.query_one("#name-input", Input).value.strip()
        self.dismiss(val or None)


class TemplateBrowserModal(ModalScreen):
    """Compact modal for picking a template by ID."""
    CSS = """
    TemplateBrowserModal { align: center middle; }
    #tbrowser-box {
        width: 70; height: 30;
        border: double #00ff41;
        background: #0d1117;
        padding: 1 2;
    }
    """
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        with Container(id="tbrowser-box"):
            yield Static("[bold #00ff41]Select Template[/]")
            yield Input(placeholder="🔍 Filter…", id="tbm-search")
            yield ListView(id="tbm-list")

    def on_mount(self) -> None:
        self._populate()

    def _populate(self, query: str = "") -> None:
        lib = get_library()
        lv = self.query_one("#tbm-list", ListView)
        lv.clear()
        templates = lib.search(query) if query else lib.all()
        for t in templates:
            lv.append(ListItem(Label(f"[#f0883e]{t.category:<14}[/]  {t.name}"), id=f"t-{t.id}"))

    @on(Input.Changed, "#tbm-search")
    def on_search(self, e: Input.Changed) -> None:
        self._populate(e.value)

    @on(ListView.Selected)
    def on_select(self, e: ListView.Selected) -> None:
        iid = e.item.id or ""
        if iid.startswith("t-"):
            self.dismiss(iid[2:])


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════
class PacketForgeApp(App):
    CSS = CSS
    TITLE = "PacketForge"
    BINDINGS = [
        Binding("ctrl+q",   "quit",        "Quit"),
        Binding("1",        "show_craft",   "Craft",     show=True),
        Binding("2",        "show_fuzz",    "Fuzz",      show=True),
        Binding("3",        "show_templates","Templates", show=True),
        Binding("4",        "show_replay",  "Replay",    show=True),
        Binding("5",        "show_capture", "Capture",   show=True),
        Binding("?",        "show_help",    "Help",      show=True),
    ]

    def on_mount(self) -> None:
        self.push_screen(CraftScreen())
        if not SCAPY_AVAILABLE:
            self.notify(
                "Scapy not installed. Packet send/receive disabled.\n"
                "Install: pip install scapy",
                severity="warning",
                timeout=8,
            )

    def action_show_craft(self)     -> None: self.switch_screen(CraftScreen())
    def action_show_fuzz(self)      -> None: self.switch_screen(FuzzScreen())
    def action_show_templates(self) -> None: self.switch_screen(TemplateScreen())
    def action_show_replay(self)    -> None: self.switch_screen(ReplayScreen())
    def action_show_capture(self)   -> None: self.switch_screen(CaptureScreen())
    def action_show_help(self)      -> None: self.push_screen(HelpScreen())


def run_tui() -> None:
    PacketForgeApp().run()
