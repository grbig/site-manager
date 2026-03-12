"""
tui.py — Textual TUI for site-manager: real-time IP monitor with block/unblock.
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    Static,
)
from textual.reactive import reactive

if TYPE_CHECKING:
    from main import AppState
    from firewall import FirewallManager
    from monitor import IPRecord


# ─────────────────────────────────────────────────────────────── #
# Detail panel                                                     #
# ─────────────────────────────────────────────────────────────── #

class DetailPanel(Static):
    """Shows detailed information about the selected IP."""

    DEFAULT_CSS = """
    DetailPanel {
        height: 11;
        border: solid $primary;
        padding: 0 1;
        background: $surface;
    }
    """

    # Use a single Static child whose content is updated in place — avoids
    # the DuplicateIds error that occurs when remove_children() + mount()
    # are called faster than Textual processes the removal from its registry.
    def compose(self) -> ComposeResult:
        yield Static("── Selecione um IP na tabela ──", id="detail-content")

    def update_record(self, record: "IPRecord | None") -> None:
        """Update the panel using rich.text.Text — no markup parsing, safe for any characters."""
        content = self.query_one("#detail-content", Static)
        if record is None:
            content.update(Text("── Selecione um IP na tabela ──"))
            return

        rate = record.requests_per_minute()
        first_seen = record.first_seen.strftime("%d/%m %H:%M:%S") if record.first_seen else "-"
        last_seen = record.last_seen.strftime("%d/%m %H:%M:%S") if record.last_seen else "-"
        path = record.last_path or "-"
        country = record.country_name or "..."

        t = Text()
        t.append(f"── {record.ip} ──\n", style="bold cyan")
        t.append(f"  País        : {record.flag_emoji} {country} ({record.country_code})\n")
        if record.is_bot:
            t.append("  Bot         : Sim — ", style="")
            t.append(record.bot_reason + "\n", style="yellow")
        else:
            t.append("  Bot         : Não\n")
        if record.is_blocked:
            t.append("  Bloqueado   : ")
            t.append("Sim\n", style="bold red")
        else:
            t.append("  Bloqueado   : Não\n")
        t.append(f"  Requisições : {record.request_count} total, {rate}/min\n")
        t.append(f"  Primeiro    : {first_seen}  Último: {last_seen}\n")
        t.append(f"  Último Req  : {record.last_method} {path} → {record.last_status}\n")
        t.append("  User Agents : ")
        uas = list(record.user_agents)[:3]
        if uas:
            t.append(uas[0] + "\n", style="dim")
            for ua in uas[1:]:
                t.append(" " * 16 + ua + "\n", style="dim")
        else:
            t.append("(nenhum)\n")

        content.update(t)


# ─────────────────────────────────────────────────────────────── #
# Main app                                                         #
# ─────────────────────────────────────────────────────────────── #

COLUMNS = [
    ("Flag", 5),
    ("IP", 17),
    ("País", 18),
    ("Reqs", 6),
    ("/min", 5),
    ("Último Acesso", 10),
    ("Bot", 4),
    ("Blq", 4),
    ("Status", 7),
    ("Último Path", 35),
]


class SiteManagerApp(App):
    """Real-time Nginx IP monitor TUI."""

    TITLE = "site-manager"
    CSS = """
    Screen {
        layout: vertical;
    }
    #table-container {
        height: 1fr;
        border: solid $primary;
    }
    DataTable {
        height: 1fr;
    }
    DataTable > .datatable--cursor {
        background: $accent 30%;
    }
    #status-bar {
        height: 1;
        background: $surface;
        padding: 0 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Sair"),
        Binding("b", "block_ip", "Bloquear"),
        Binding("u", "unblock_ip", "Liberar"),
        Binding("f", "toggle_bots", "Só Bots"),
        Binding("c", "clear_ip", "Remover"),
        Binding("r", "refresh_geo", "Re-GeoIP"),
        Binding("?", "show_help", "Ajuda"),
    ]

    show_bots_only: reactive[bool] = reactive(False)

    def __init__(
        self,
        state: "AppState",
        firewall: "FirewallManager",
        refresh_interval: float = 1.0,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._state = state
        self._firewall = firewall
        self._refresh_interval = refresh_interval
        self._row_keys: dict[str, str] = {}  # ip -> DataTable row key
        self._selected_ip: str | None = None
        self._total_requests: int = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="table-container"):
            yield DataTable(id="ip-table", cursor_type="row", zebra_stripes=True)
        yield DetailPanel(id="detail-panel")
        yield Label("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#ip-table", DataTable)
        for col_name, col_width in COLUMNS:
            table.add_column(col_name, width=col_width)
        self.set_interval(self._refresh_interval, self._tick)

    # ------------------------------------------------------------------ #
    # Periodic refresh                                                     #
    # ------------------------------------------------------------------ #

    def _tick(self) -> None:
        """Called every refresh_interval seconds to update the UI."""
        records = dict(self._state.ip_records)

        if self.show_bots_only:
            records = {ip: r for ip, r in records.items() if r.is_bot}

        self._update_table(records)
        self._update_detail()
        self._update_status(records)

    def _make_row(self, ip: str, r: "IPRecord") -> tuple:
        rate = r.requests_per_minute()
        last_seen = r.last_seen.strftime("%H:%M:%S") if r.last_seen else "-"
        bot_mark = "Y" if r.is_bot else " "
        blk_mark = "Y" if r.is_blocked else " "
        path = (r.last_path[:33] + "…") if r.last_path and len(r.last_path) > 34 else (r.last_path or "-")
        country = r.country_name[:16] if r.country_name else "..."
        return (
            r.flag_emoji,
            ip,
            country,
            str(r.request_count),
            str(rate),
            last_seen,
            bot_mark,
            blk_mark,
            str(r.last_status) if r.last_status else "-",
            path,
        )

    def _update_table(self, records: dict[str, "IPRecord"]) -> None:
        table = self.query_one("#ip-table", DataTable)

        # Sort: blocked first, then bots, then by last_seen desc
        sorted_ips = sorted(
            records.keys(),
            key=lambda ip: (
                not records[ip].is_blocked,
                not records[ip].is_bot,
                -(records[ip].last_seen.timestamp() if records[ip].last_seen else 0),
            ),
        )

        current_ips = set(self._row_keys.keys())
        new_ips = set(sorted_ips)

        # Add new rows
        for ip in sorted_ips:
            if ip not in current_ips:
                row_data = self._make_row(ip, records[ip])
                try:
                    self._row_keys[ip] = table.add_row(*row_data, key=ip)
                except Exception:
                    pass

        # Remove stale rows (IPs no longer in records)
        for ip in current_ips - new_ips:
            try:
                table.remove_row(self._row_keys.pop(ip))
            except Exception:
                self._row_keys.pop(ip, None)

        # Update cells for existing rows
        col_keys = [col.key for col in table.columns.values()]
        for ip in sorted_ips:
            if ip in current_ips and ip in self._row_keys:
                row_data = self._make_row(ip, records[ip])
                rk = self._row_keys[ip]
                for col_key, value in zip(col_keys, row_data):
                    try:
                        table.update_cell(rk, col_key, value, update_width=False)
                    except Exception:
                        pass

    def _update_detail(self) -> None:
        panel = self.query_one("#detail-panel", DetailPanel)
        if self._selected_ip and self._selected_ip in self._state.ip_records:
            panel.update_record(self._state.ip_records[self._selected_ip])
        else:
            panel.update_record(None)

    def _update_status(self, records: dict) -> None:
        total_reqs = sum(r.request_count for r in records.values())
        bots = sum(1 for r in records.values() if r.is_bot)
        blocked = sum(1 for r in records.values() if r.is_blocked)
        label = self.query_one("#status-bar", Label)
        mode = " [APENAS BOTS]" if self.show_bots_only else ""
        label.update(
            f"IPs: {len(records)} | Reqs: {total_reqs} | Bots: {bots} | Bloqueados: {blocked}{mode}"
        )

    # ------------------------------------------------------------------ #
    # Table selection tracking                                             #
    # ------------------------------------------------------------------ #

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key:
            self._selected_ip = str(event.row_key.value)
            self._update_detail()

    def _get_selected_ip(self) -> str | None:
        """Return the IP of the currently selected table row."""
        return self._selected_ip

    # ------------------------------------------------------------------ #
    # Actions                                                              #
    # ------------------------------------------------------------------ #

    async def action_block_ip(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            self.notify("Nenhum IP selecionado", severity="warning")
            return
        result = await self._firewall.block(ip)
        severity = "information" if result.success else "error"
        self.notify(result.message, severity=severity)
        if result.success:
            async with self._state.lock:
                if ip in self._state.ip_records:
                    self._state.ip_records[ip].is_blocked = True
                self._state.blocked_ips.add(ip)

    async def action_unblock_ip(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            self.notify("Nenhum IP selecionado", severity="warning")
            return
        result = await self._firewall.unblock(ip)
        severity = "information" if result.success else "error"
        self.notify(result.message, severity=severity)
        if result.success:
            async with self._state.lock:
                if ip in self._state.ip_records:
                    self._state.ip_records[ip].is_blocked = False
                self._state.blocked_ips.discard(ip)

    def action_toggle_bots(self) -> None:
        self.show_bots_only = not self.show_bots_only
        mode = "LIGADO" if self.show_bots_only else "DESLIGADO"
        self.notify(f"Filtro bots: {mode}")

    async def action_clear_ip(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            self.notify("Nenhum IP selecionado", severity="warning")
            return
        async with self._state.lock:
            self._state.ip_records.pop(ip, None)
        self._selected_ip = None
        self.notify(f"{ip} removido da lista")

    def action_show_help(self) -> None:
        help_text = (
            "[bold]Atalhos:[/]\n"
            "  ↑/↓  Navegar entre IPs\n"
            "  b    Bloquear IP selecionado\n"
            "  u    Liberar IP bloqueado\n"
            "  f    Filtrar apenas bots\n"
            "  c    Remover IP da lista\n"
            "  r    Re-consultar GeoIP\n"
            "  q    Sair"
        )
        self.notify(help_text, title="Ajuda", timeout=8)

    async def action_refresh_geo(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            self.notify("Nenhum IP selecionado", severity="warning")
            return
        self.notify(f"Re-consultando GeoIP para {ip}...")
        # Clear cache entry and re-enrich
        from geo import GeoResolver
        async with self._state.lock:
            if ip in self._state.ip_records:
                self._state.ip_records[ip].country_code = ""
                self._state.ip_records[ip].country_name = ""
                self._state.ip_records[ip].flag_emoji = "🌐"
        # Trigger re-enrichment (geo lookup will not find it in cache if we clear it)
        from monitor import enrich_async
        await enrich_async(ip, self._state, self._state.geo, self._state.detector)
        self.notify(f"GeoIP atualizado para {ip}")
