"""
main.py — Entry point for site-manager: real-time Nginx IP monitor.

Usage:
    python3 main.py [--log-file /var/log/nginx/access.log] [--demo]
"""
from __future__ import annotations

import argparse
import asyncio
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from geo import GeoResolver
    from bot_detector import BotDetector


# ─────────────────────────────────────────────────────────────── #
# Shared application state                                         #
# ─────────────────────────────────────────────────────────────── #

@dataclass
class AppState:
    ip_records: dict = field(default_factory=dict)   # ip -> IPRecord
    blocked_ips: set = field(default_factory=set)    # IPs from blocked.json
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # Injected after creation for use in tui.py action_refresh_geo
    geo: "GeoResolver | None" = None
    detector: "BotDetector | None" = None


# ─────────────────────────────────────────────────────────────── #
# Demo mode: generate fake log entries for testing                 #
# ─────────────────────────────────────────────────────────────── #

_DEMO_IPS = [
    ("203.0.113.5", "RU", "Russia", "🇷🇺", True, "Rate: 143/min"),
    ("198.51.100.2", "BR", "Brazil", "🇧🇷", False, ""),
    ("192.0.2.88", "US", "United States", "🇺🇸", False, ""),
    ("203.0.113.99", "CN", "China", "🇨🇳", True, "UA: Baiduspider"),
    ("185.220.101.5", "DE", "Germany", "🇩🇪", True, "UA: Python HTTP"),
    ("1.1.1.1", "AU", "Australia", "🇦🇺", False, ""),
    ("45.33.32.156", "US", "United States", "🇺🇸", True, "UA: Nmap"),
    ("8.8.8.8", "US", "United States", "🇺🇸", False, ""),
]

_DEMO_PATHS = [
    "/wp-login.php", "/", "/wp-content/themes/",
    "/xmlrpc.php", "/wp-admin/", "/sitemap.xml",
    "/robots.txt", "/?p=1", "/wp-json/wp/v2/posts",
]

_DEMO_UAS = [
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8)",
    "python-requests/2.28.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.85.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0)",
]


async def _demo_generator(state: AppState) -> None:
    """Generate fake log entries to demonstrate the TUI without a real log."""
    from monitor import IPRecord
    from collections import deque

    for ip_info in _DEMO_IPS:
        ip, cc, cn, flag, is_bot, bot_reason = ip_info
        record = IPRecord(
            ip=ip,
            first_seen=datetime.now(tz=timezone.utc),
            last_seen=datetime.now(tz=timezone.utc),
            request_count=random.randint(1, 500),
            country_code=cc,
            country_name=cn,
            flag_emoji=flag,
            is_bot=is_bot,
            bot_reason=bot_reason,
            is_blocked=ip in state.blocked_ips,
            last_method="GET",
            last_path=random.choice(_DEMO_PATHS),
            last_status=random.choice([200, 200, 200, 404, 403, 301]),
            user_agents={random.choice(_DEMO_UAS)},
        )
        for _ in range(record.request_count):
            record.req_timestamps.append(datetime.now().timestamp())
        async with state.lock:
            state.ip_records[ip] = record

    # Continuously add fake requests
    while True:
        await asyncio.sleep(random.uniform(0.3, 1.5))
        ip_info = random.choice(_DEMO_IPS)
        ip = ip_info[0]
        async with state.lock:
            if ip in state.ip_records:
                r = state.ip_records[ip]
                r.request_count += 1
                r.last_seen = datetime.now(tz=timezone.utc)
                r.last_path = random.choice(_DEMO_PATHS)
                r.last_status = random.choice([200, 200, 404, 403])
                r.req_timestamps.append(datetime.now().timestamp())
                r.prune_timestamps()


# ─────────────────────────────────────────────────────────────── #
# CLI argument parsing                                             #
# ─────────────────────────────────────────────────────────────── #

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="site-manager",
        description="Monitor de IPs em tempo real para servidor Nginx/WordPress",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 main.py
  python3 main.py --log-file /var/log/nginx/access.log
  python3 main.py --block-method iptables --rate-threshold 50
  python3 main.py --demo
        """,
    )
    parser.add_argument(
        "--log-file",
        default="/var/log/nginx/access.log",
        help="Caminho do log de acesso do Nginx (padrão: /var/log/nginx/access.log)",
    )
    parser.add_argument(
        "--geoip-db",
        default=None,
        help="Caminho do GeoLite2-City.mmdb (padrão: ~/.site-manager/GeoLite2-City.mmdb)",
    )
    parser.add_argument(
        "--block-method",
        choices=["ufw", "iptables", "nginx"],
        default="ufw",
        help="Método de bloqueio de IPs (padrão: ufw)",
    )
    parser.add_argument(
        "--nginx-conf",
        default=None,
        help="Caminho do arquivo de IPs bloqueados do nginx (padrão: /etc/nginx/conf.d/blocked-ips.conf)",
    )
    parser.add_argument(
        "--rate-threshold",
        type=int,
        default=100,
        help="Requisições/min para marcar IP como bot suspeito (padrão: 100)",
    )
    parser.add_argument(
        "--refresh",
        type=float,
        default=1.0,
        help="Intervalo de atualização da TUI em segundos (padrão: 1.0)",
    )
    parser.add_argument(
        "--replay-lines",
        type=int,
        default=500,
        help="Número de linhas do log a carregar ao iniciar (padrão: 500)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Modo demo com dados simulados (não requer log real)",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────── #
# Entry point                                                      #
# ─────────────────────────────────────────────────────────────── #

def main() -> None:
    args = parse_args()

    from geo import GeoResolver
    from bot_detector import BotDetector
    from firewall import FirewallManager
    from tui import SiteManagerApp

    # Build shared state
    state = AppState()

    # Build components
    geo = GeoResolver(mmdb_path=args.geoip_db)
    detector = BotDetector(rate_threshold=args.rate_threshold)
    firewall = FirewallManager(
        method=args.block_method,
        nginx_conf=args.nginx_conf,
    )

    # Inject into state for use by tui.py action_refresh_geo
    state.geo = geo
    state.detector = detector
    state.blocked_ips = set(firewall.blocked_ips)

    async def run() -> None:
        app = SiteManagerApp(
            state=state,
            firewall=firewall,
            refresh_interval=args.refresh,
        )

        if args.demo:
            demo_task = asyncio.create_task(_demo_generator(state))
            try:
                await app.run_async()
            finally:
                demo_task.cancel()
        else:
            from monitor import tail_log, replay_log, IPRecord, enrich_async

            async def start_monitor():
                from datetime import timezone as tz

                # Create stub records for IPs blocked in previous sessions
                stub_time = datetime.now(tz=tz.utc)
                for ip in list(state.blocked_ips):
                    async with state.lock:
                        if ip not in state.ip_records:
                            state.ip_records[ip] = IPRecord(
                                ip=ip,
                                first_seen=stub_time,
                                last_seen=stub_time,
                                is_blocked=True,
                            )
                    asyncio.create_task(enrich_async(ip, state, geo, detector))

                # Pre-populate with recent log entries
                await replay_log(args.log_file, state, geo, detector, lines=args.replay_lines)
                # Then start tailing in real-time
                await tail_log(args.log_file, state, geo, detector)

            monitor_task = asyncio.create_task(start_monitor())
            try:
                await app.run_async()
            finally:
                monitor_task.cancel()
                await geo.close()

    asyncio.run(run())


if __name__ == "__main__":
    main()
