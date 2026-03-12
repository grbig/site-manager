"""
monitor.py — Nginx log tailer, parser, and IP state management.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from geo import GeoResolver
    from bot_detector import BotDetector
    from main import AppState


# Nginx combined log format regex
COMBINED_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Regex to split "METHOD /path PROTO" from the request field in JSON logs
REQUEST_RE = re.compile(r'^(\S+)\s+(\S+)\s+(\S+)$')

# Max timestamps kept per IP (60s window at up to 1000 req/s = 60000 entries)
MAX_TIMESTAMPS = 60_000
# Max IPs tracked in memory before evicting oldest
MAX_IPS = 5_000


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str


@dataclass
class IPRecord:
    ip: str
    first_seen: datetime
    last_seen: datetime
    request_count: int = 0
    country_code: str = ""
    country_name: str = ""
    flag_emoji: str = "🌐"
    is_bot: bool = False
    bot_reason: str = ""
    is_blocked: bool = False
    last_method: str = ""
    last_path: str = ""
    last_status: int = 0
    user_agents: set = field(default_factory=set)
    req_timestamps: deque = field(default_factory=lambda: deque(maxlen=MAX_TIMESTAMPS))

    def requests_per_minute(self) -> int:
        """Count requests in the last 60 seconds."""
        now = datetime.now().timestamp()
        cutoff = now - 60.0
        count = sum(1 for ts in self.req_timestamps if ts >= cutoff)
        return count

    def prune_timestamps(self) -> None:
        """Remove timestamps older than 60 seconds."""
        now = datetime.now().timestamp()
        cutoff = now - 60.0
        while self.req_timestamps and self.req_timestamps[0] < cutoff:
            self.req_timestamps.popleft()


def parse_line(raw: str) -> LogEntry | None:
    """Parse a single Nginx log line. Auto-detects JSON or combined format."""
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("{"):
        return _parse_json(raw)
    return _parse_combined(raw)


def _parse_json(raw: str) -> LogEntry | None:
    """Parse a JSON-format Nginx log line."""
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        return None

    # Extract IP — prefer http_x_forwarded_for if present (real IP behind proxy)
    ip = d.get("http_x_forwarded_for", "") or d.get("remote_addr", "")
    if not ip or ip == "-":
        ip = d.get("remote_addr", "")
    # x_forwarded_for may be a comma-separated list; take first
    if "," in ip:
        ip = ip.split(",")[0].strip()
    if not ip:
        return None

    # Parse "METHOD /path PROTO" request field
    request = d.get("request", "")
    m = REQUEST_RE.match(request)
    if m:
        method, path, protocol = m.group(1), m.group(2), m.group(3)
    else:
        method, path, protocol = "-", request or "-", "-"

    # Timestamp
    ts_str = d.get("timestamp", "")
    try:
        timestamp = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        timestamp = datetime.now().astimezone()

    return LogEntry(
        ip=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status=int(d.get("status", 0)),
        bytes_sent=int(d.get("body_bytes_sent", 0) or 0),
        referer=d.get("http_referrer", "") or "",
        user_agent=d.get("http_user_agent", "") or "",
    )


def _parse_combined(raw: str) -> LogEntry | None:
    """Parse a standard Nginx combined log format line."""
    m = COMBINED_LOG_RE.match(raw)
    if not m:
        return None
    try:
        timestamp = datetime.strptime(m.group("time"), TIME_FORMAT)
    except ValueError:
        timestamp = datetime.now().astimezone()

    bytes_str = m.group("bytes")
    bytes_sent = int(bytes_str) if bytes_str != "-" else 0

    return LogEntry(
        ip=m.group("ip"),
        timestamp=timestamp,
        method=m.group("method"),
        path=m.group("path"),
        protocol=m.group("proto"),
        status=int(m.group("status")),
        bytes_sent=bytes_sent,
        referer=m.group("referer"),
        user_agent=m.group("ua"),
    )


async def upsert_record(
    entry: LogEntry,
    state: "AppState",
    geo: "GeoResolver",
    detector: "BotDetector",
) -> None:
    """Update or create an IPRecord for the given log entry."""
    async with state.lock:
        is_new = entry.ip not in state.ip_records

        if is_new:
            # Evict oldest IP if over limit
            if len(state.ip_records) >= MAX_IPS:
                oldest_ip = min(
                    state.ip_records,
                    key=lambda ip: state.ip_records[ip].last_seen,
                )
                del state.ip_records[oldest_ip]

            record = IPRecord(
                ip=entry.ip,
                first_seen=entry.timestamp,
                last_seen=entry.timestamp,
                request_count=1,
                last_method=entry.method,
                last_path=entry.path,
                last_status=entry.status,
                user_agents={entry.user_agent} if entry.user_agent else set(),
            )
            record.req_timestamps.append(entry.timestamp.timestamp())
            # Mark as blocked if already in blocked set
            record.is_blocked = entry.ip in state.blocked_ips
            state.ip_records[entry.ip] = record
        else:
            record = state.ip_records[entry.ip]
            record.request_count += 1
            record.last_seen = entry.timestamp
            record.last_method = entry.method
            record.last_path = entry.path
            record.last_status = entry.status
            if entry.user_agent:
                record.user_agents.add(entry.user_agent)
            record.req_timestamps.append(entry.timestamp.timestamp())
            record.prune_timestamps()

    # Enrich new IPs asynchronously (outside lock)
    if is_new:
        asyncio.create_task(enrich_async(entry.ip, state, geo, detector))
    else:
        # Re-check rate-based bot detection on every request
        async with state.lock:
            record = state.ip_records.get(entry.ip)
            if record and not record.is_bot:
                result = detector.classify_rate(record)
                if result.is_bot:
                    record.is_bot = True
                    record.bot_reason = result.reason


async def enrich_async(
    ip: str,
    state: "AppState",
    geo: "GeoResolver",
    detector: "BotDetector",
) -> None:
    """Perform GeoIP lookup and bot detection for a newly seen IP."""
    geo_result = await geo.lookup(ip)

    async with state.lock:
        record = state.ip_records.get(ip)
        if record is None:
            return
        record.country_code = geo_result.country_code
        record.country_name = geo_result.country_name
        record.flag_emoji = geo_result.flag_emoji

        bot_result = detector.classify(record)
        record.is_bot = bot_result.is_bot
        record.bot_reason = bot_result.reason


async def tail_log(
    log_file: str,
    state: "AppState",
    geo: "GeoResolver",
    detector: "BotDetector",
) -> None:
    """Tail the nginx access log file in real-time, handling log rotation."""
    while not os.path.exists(log_file):
        await asyncio.sleep(2.0)

    fd = open(log_file, "r", encoding="utf-8", errors="replace")
    fd.seek(0, 2)  # Seek to end of file
    current_ino = os.fstat(fd.fileno()).st_ino

    try:
        while True:
            line = fd.readline()
            if line:
                try:
                    entry = parse_line(line)
                    if entry:
                        await upsert_record(entry, state, geo, detector)
                except Exception:
                    pass  # Skip bad lines, keep tailing
            else:
                await asyncio.sleep(0.1)
                # Check for log rotation
                try:
                    new_ino = os.stat(log_file).st_ino
                except FileNotFoundError:
                    await asyncio.sleep(1.0)
                    continue
                if new_ino != current_ino:
                    fd.close()
                    fd = open(log_file, "r", encoding="utf-8", errors="replace")
                    current_ino = new_ino
    finally:
        fd.close()


async def replay_log(
    log_file: str,
    state: "AppState",
    geo: "GeoResolver",
    detector: "BotDetector",
    lines: int = 500,
) -> None:
    """Read the last N lines of the log file to populate initial state."""
    if not os.path.exists(log_file):
        return

    try:
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            # Read enough bytes to get `lines` entries (avg ~600 bytes per JSON line)
            read_size = min(file_size, lines * 800)
            f.seek(file_size - read_size)
            raw = f.read().decode("utf-8", errors="replace")
    except OSError:
        return

    all_lines = raw.splitlines()
    # Skip the first line (likely partial) unless we read from the beginning
    if read_size < file_size:
        all_lines = all_lines[1:]
    all_lines = all_lines[-lines:]

    batch = 0
    for line in all_lines:
        try:
            entry = parse_line(line)
            if entry:
                await upsert_record(entry, state, geo, detector)
                batch += 1
                # Yield every 20 entries to keep TUI responsive
                if batch % 20 == 0:
                    await asyncio.sleep(0)
        except Exception:
            pass  # Skip bad lines, continue loading
