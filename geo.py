"""
geo.py — GeoIP resolution with local GeoLite2 database and ip-api.com fallback.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from cachetools import LRUCache
    CACHETOOLS_AVAILABLE = True
except ImportError:
    CACHETOOLS_AVAILABLE = False


def _country_to_flag(code: str) -> str:
    """Convert ISO 3166-1 alpha-2 country code to flag emoji."""
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in code)


@dataclass
class GeoResult:
    country_code: str
    country_name: str
    flag_emoji: str

    @classmethod
    def unknown(cls) -> "GeoResult":
        return cls(country_code="??", country_name="Unknown", flag_emoji="🌐")

    @classmethod
    def local(cls) -> "GeoResult":
        return cls(country_code="LO", country_name="Local", flag_emoji="🏠")


class RateLimiter:
    """Sliding-window rate limiter: max N calls per `period` seconds."""

    def __init__(self, max_calls: int = 45, period: float = 60.0) -> None:
        self._max_calls = max_calls
        self._period = period
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self._period
            # Prune old timestamps
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            if len(self._timestamps) >= self._max_calls:
                # Wait until the oldest entry falls outside the window
                wait_time = self._period - (now - self._timestamps[0]) + 0.05
                await asyncio.sleep(wait_time)
                # Prune again after waiting
                now = time.monotonic()
                cutoff = now - self._period
                while self._timestamps and self._timestamps[0] < cutoff:
                    self._timestamps.popleft()

            self._timestamps.append(time.monotonic())


class GeoResolver:
    """Resolve IP addresses to country info using GeoLite2 DB or ip-api.com."""

    DEFAULT_DB_PATH = Path.home() / ".site-manager" / "GeoLite2-City.mmdb"

    def __init__(self, mmdb_path: Optional[str] = None) -> None:
        self._reader: Optional["geoip2.database.Reader"] = None
        self._session: Optional["aiohttp.ClientSession"] = None
        self._rate_limiter = RateLimiter(max_calls=45, period=60.0)

        # Set up LRU cache (10k entries)
        if CACHETOOLS_AVAILABLE:
            self._cache: dict = LRUCache(maxsize=10_000)
        else:
            self._cache = {}

        # Try to open GeoLite2 database
        db_path = Path(mmdb_path) if mmdb_path else self.DEFAULT_DB_PATH
        if GEOIP2_AVAILABLE and db_path.exists():
            try:
                self._reader = geoip2.database.Reader(str(db_path))
            except Exception:
                self._reader = None

    async def _get_session(self) -> "aiohttp.ClientSession":
        if self._session is None or self._session.closed:
            if not AIOHTTP_AVAILABLE:
                raise RuntimeError("aiohttp not available")
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5.0)
            )
        return self._session

    def _is_special_ip(self, ip: str) -> Optional[GeoResult]:
        """Return a GeoResult if the IP is private, loopback, or reserved."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return GeoResult.local()
            if addr.is_reserved or addr.is_unspecified:
                return GeoResult(country_code="--", country_name="Reserved", flag_emoji="🔒")
        except ValueError:
            return GeoResult.unknown()
        return None

    def _lookup_geoip2(self, ip: str) -> Optional[GeoResult]:
        """Synchronous GeoLite2 lookup. Fast enough for inline use."""
        if self._reader is None:
            return None
        try:
            response = self._reader.city(ip)
            code = response.country.iso_code or "??"
            name = response.country.name or "Unknown"
            return GeoResult(
                country_code=code,
                country_name=name,
                flag_emoji=_country_to_flag(code),
            )
        except Exception:
            return None

    async def _lookup_ipapi(self, ip: str) -> GeoResult:
        """Async ip-api.com lookup with rate limiting."""
        await self._rate_limiter.acquire()
        try:
            session = await self._get_session()
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return GeoResult.unknown()
                data = await resp.json()
                if data.get("status") != "success":
                    return GeoResult.unknown()
                code = data.get("countryCode", "??")
                name = data.get("country", "Unknown")
                return GeoResult(
                    country_code=code,
                    country_name=name,
                    flag_emoji=_country_to_flag(code),
                )
        except Exception:
            return GeoResult.unknown()

    async def lookup(self, ip: str) -> GeoResult:
        """Resolve an IP to GeoResult. Checks cache, then GeoLite2, then ip-api.com."""
        # Cache check
        if ip in self._cache:
            return self._cache[ip]

        # Private/reserved IPs
        special = self._is_special_ip(ip)
        if special is not None:
            self._cache[ip] = special
            return special

        # GeoLite2 (offline, fast)
        result = self._lookup_geoip2(ip)
        if result is None:
            # Fallback to ip-api.com
            result = await self._lookup_ipapi(ip)

        self._cache[ip] = result
        return result

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self._reader:
            self._reader.close()
