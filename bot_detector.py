"""
bot_detector.py — Bot detection via User-Agent patterns and request rate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from monitor import IPRecord


@dataclass
class BotResult:
    is_bot: bool
    reason: str


# (regex_pattern, human_readable_label)
_RAW_PATTERNS: list[tuple[str, str]] = [
    # Search engine crawlers
    (r"googlebot", "Googlebot"),
    (r"bingbot", "Bingbot"),
    (r"slurp", "Yahoo Slurp"),
    (r"duckduckbot", "DuckDuckBot"),
    (r"baiduspider", "Baiduspider"),
    (r"yandexbot|yandexmobilebot", "YandexBot"),
    (r"sogou", "Sogou"),
    (r"exabot", "Exabot"),
    # Social / link preview
    (r"facebot|facebookexternalhit", "Facebook"),
    (r"twitterbot", "Twitterbot"),
    (r"linkedinbot", "LinkedInBot"),
    (r"whatsapp", "WhatsApp"),
    (r"telegrambot", "TelegramBot"),
    # Archive / indexing
    (r"ia_archiver|wayback", "Internet Archive"),
    (r"archive\.org_bot", "Archive.org"),
    # SEO crawlers
    (r"semrushbot", "SEMrushBot"),
    (r"ahrefsbot", "AhrefsBot"),
    (r"mj12bot", "MJ12Bot"),
    (r"dotbot", "DotBot"),
    (r"rogerbot", "Rogerbot"),
    (r"screaming.?frog", "Screaming Frog"),
    (r"sistrix", "Sistrix"),
    (r"seokicks", "SEOkicks"),
    (r"seoscanners", "SEOscanners"),
    # Script / automation
    (r"python-requests|python-urllib", "Python HTTP"),
    (r"libwww-perl", "Perl HTTP"),
    (r"curl\/", "curl"),
    (r"wget\/", "wget"),
    (r"go-http-client", "Go HTTP"),
    (r"java\/[0-9]", "Java HTTP"),
    (r"okhttp\/", "OkHttp"),
    (r"axios\/", "Axios"),
    (r"node-fetch|node\.js", "Node.js"),
    (r"apache-httpclient", "Apache HTTPClient"),
    # Security scanners / attack tools
    (r"masscan", "Masscan"),
    (r"zgrab", "ZGrab"),
    (r"nmap", "Nmap"),
    (r"nikto", "Nikto"),
    (r"sqlmap", "SQLMap"),
    (r"nessus|openvas", "Vuln Scanner"),
    (r"dirbuster|dirb\/", "DirBuster"),
    (r"wfuzz", "WFuzz"),
    (r"hydra", "Hydra"),
    # WordPress-specific attack patterns (checked in path too)
    (r"wp-login\.php|xmlrpc\.php", "WP Brute Force"),
    # Generic headless / unknown bots
    (r"headlesschrome|phantomjs|puppeteer|playwright", "Headless Browser"),
    (r"^-$|^$", "Empty UA"),  # Empty or dash User-Agent
]


def _compile_patterns() -> list[tuple[re.Pattern, str]]:
    return [(re.compile(p, re.IGNORECASE), label) for p, label in _RAW_PATTERNS]


# WordPress attack paths (checked regardless of UA)
_WP_ATTACK_PATHS = re.compile(
    r"xmlrpc\.php|wp-login\.php|/\.\./|eval\(base64|select.*from|union.*select",
    re.IGNORECASE,
)

_COMPILED_PATTERNS = _compile_patterns()


class BotDetector:
    """Classifies IPs as bots based on User-Agent patterns and request rate."""

    def __init__(self, rate_threshold: int = 100) -> None:
        self._rate_threshold = rate_threshold
        self._patterns = _COMPILED_PATTERNS

    def classify(self, record: "IPRecord") -> BotResult:
        """Full classification: checks UA patterns first, then rate."""
        # 1. Check User-Agent patterns
        for ua in record.user_agents:
            for pattern, label in self._patterns:
                if pattern.search(ua):
                    return BotResult(is_bot=True, reason=f"UA: {label}")

        # 2. Check last accessed path for WordPress attacks
        if record.last_path and _WP_ATTACK_PATHS.search(record.last_path):
            return BotResult(is_bot=True, reason="Path: WP Attack")

        # 3. Rate check
        return self.classify_rate(record)

    def classify_rate(self, record: "IPRecord") -> BotResult:
        """Check only request rate (used for ongoing monitoring)."""
        rate = record.requests_per_minute()
        if rate >= self._rate_threshold:
            return BotResult(is_bot=True, reason=f"Rate: {rate}/min")
        return BotResult(is_bot=False, reason="")

    def is_known_good_bot(self, record: "IPRecord") -> bool:
        """Returns True if the bot is a known legitimate crawler (e.g. Googlebot)."""
        _KNOWN_GOOD = {"Googlebot", "Bingbot", "Yahoo Slurp", "DuckDuckBot",
                       "Baiduspider", "YandexBot", "Facebook", "Twitterbot"}
        for ua in record.user_agents:
            for pattern, label in self._patterns:
                if pattern.search(ua) and label in _KNOWN_GOOD:
                    return True
        return False
