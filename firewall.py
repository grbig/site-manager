"""
firewall.py — Block/unblock IPs via ufw, iptables, or nginx deny rules.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


BlockMethod = Literal["ufw", "iptables", "nginx"]

CONFIG_DIR = Path.home() / ".site-manager"
BLOCKED_JSON = CONFIG_DIR / "blocked.json"
NGINX_CONF = Path("/etc/nginx/conf.d/blocked-ips.conf")


@dataclass
class BlockResult:
    success: bool
    message: str


def _validate_ip(ip: str) -> None:
    """Raise ValueError if ip is not a valid IPv4 or IPv6 address."""
    ipaddress.ip_address(ip)


async def _run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    """Run a subprocess command, return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


class FirewallManager:
    """Manages IP blocking/unblocking via ufw, iptables, or nginx."""

    def __init__(
        self,
        method: BlockMethod = "ufw",
        nginx_conf: str | None = None,
    ) -> None:
        self._method = method
        self._nginx_conf = Path(nginx_conf) if nginx_conf else NGINX_CONF
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._blocked: set[str] = self._load_blocked()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    async def block(self, ip: str) -> BlockResult:
        """Block an IP address using the configured method."""
        try:
            _validate_ip(ip)
        except ValueError:
            return BlockResult(success=False, message=f"IP inválido: {ip}")

        if ip in self._blocked:
            return BlockResult(success=False, message=f"{ip} já está bloqueado")

        dispatch = {
            "ufw": self._block_ufw,
            "iptables": self._block_iptables,
            "nginx": self._block_nginx,
        }
        result = await dispatch[self._method](ip)

        if result.success:
            self._blocked.add(ip)
            self._save_blocked()

        return result

    async def unblock(self, ip: str) -> BlockResult:
        """Unblock a previously blocked IP address."""
        try:
            _validate_ip(ip)
        except ValueError:
            return BlockResult(success=False, message=f"IP inválido: {ip}")

        if ip not in self._blocked:
            return BlockResult(success=False, message=f"{ip} não está bloqueado")

        dispatch = {
            "ufw": self._unblock_ufw,
            "iptables": self._unblock_iptables,
            "nginx": self._unblock_nginx,
        }
        result = await dispatch[self._method](ip)

        if result.success:
            self._blocked.discard(ip)
            self._save_blocked()

        return result

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    @property
    def blocked_ips(self) -> frozenset[str]:
        return frozenset(self._blocked)

    # ------------------------------------------------------------------ #
    # ufw                                                                  #
    # ------------------------------------------------------------------ #

    async def _block_ufw(self, ip: str) -> BlockResult:
        code, stdout, stderr = await _run_cmd(
            ["sudo", "ufw", "deny", "from", ip, "to", "any"]
        )
        if code == 0:
            return BlockResult(success=True, message=f"Bloqueado {ip} via ufw")
        return BlockResult(success=False, message=f"Erro ufw: {stderr or stdout}")

    async def _unblock_ufw(self, ip: str) -> BlockResult:
        code, stdout, stderr = await _run_cmd(
            ["sudo", "ufw", "delete", "deny", "from", ip, "to", "any"]
        )
        if code == 0:
            return BlockResult(success=True, message=f"Liberado {ip} via ufw")
        return BlockResult(success=False, message=f"Erro ufw: {stderr or stdout}")

    # ------------------------------------------------------------------ #
    # iptables                                                             #
    # ------------------------------------------------------------------ #

    async def _block_iptables(self, ip: str) -> BlockResult:
        code, stdout, stderr = await _run_cmd(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        )
        if code == 0:
            return BlockResult(success=True, message=f"Bloqueado {ip} via iptables")
        return BlockResult(success=False, message=f"Erro iptables: {stderr or stdout}")

    async def _unblock_iptables(self, ip: str) -> BlockResult:
        code, stdout, stderr = await _run_cmd(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        )
        if code == 0:
            return BlockResult(success=True, message=f"Liberado {ip} via iptables")
        return BlockResult(success=False, message=f"Erro iptables: {stderr or stdout}")

    # ------------------------------------------------------------------ #
    # nginx                                                                #
    # ------------------------------------------------------------------ #

    async def _block_nginx(self, ip: str) -> BlockResult:
        try:
            # Read current conf
            existing = self._read_nginx_conf()
            line = f"deny {ip};"
            if line in existing.splitlines():
                return BlockResult(success=False, message=f"{ip} já está no nginx conf")
            new_content = existing.rstrip() + f"\ndeny {ip};\n"
            result = await self._write_nginx_conf(new_content)
            if not result.success:
                return result
            # Reload nginx
            reload_result = await self._nginx_reload()
            if not reload_result.success:
                return reload_result
            return BlockResult(success=True, message=f"Bloqueado {ip} via nginx")
        except Exception as e:
            return BlockResult(success=False, message=f"Erro nginx: {e}")

    async def _unblock_nginx(self, ip: str) -> BlockResult:
        try:
            existing = self._read_nginx_conf()
            line_to_remove = f"deny {ip};"
            lines = [l for l in existing.splitlines() if l.strip() != line_to_remove]
            new_content = "\n".join(lines) + "\n"
            result = await self._write_nginx_conf(new_content)
            if not result.success:
                return result
            reload_result = await self._nginx_reload()
            if not reload_result.success:
                return reload_result
            return BlockResult(success=True, message=f"Liberado {ip} via nginx")
        except Exception as e:
            return BlockResult(success=False, message=f"Erro nginx: {e}")

    def _read_nginx_conf(self) -> str:
        if self._nginx_conf.exists():
            return self._nginx_conf.read_text()
        return "# IPs bloqueados pelo site-manager\n"

    async def _write_nginx_conf(self, content: str) -> BlockResult:
        """Write to nginx conf using sudo tee (file is owned by root)."""
        proc = await asyncio.create_subprocess_exec(
            "sudo", "tee", str(self._nginx_conf),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate(content.encode())
        if proc.returncode != 0:
            return BlockResult(success=False, message=f"Erro escrita nginx conf: {stderr.decode()}")
        return BlockResult(success=True, message="")

    async def _nginx_reload(self) -> BlockResult:
        code, _, stderr = await _run_cmd(["sudo", "nginx", "-s", "reload"])
        if code != 0:
            return BlockResult(success=False, message=f"Erro nginx reload: {stderr}")
        return BlockResult(success=True, message="")

    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #

    def _load_blocked(self) -> set[str]:
        if BLOCKED_JSON.exists():
            try:
                data = json.loads(BLOCKED_JSON.read_text())
                return set(data.get("blocked", []))
            except Exception:
                return set()
        return set()

    def _save_blocked(self) -> None:
        """Atomically write blocked IPs to JSON."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"blocked": sorted(self._blocked)}, indent=2)
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            dir=CONFIG_DIR,
            delete=False,
            suffix=".tmp",
        )
        try:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, BLOCKED_JSON)
        except Exception:
            tmp.close()
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
