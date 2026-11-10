"""Thin nftables wrapper.

All rules live in their own table (inet nope) so there  anything the
admin sets up is never touched. Blocked IPs go into a set with the `timeout` flag, so nftables
expires them automatically. With dry_run=True nothing is executed, the scripts are
just logged and kept in `history` (used by the tests)
"""

import ipaddress
import logging
import shutil
import subprocess

log = logging.getLogger("nope.nft")

SETUP_SCRIPT = """\
add table inet nope
delete table inet nope
table inet nope {
    set blocklist4 {
        type ipv4_addr
        flags timeout
    }
    set blocklist6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocklist4 drop
        ip6 saddr @blocklist6 drop
    }
}
"""

TEARDOWN_SCRIPT = "add table inet nope\ndelete table inet nope\n"


class NftError(RuntimeError):
    pass


def _target(ip):
    """Validate the address (raises ValueError) and pick the matching set"""
    addr = ipaddress.ip_address(ip)
    return ("blocklist4" if addr.version == 4 else "blocklist6"), str(addr)


class Nft:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.history = []

    def _run(self, script):
        self.history.append(script)
        if self.dry_run:
            log.info("[dry-run] nft -f -\n%s", script.rstrip())
            return
        if shutil.which("nft") is None:
            raise NftError("nft not found, install nftables or use --dry-run")
        result = subprocess.run(
            ["nft", "-f", "-"], input=script, text=True, capture_output=True
        )
        if result.returncode != 0:
            raise NftError(result.stderr.strip() or "nft failed")

    def setup(self):
        self._run(SETUP_SCRIPT)

    def teardown(self):
        self._run(TEARDOWN_SCRIPT)

    def add(self, ip, seconds):
        set_name, addr = _target(ip)
        self._run(f"add element inet nope {set_name} {{ {addr} timeout {int(seconds)}s }}\n")

    def remove(self, ip):
        set_name, addr = _target(ip)
        try:
            self._run(f"delete element inet nope {set_name} {{ {addr} }}\n")
        except NftError as exc:
            # usually just means the block already expired
            log.warning("could not remove %s from nftables: %s", addr, exc)
