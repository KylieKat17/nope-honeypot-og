"""Turns a score into an action: log, alert or block"""

import ipaddress
import logging

from .events import Event
from .nft import Nft, NftError
from .store import Store

log = logging.getLogger("nope.responder")


class Responder:
    def __init__(self, store: Store, nft: Nft, cfg):
        self.store = store
        self.nft = nft
        self.alert_at = cfg["alert_threshold"]
        self.block_at = cfg["block_threshold"]
        self.block_seconds = cfg["block_seconds"]
        self.whitelist = [ipaddress.ip_network(n, strict=False) for n in cfg["whitelist"]]
        self.alerted = set()

    def whitelisted(self, ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.whitelist)

    def respond(self, event: Event, score: float):
        """Act on the new score and return the action name for the event log."""
        ip = event.ip
        if score >= self.block_at:
            if self.store.is_blocked(ip, event.ts):
                return "none"
            try:
                self.nft.add(ip, self.block_seconds)
            except NftError as exc:
                log.error("failed to block %s: %s", ip, exc)
                return "block-failed"
            reason = f"score {score:.1f} ({event.service}/{event.kind})"
            self.store.add_block(ip, event.ts, event.ts + self.block_seconds, reason)
            self.alerted.discard(ip)
            log.warning("BLOCK %s for %ss, %s", ip, self.block_seconds, reason)
            return "block"
        if score >= self.alert_at:
            if ip not in self.alerted:
                self.alerted.add(ip)
                log.warning("ALERT %s score %.1f (%s/%s)", ip, score, event.service, event.kind)
                return "alert"
            return "watch"
        return "log"
