import copy

import pytest

from nope.config import DEFAULTS
from nope.events import Event
from nope.nft import Nft
from nope.responder import Responder
from nope.store import Store


def make(**overrides):
    cfg = copy.deepcopy(DEFAULTS)
    cfg.update(overrides)
    store = Store(":memory:")
    nft = Nft(dry_run=True)
    return store, nft, Responder(store, nft, cfg)


def ev(ip="10.0.0.5", ts=1000.0):
    return Event(ip, 2222, "ssh", "auth", ts=ts)


def test_below_alert_is_just_logged():
    _, nft, r = make()
    assert r.respond(ev(), 2) == "log"
    assert nft.history == []


def test_alert_fires_once_then_watches():
    _, _, r = make()
    assert r.respond(ev(), 6) == "alert"
    assert r.respond(ev(), 8) == "watch"


def test_block_adds_nft_element_and_db_row():
    store, nft, r = make()
    assert r.respond(ev(), 20) == "block"
    assert "blocklist4 { 10.0.0.5 timeout 600s }" in nft.history[-1]
    assert store.is_blocked("10.0.0.5", 1001.0)
    assert not store.is_blocked("10.0.0.5", 1000.0 + 601)


def test_already_blocked_is_not_blocked_twice():
    _, nft, r = make()
    r.respond(ev(), 20)
    count = len(nft.history)
    assert r.respond(ev(ts=1001.0), 25) == "none"
    assert len(nft.history) == count


def test_whitelist_matches_single_ips_and_ranges():
    _, _, r = make(whitelist=["192.168.56.0/24", "10.0.0.9"])
    assert r.whitelisted("192.168.56.1")
    assert r.whitelisted("10.0.0.9")
    assert not r.whitelisted("10.0.0.10")


def test_nft_uses_ipv6_set_for_v6():
    nft = Nft(dry_run=True)
    nft.add("2001:db8::1", 60)
    assert "blocklist6 { 2001:db8::1 timeout 60s }" in nft.history[-1]


def test_nft_rejects_garbage_instead_of_building_a_script():
    nft = Nft(dry_run=True)
    with pytest.raises(ValueError):
        nft.add("1.2.3.4 } ; flush ruleset ; {", 60)
    assert nft.history == []
