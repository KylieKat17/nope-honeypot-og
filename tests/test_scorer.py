import pytest

from nope.events import Event
from nope.scorer import Scorer, decay
from nope.store import Store

WEIGHTS = {"connect": 1, "probe": 2, "auth": 5, "exploit": 10}


def make():
    return Scorer(Store(":memory:"), WEIGHTS, half_life=100)


def ev(kind, ts=0, ip="10.0.0.5"):
    return Event(ip, 2222, "ssh", kind, ts=ts)


def test_weights_accumulate():
    s = make()
    assert s.add(ev("connect")) == 1
    assert s.add(ev("auth")) == 6


def test_unknown_kind_counts_as_one():
    assert make().add(ev("weird")) == 1


def test_scores_are_per_ip():
    s = make()
    s.add(ev("exploit", ip="10.0.0.5"))
    assert s.add(ev("connect", ip="10.0.0.6")) == 1


def test_decay_halves_each_half_life():
    assert decay(8, 100, 100) == pytest.approx(4)
    assert decay(8, 200, 100) == pytest.approx(2)


def test_decay_applied_between_events():
    s = make()
    s.add(ev("exploit", ts=0))                              # 10
    assert s.add(ev("connect", ts=100)) == pytest.approx(6)  # 10 * 0.5 + 1
