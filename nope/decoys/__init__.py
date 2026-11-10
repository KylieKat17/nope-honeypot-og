"""Decoy services. Each module exposes `async start(host, port, emit)`"""

from . import redis, ssh

DECOYS = {"ssh": ssh, "redis": redis}
