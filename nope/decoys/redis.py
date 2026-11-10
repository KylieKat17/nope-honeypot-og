"""Decoy Redis service.

Pretends to be a Redis server with a password set: every command gets
-NOAUTH, and AUTH always fails. That pushes scanners and brute-forcers into
sending AUTH attempts, which is what we score. Commands that Redis exploits
rely on (CONFIG, SLAVEOF, MODULE, EVAL...) are scored as "exploit".
"""

import asyncio

from ..events import Event
from .base import IDLE_TIMEOUT, MAX_READ, clean, close, peer_ip

MAX_ROUNDS = 50

EXPLOIT_COMMANDS = {
    "CONFIG", "SLAVEOF", "REPLICAOF", "MODULE", "EVAL", "EVALSHA",
    "SCRIPT", "FLUSHALL", "FLUSHDB", "DEBUG", "SAVE", "BGSAVE", "SHUTDOWN",
}

NOAUTH = b"-NOAUTH Authentication required.\r\n"
WRONGPASS = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n"


def parse_command(data: bytes):
    """Pull the words out of RESP or inline Redis input.

    Drops the *N / $N framing lines. Pipelined commands just end up as one
    flat word list, which is fine for scoring.
    """
    text = data.decode("utf-8", "replace")
    return [line for line in text.split("\r\n") if line and line[0] not in "*$"]


def classify(words):
    upper = [w.upper() for w in words]
    if any(w in EXPLOIT_COMMANDS for w in upper):
        return "exploit"
    if "AUTH" in upper:
        return "auth"
    return "probe"


async def start(host, port, emit):
    async def handle(reader, writer):
        ip = peer_ip(writer)
        emit(Event(ip, port, "redis", "connect"))
        try:
            for _ in range(MAX_ROUNDS):
                data = await asyncio.wait_for(reader.read(MAX_READ), IDLE_TIMEOUT)
                if not data:
                    break
                words = parse_command(data)
                emit(Event(ip, port, "redis", classify(words), clean(data)))
                is_auth = bool(words) and words[0].upper() == "AUTH"
                writer.write(WRONGPASS if is_auth else NOAUTH)
                await writer.drain()
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            await close(writer)

    return await asyncio.start_server(handle, host, port)
