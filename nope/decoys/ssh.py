"""Decoy SSH service.

Sends a believable OpenSSH banner and records what the client sends back.
It does not implement the real SSH handshake, so it can tell connect-only
from banner-sending clients but cannot see password guesses. Swapping this
for an asyncssh server would unlock "auth" events (see README roadmap)
"""

import asyncio

from ..events import Event
from .base import IDLE_TIMEOUT, MAX_READ, clean, close, peer_ip

BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"


async def start(host, port, emit):
    async def handle(reader, writer):
        ip = peer_ip(writer)
        emit(Event(ip, port, "ssh", "connect"))
        try:
            writer.write(BANNER)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(MAX_READ), IDLE_TIMEOUT)
            if data:
                emit(Event(ip, port, "ssh", "probe", clean(data)))
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            await close(writer)

    return await asyncio.start_server(handle, host, port)
