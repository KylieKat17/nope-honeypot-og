"""Small helpers shared by the decoys"""

IDLE_TIMEOUT = 10        # seconds to wait for a client to say something
MAX_READ = 4096          # never read more than this in one go
MAX_PAYLOAD_CHARS = 256  # how much of a payload we keep in the event log


def peer_ip(writer):
    peer = writer.get_extra_info("peername")
    return peer[0] if peer else "unknown"


def clean(data: bytes):
    """Printable, truncated version of what a client sent"""
    text = data[:MAX_PAYLOAD_CHARS].decode("utf-8", "replace")
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)


async def close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
