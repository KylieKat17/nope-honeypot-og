"""The one interface between the decoys and everything else

Decoys build an Event and hand it to the daemon. The scorer, responder and
store only ever see this shape
"""

import time
from dataclasses import dataclass, field

# Ordered roughly from least to most serious.
KINDS = ("connect", "probe", "auth", "exploit")


@dataclass
class Event:
    ip: str
    port: int
    service: str          # "ssh", "redis", ...
    kind: str             # one of KINDS
    payload: str = ""     # printable, truncated copy of what the client sent
    ts: float = field(default_factory=time.time)
