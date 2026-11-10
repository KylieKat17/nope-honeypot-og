"""Per-IP severity scoring with exponential time decay"""

from .events import Event


def decay(score, elapsed, half_life):
    """Score after `elapsed` seconds of quiet. Halves every `half_life` seconds"""
    if half_life <= 0 or elapsed <= 0:
        return score
    return score * 0.5 ** (elapsed / half_life)


class Scorer:
    def __init__(self, store, weights, half_life):
        self.store = store
        self.weights = weights
        self.half_life = half_life

    def current(self, ip, now):
        row = self.store.get_score(ip)
        if row is None:
            return 0.0
        return decay(row["score"], now - row["updated"], self.half_life)

    def add(self, event: Event):
        """Decay the source's old score, add this event's weight, save, return it"""
        score = self.current(event.ip, event.ts) + self.weights.get(event.kind, 1)
        self.store.set_score(event.ip, score, event.ts)
        return score
