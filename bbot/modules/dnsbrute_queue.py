"""Fair, bounded wordlist progress across observed DNS parents."""

import heapq


class DNSBruteQueue:
    def __init__(self, word_count):
        self.word_count = word_count
        self.events = {}
        self.positions = {}
        self.limits = {}
        self.limited = set()
        self._heap = []
        self._order = 0

    def add(self, parent, event, *, limit=None):
        if parent in self.events:
            return False
        self.events[parent] = event
        self.positions[parent] = 0
        self.limits[parent] = min(self.word_count, limit or self.word_count)
        heapq.heappush(self._heap, (0, self._order, parent))
        self._order += 1
        return True

    def __bool__(self):
        return bool(self._heap)

    def reserve(self, batch_size, max_parents):
        if not self._heap:
            return []
        selected = [heapq.heappop(self._heap) for _ in range(min(max_parents, len(self._heap)))]
        # Give lagging parents priority. A newly observed parent catches up
        # before an older parent advances farther into the wordlist.
        lowest = selected[0][0]
        lagging = [entry for entry in selected if entry[0] == lowest]
        for entry in selected[len(lagging):]:
            heapq.heappush(self._heap, entry)
        next_position = self._heap[0][0] if self._heap else self.word_count
        width = max(1, batch_size // len(lagging))
        if next_position > lowest:
            width = min(width, next_position - lowest)
        end = min(self.word_count, lowest + width)
        return [(parent, lowest, end, self.events[parent], order) for _, order, parent in lagging]

    def complete(self, reservation, *, limited=False, checked=None):
        parent, start, end, _event, order = reservation
        if checked is not None:
            end = min(end, start + checked)
        end = min(end, self.limits[parent])
        self.positions[parent] = end
        if limited:
            self.limited.add(parent)
        if end < self.limits[parent] and not limited:
            heapq.heappush(self._heap, (end, order, parent))

    def retry(self, reservation):
        parent, start, _end, _event, order = reservation
        heapq.heappush(self._heap, (start, order, parent))
