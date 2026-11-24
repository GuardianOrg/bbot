"""Fair, bounded wordlist progress across observed DNS parents."""

import heapq


class DNSBruteQueue:
    def __init__(self, word_count):
        self.word_count = word_count
        self.events = {}
        self.positions = {}
        # Words before this offset all got a DNS answer: the safe point to resume from.
        self.covered = {}
        self.limits = {}
        self.limited = set()
        # Parents dropped before their limit: their remaining words are neither asked nor covered.
        self.stopped = set()
        self._heap = []
        self._order = 0

    def add(self, parent, event, *, limit=None, start=0):
        """Queue ``parent``; ``start`` resumes after words an earlier run already checked."""
        if parent in self.events:
            return False
        self.events[parent] = event
        self.limits[parent] = min(self.word_count, limit or self.word_count)
        self.positions[parent] = min(max(0, int(start)), self.limits[parent])
        self.covered[parent] = self.positions[parent]
        if self.positions[parent] < self.limits[parent]:
            heapq.heappush(self._heap, (self.positions[parent], self._order, parent))
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

    def complete(self, reservation, *, limited=False, checked=None, answered=None):
        """Advance past ``checked`` submitted words; ``answered`` leading ones of them got a DNS answer."""
        parent, start, end, _event, order = reservation
        if checked is not None:
            end = min(end, start + checked)
        end = min(end, self.limits[parent])
        self.positions[parent] = end
        # Coverage stops at the first unanswered word and stays there; later words still advance
        # the scan, and a resumed run repeats them rather than skipping the unanswered one.
        if self.covered[parent] == start:
            self.covered[parent] = end if answered is None else min(end, start + answered)
        if limited:
            self.limited.add(parent)
        if end < self.limits[parent] and not limited and parent not in self.stopped:
            heapq.heappush(self._heap, (end, order, parent))

    def stop(self, parent):
        """Ask no more words beneath ``parent``; call before completing its reservation."""
        self.stopped.add(parent)

    def retry(self, reservation):
        parent, start, _end, _event, order = reservation
        heapq.heappush(self._heap, (start, order, parent))
