from bbot.modules.dnsbrute_queue import DNSBruteQueue


def test_new_parent_catches_up_before_older_parent_advances():
    queue = DNSBruteQueue(23000)
    assert queue.add("a.example.com", object())
    first = queue.reserve(5000, 5)
    assert [(item[0], item[1:3]) for item in first] == [("a.example.com", (0, 5000))]
    queue.complete(first[0])

    assert queue.add("b.example.com", object())
    assert not queue.add("b.example.com", object())
    catch_up = queue.reserve(5000, 5)
    assert [(item[0], item[1:3]) for item in catch_up] == [("b.example.com", (0, 5000))]
    queue.complete(catch_up[0])
    shared = queue.reserve(5000, 5)
    assert [(item[0], item[1:3]) for item in shared] == [
        ("a.example.com", (5000, 7500)),
        ("b.example.com", (5000, 7500)),
    ]


def test_five_equal_parents_share_one_5000_name_round():
    queue = DNSBruteQueue(107178)
    for index in range(5):
        queue.add(f"{index}.example.com", object())
    batch = queue.reserve(5000, 5)
    assert len(batch) == 5
    assert all((start, end) == (0, 1000) for _parent, start, end, _event, _order in batch)
    for item in batch:
        queue.complete(item)
    assert set(queue.positions.values()) == {1000}


def test_queue_respects_child_limit_and_retries_failed_batch():
    queue = DNSBruteQueue(107178)
    queue.add("child.example.com", object(), limit=2000)
    reservation = queue.reserve(5000, 5)[0]
    queue.retry(reservation)
    again = queue.reserve(5000, 5)[0]
    assert again[1:3] == (0, 5000)
    queue.complete(again)
    assert queue.positions["child.example.com"] == 2000
    assert not queue


def test_late_parent_preempts_partly_completed_round():
    queue = DNSBruteQueue(23000)
    for index in range(5):
        queue.add(f"{index}.example.com", object())
    batch = queue.reserve(5000, 5)
    for item in batch:
        queue.complete(item)
    queue.add("late.example.com", object())
    assert queue.reserve(5000, 5)[0][:3] == ("late.example.com", 0, 1000)


def test_few_parents_use_full_vocabulary_without_rechecking_words():
    queue = DNSBruteQueue(107178)
    for parent in ("halborn.com", "guardian.security"):
        queue.add(parent, object())
    seen = {parent: set() for parent in queue.events}
    rounds = 0
    while queue:
        rounds += 1
        for reservation in queue.reserve(5000, 5):
            parent, start, end, *_ = reservation
            assert not seen[parent].intersection(range(start, end))
            seen[parent].update(range(start, end))
            queue.complete(reservation)
    assert rounds < 100
    assert all(len(words) == 107178 for words in seen.values())


def test_many_parents_share_rounds_and_new_parent_catches_up():
    queue = DNSBruteQueue(107178)
    for index in range(200):
        queue.add(f"host{index}.halborn.com", object())
    for _ in range(40):
        batch = queue.reserve(5000, 5)
        assert len(batch) == 5
        assert sum(end - start for _, start, end, *_ in batch) <= 5000
        for reservation in batch:
            queue.complete(reservation)
    assert set(queue.positions.values()) == {1000}
    queue.add("late.hacktricks-training.com", object())
    late = queue.reserve(5000, 5)
    assert [entry[:3] for entry in late] == [("late.hacktricks-training.com", 0, 1000)]
    queue.complete(late[0])
    next_round = queue.reserve(5000, 5)
    assert len(next_round) == 5
    assert all(start == 1000 for _, start, *_ in next_round)


def test_large_parent_count_still_fits_the_round_budget():
    queue = DNSBruteQueue(107178)
    for index in range(1000):
        queue.add(f"host{index}.guardian.security", object())
    for _ in range(200):
        batch = queue.reserve(5000, 5)
        assert len(batch) == 5
        assert sum(end - start for _, start, end, *_ in batch) == 5000
        for reservation in batch:
            queue.complete(reservation)
    assert set(queue.positions.values()) == {1000}
