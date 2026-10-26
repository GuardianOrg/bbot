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
