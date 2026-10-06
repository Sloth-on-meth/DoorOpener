"""Concurrent touch_user() must not undo an admin edit by saving a stale snapshot."""

import threading

from users_store import UsersStore


def test_concurrent_touch_does_not_revert_disable(tmp_path):
    store = UsersStore(str(tmp_path / "users.json"))
    store.create_user("alice", "1234")
    stop = threading.Event()

    def toucher():
        while not stop.is_set():
            store.touch_user("alice")

    t = threading.Thread(target=toucher)
    t.start()
    try:
        for _ in range(50):
            store.update_user("alice", active=False)
            # read back through a fresh instance so we assert what actually reached the file
            assert UsersStore(str(tmp_path / "users.json")).list_users()["users"][0]["active"] is False
            store.update_user("alice", active=True)
    finally:
        stop.set()
        t.join()


def test_concurrent_touches_are_all_counted(tmp_path):
    store = UsersStore(str(tmp_path / "users.json"))
    store.create_user("bob", "4321")
    threads = [threading.Thread(target=lambda: [store.touch_user("bob") for _ in range(25)]) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert UsersStore(str(tmp_path / "users.json")).list_users()["users"][0]["times_used"] == 100
