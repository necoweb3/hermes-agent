"""Tests for session expiry watcher dict iteration safety.

P1-5: The session expiry watcher iterates session_store._entries without
holding the store's threading lock.  Thread-pool callers (batch runner,
cron worker) can mutate _entries concurrently, potentially causing
RuntimeError from dict size changes during iteration.  The fix acquires
the session-store lock for the entire snapshot+iteration block.
"""

import inspect
import threading

import pytest

from gateway.run import GatewayRunner


class TestSessionExpiryWatcherLock:
    """Verify the expiry watcher acquires the session-store lock."""

    def test_watcher_uses_ensure_loaded_locked(self):
        """The watcher must call _ensure_loaded_locked (not _ensure_loaded)
        while holding the lock."""
        source = inspect.getsource(GatewayRunner._session_expiry_watcher)
        assert "_ensure_loaded_locked" in source, (
            "Watcher should use _ensure_loaded_locked under lock"
        )

    def test_watcher_iteration_is_under_lock(self):
        """The _entries.items() iteration must be inside the lock block."""
        source = inspect.getsource(GatewayRunner._session_expiry_watcher)
        # Check that _entries.items() appears after _lock acquisition
        lock_idx = source.find("_lock:")
        entries_idx = source.find("_entries.items()")
        assert lock_idx != -1, "Watcher should acquire _lock"
        assert entries_idx != -1, "Watcher should iterate _entries"
        assert lock_idx < entries_idx, (
            "_entries.items() should appear after _lock acquisition in source"
        )

    def test_watcher_lock_block_encloses_both_load_and_iterate(self):
        """The lock must cover both _ensure_loaded_locked and the iteration,
        not just one or the other."""
        source = inspect.getsource(GatewayRunner._session_expiry_watcher)
        # Find the with-block that holds _lock
        with_lock_start = source.find("with self.session_store._lock:")
        assert with_lock_start != -1, "No 'with self.session_store._lock:' found"

        # Find _ensure_loaded_locked and _entries.items() within the with-block
        after_lock = source[with_lock_start:]
        loaded_idx = after_lock.find("_ensure_loaded_locked")
        entries_idx = after_lock.find("_entries.items()")

        assert loaded_idx != -1, "_ensure_loaded_locked not found after lock"
        assert entries_idx != -1, "_entries.items() not found after lock"
        assert loaded_idx < entries_idx, (
            "_ensure_loaded_locked should appear before _entries.items()"
        )

    def test_watcher_does_not_call_unlocked_ensure_loaded(self):
        """The watcher must not call _ensure_loaded() (the unlocked variant)
        during iteration."""
        source = inspect.getsource(GatewayRunner._session_expiry_watcher)
        # Find _ensure_loaded calls that are NOT _ensure_loaded_locked
        import re
        unlocked_calls = [
            m for m in re.finditer(r"_ensure_loaded\(\)", source)
            if not source[m.start():m.end() + 8].startswith("_ensure_loaded_locked")
        ]
        assert len(unlocked_calls) == 0, (
            f"Found {len(unlocked_calls)} calls to _ensure_loaded() (unlocked) "
            "in watcher — should use _ensure_loaded_locked under lock"
        )

    def test_concurrent_mutation_with_lock_does_not_crash(self):
        """With the lock held, concurrent dict mutation cannot crash the watcher."""
        _entries = {}
        _lock = threading.Lock()
        results = []

        class FakeEntry:
            def __init__(self, sid):
                self.session_id = sid
                self.expiry_finalized = False

        for i in range(100):
            _entries[f"session:{i}"] = FakeEntry(f"session:{i}")

        def mutate_dict():
            """Simulate a thread-pool caller mutating the dict."""
            import time
            time.sleep(0.005)
            with _lock:
                for i in range(100, 120):
                    _entries[f"new:{i}"] = FakeEntry(f"new:{i}")

        def safe_iteration():
            """Simulate the fixed watcher: iterate under lock."""
            import time
            try:
                with _lock:
                    # Snapshot + iterate while holding lock
                    for key, entry in list(_entries.items()):
                        pass
                results.append("ok")
            except RuntimeError as e:
                results.append(f"crash: {e}")

        t = threading.Thread(target=mutate_dict)
        t2 = threading.Thread(target=safe_iteration)
        t.start()
        t2.start()
        t.join()
        t2.join()

        assert results == ["ok"], f"Watcher iteration failed: {results}"
