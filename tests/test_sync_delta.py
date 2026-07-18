import threading
import unittest
from collections import deque

from mijiaAPI.api_server import (
    SYNC_EVENT_HISTORY_LIMIT,
    ManagedSession,
    _build_sync_delta,
    _merge_sync_events,
)


def _state(*, online=False, value=0, structure="stable"):
    return {
        "structure": structure,
        "devices": {
            "device-1": {
                "online": online,
                "properties": {
                    "2:1": {
                        "siid": 2,
                        "piid": 1,
                        "value": value,
                        "error": None,
                    }
                },
            }
        },
    }


def _event(base, revision, changes, *, resync=False):
    return {
        "base_revision": base,
        "revision": revision,
        "generated_at": 1000 + revision,
        "resync_required": resync,
        "changes": changes,
    }


class SyncDeltaTests(unittest.TestCase):
    def test_unchanged_state_has_no_delta(self):
        changes, resync = _build_sync_delta(_state(), _state())
        self.assertEqual(changes, [])
        self.assertFalse(resync)

    def test_only_changed_values_are_emitted(self):
        changes, resync = _build_sync_delta(
            _state(online=False, value=1),
            _state(online=True, value=2),
        )
        self.assertFalse(resync)
        self.assertEqual([item["method"] for item in changes], [
            "device_online_changed",
            "properties_changed",
        ])
        self.assertEqual(changes[1]["params"], [{
            "did": "device-1",
            "siid": 2,
            "piid": 1,
            "previous_value": 1,
            "previous_code": 0,
            "value": 2,
            "code": 0,
        }])

    def test_structure_change_requires_snapshot(self):
        changes, resync = _build_sync_delta(
            _state(structure="old"),
            _state(structure="new"),
        )
        self.assertEqual(changes, [])
        self.assertTrue(resync)

    def test_event_merge_keeps_latest_property_value(self):
        first = _event(1, 2, [{
            "method": "properties_changed",
            "params": [{"did": "d", "siid": 2, "piid": 1, "value": 10}],
        }])
        second = _event(2, 3, [{
            "method": "properties_changed",
            "params": [{"did": "d", "siid": 2, "piid": 1, "value": 20}],
        }])
        merged = _merge_sync_events(1, [first, second])
        self.assertEqual(merged["base_revision"], 1)
        self.assertEqual(merged["revision"], 3)
        self.assertEqual(merged["changes"][0]["params"][0]["value"], 20)

    def test_event_merge_drops_round_trip_to_original_value(self):
        first = _event(1, 2, [{
            "method": "device_online_changed",
            "params": [{"did": "d", "previous_value": False, "value": True}],
        }])
        second = _event(2, 3, [{
            "method": "device_online_changed",
            "params": [{"did": "d", "previous_value": True, "value": False}],
        }])
        merged = _merge_sync_events(1, [first, second])
        self.assertEqual(merged["changes"], [])

    def test_history_returns_continuous_merged_delta(self):
        session = ManagedSession.__new__(ManagedSession)
        session._sync_lock = threading.RLock()
        session._sync_revision = 3
        session._sync_state = _state(value=3)
        session._sync_events = deque(maxlen=SYNC_EVENT_HISTORY_LIMIT)
        session._sync_events.extend([
            _event(1, 2, [{
                "method": "properties_changed",
                "params": [{"did": "d", "siid": 2, "piid": 1, "value": 2}],
            }]),
            _event(2, 3, [{
                "method": "properties_changed",
                "params": [{"did": "d", "siid": 2, "piid": 1, "value": 3}],
            }]),
        ])
        revision, event, resync = session.get_sync_event_after(1)
        self.assertEqual(revision, 3)
        self.assertFalse(resync)
        self.assertEqual(event["revision"], 3)
        self.assertEqual(event["changes"][0]["params"][0]["value"], 3)

    def test_history_gap_requires_snapshot(self):
        session = ManagedSession.__new__(ManagedSession)
        session._sync_lock = threading.RLock()
        session._sync_revision = 4
        session._sync_state = _state(value=4)
        session._sync_events = deque([
            _event(3, 4, []),
        ], maxlen=SYNC_EVENT_HISTORY_LIMIT)
        revision, event, resync = session.get_sync_event_after(1)
        self.assertEqual(revision, 4)
        self.assertIsNone(event)
        self.assertTrue(resync)


if __name__ == "__main__":
    unittest.main()
