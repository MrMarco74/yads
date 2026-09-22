"""
Regression test for the chord callback in _dispatch_module_chord.

A Celery chord prepends the group's result list to its callback's arguments
unless the callback signature is immutable. finalize_scan was dispatched with
`.s(...)`, so every argument shifted by one:

    target_id       <- [None, None, ...]   (the group result)
    domain          <- target_id
    tenant_id       <- domain
    scan_types      <- tenant_id           (an int)

and finalize_scan died on `set(scan_types)` with
"TypeError: 'int' object is not iterable". Since finalize_scan is what resets
a target from "running" back to "idle", every chord-dispatched scan left its
target hanging -- the 204 stuck targets seen on 2026-09-21.

finalize_scan does not use the group results, so the callback must be
immutable.
"""
from unittest.mock import MagicMock, patch

from yads.worker_tasks import _dispatch_module_chord


def _fake_module(name):
    mod = MagicMock()
    mod.name = name
    mod.requires_https = False
    mod.requires_http = False
    return mod


def test_chord_callback_is_immutable_so_arguments_do_not_shift():
    scan_types = ["asn_scanner"]

    with patch("yads.worker_tasks.get_simple_dispatch_modules",
               return_value=[_fake_module("asn_scanner")]), \
         patch("yads.worker_tasks.run_scan_module"), \
         patch("yads.worker_tasks.finalize_scan") as finalize, \
         patch("yads.worker_tasks.chord"):
        _dispatch_module_chord(42, "example.com", 2, scan_types,
                               has_http=True, has_https=True, is_parked=False,
                               scan_start_time="2026-09-22T00:00:00")

    finalize.si.assert_called_once_with(42, "example.com", 2, scan_types,
                                        "2026-09-22T00:00:00")
    finalize.s.assert_not_called()
