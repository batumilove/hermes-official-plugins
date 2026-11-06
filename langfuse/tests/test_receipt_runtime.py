"""Offline plugin root-to-host-boundary integration; SDK is a local recording double."""
from contextlib import nullcontext
import importlib.util
import sys
from types import SimpleNamespace

import pytest

if importlib.util.find_spec("hermes_cli.plugins_turn_boundary") is None:
    pytest.skip("Host lacks the optional turn-evidence API; pinned-core CI exercises it",
                allow_module_level=True)

import langfuse_plugin as plugin
from langfuse_plugin.receipt_runtime import ReceiptRuntime
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from hermes_cli.plugins_turn_boundary import turn_boundary
from hermes_cli.plugins_turn_evidence_collector import TurnEvidenceCollector
from langfuse_plugin import delivery_receipts

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                 reason="Receipt producer identity requires Linux /proc")


@pytest.fixture
def world(tmp_path, monkeypatch):
    directory = tmp_path / "receipts"
    directory.mkdir(mode=0o700)
    manager = PluginManager(scope_key=str(tmp_path))
    context = PluginContext(PluginManifest(name="langfuse"), manager)
    settings = {"enabled": True, "directory": str(directory)}
    monkeypatch.setattr(context, "get_config", lambda key, default=None: settings)
    monkeypatch.setattr(plugin, "_core_ships_langfuse", lambda: False)
    plugin.register(context)
    yield manager, context, settings
    plugin._TRACE_STATE.clear()
    plugin._RECEIPT_RUNTIME = None


def test_real_root_teardown_preserves_original_reader(world, monkeypatch):
    manager, _context, _ = world
    root = SimpleNamespace(id="b" * 16, set_trace_io=lambda **kw: None,
                           update=lambda **kw: None, end=lambda: None)
    client = SimpleNamespace(create_trace_id=lambda **kw: "a" * 32,
                             start_observation=lambda **kw: root)
    monkeypatch.setattr(plugin, "propagate_attributes", lambda **kw: nullcontext())
    monkeypatch.setattr(plugin, "_get_langfuse", lambda: client)
    with turn_boundary(manager, "turn"):
        state = plugin._start_root_trace(task_key="task", session_id="session", task_id="",
                    platform="", provider="", model="", api_mode="", messages=[],
                    client=client, turn_id="turn")
        assert state.receipt is not None
        plugin._TRACE_STATE["task"] = state
        plugin._finish_trace("task", output="done")
        assert "task" not in plugin._TRACE_STATE
        report = plugin._RECEIPT_RUNTIME.collect("turn", deadline_seconds=0.01)
        assert report["a" * 32]["status"] == "unknown"
    report = plugin._RECEIPT_RUNTIME.collect("turn")
    assert report["a" * 32]["status"] == "collected"
    assert report["a" * 32]["proof"]["valid"] is True
    state.receipt.invalidate()
    collector = next(iter(plugin._RECEIPT_RUNTIME.turns.values()))[1]
    with pytest.raises(RuntimeError, match="no transfer key"):
        collector.issue_transfer("a" * 32)


@pytest.mark.parametrize("case", ["disabled", "relative", "unscoped", "wrong_turn"])
def test_admission_rejects_without_receipt_files(world, case):
    manager, _, settings = world
    runtime = plugin._RECEIPT_RUNTIME
    if case == "disabled":
        settings["enabled"] = False
    if case == "relative":
        settings["directory"] = "relative"
    if case == "unscoped":
        assert runtime.open_trace("a" * 32, "b" * 16, "turn") is None
    else:
        with turn_boundary(manager, "turn"):
            assert runtime.open_trace("a" * 32, "b" * 16,
                                      "other" if case == "wrong_turn" else "turn") is None
    assert not runtime.turns


def test_capacity_expiry_and_ambiguous_turns(world):
    manager, context, _settings = world
    now = [0.0]
    runtime = ReceiptRuntime(context, clock=lambda: now[0])
    for i in range(16):
        with turn_boundary(manager, "turn"):
            assert runtime.open_trace(f"{i:032x}", "b" * 16, "turn") is not None
    assert runtime.collect("turn") == {"status": "unverified"}
    with turn_boundary(manager, "new"):
        assert runtime.open_trace("f" * 32, "b" * 16, "new") is None
    now[0] = 301.0
    assert runtime.collect("turn") == {"status": "unverified"}
    assert not runtime.turns


def test_attachment_cannot_reopen_closed_or_foreign_scope(world):
    manager, context, settings = world
    collector = TurnEvidenceCollector(manager, context, delivery_receipts,
                       turn_id="turn", receipt_directory=settings["directory"])
    with pytest.raises(RuntimeError):
        collector.attach_current_turn()
    with turn_boundary(manager, "other"):
        with pytest.raises(RuntimeError):
            collector.attach_current_turn()
    with turn_boundary(manager, "turn") as scope:
        scope.close(True)
        with pytest.raises(RuntimeError):
            collector.attach_current_turn()


def test_profile_yaml_opt_in_uses_real_context_reader(tmp_path, monkeypatch):
    import os
    from pathlib import Path
    import yaml

    home = Path(os.environ["HERMES_HOME"])
    directory = tmp_path / "private-receipts"
    directory.mkdir(mode=0o700)
    data = {"plugins": {"entries": {"langfuse": {"settings": {
        "receipts": {"enabled": True, "directory": str(directory)}}}}}}
    (home / "config.yaml").write_text(yaml.safe_dump(data))
    manager = PluginManager(scope_key=str(home))
    context = PluginContext(PluginManifest(name="langfuse"), manager)
    runtime = ReceiptRuntime(context)
    with turn_boundary(manager, "yaml-turn"):
        assert runtime.open_trace("e" * 32, "b" * 16, "yaml-turn") is not None


def test_concurrent_attachment_commits_only_one_authority(world):
    import threading
    manager, context, settings = world
    collector = TurnEvidenceCollector(manager, context, delivery_receipts,
                       turn_id="turn", receipt_directory=settings["directory"])
    start = threading.Barrier(2)
    both_scopes_entered = threading.Event()
    count_lock = threading.Lock()
    count = [0]
    attached, errors = [], []

    class ScheduledScopeLock:
        def __init__(self, inner):
            self.inner = inner
            self.first = True

        def __enter__(self):
            if self.first:
                self.first = False
                with count_lock:
                    count[0] += 1
                    if count[0] == 2:
                        both_scopes_entered.set()
                # In the broken implementation both independent scope locks can
                # enter before either commits. A serialized winner proceeds alone.
                both_scopes_entered.wait(timeout=2)
            self.inner.acquire()
            return self

        def __exit__(self, *args):
            self.inner.release()

    def attach():
        try:
            with turn_boundary(manager, "turn") as scope:
                scope.lock = ScheduledScopeLock(scope.lock)
                start.wait(timeout=5)
                try:
                    collector.attach_current_turn()
                    attached.append(scope)
                except RuntimeError:
                    pass
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=attach) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert not errors and not any(thread.is_alive() for thread in threads)
    assert len(attached) == 1
    assert collector._boundary is attached[0]
    with pytest.raises(RuntimeError):
        with collector.begin_turn():
            pass
