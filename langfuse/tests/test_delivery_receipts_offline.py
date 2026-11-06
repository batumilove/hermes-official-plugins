"""Offline, stdlib-only evidence and adapter tests. No SDK/network/credentials required."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("receipt_test_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from receipt_test_plugin import delivery_receipts as dr

TID, RID, CID = "1" * 32, "2" * 16, "3" * 16


@unittest.skipUnless(sys.platform == "linux", "Receipt producer identity requires Linux /proc")
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "receipts"
        self.path.mkdir(mode=0o700)
        self.addCleanup(self.temp.cleanup)

    def receipt(self):
        return dr.Receipt(self.path, TID, RID, "synthetic-turn")

    def completed(self):
        r = self.receipt()
        r.started(CID); r.ended(CID); r.ended(RID)
        self.assertTrue(r.finish())
        self.recorder = r
        return r, dr.read_receipt(self.path, TID)

    def reconcile(self, receipt, backend):
        return dr.reconcile(receipt, backend, terminal_proof=self.recorder.terminal_proof())

    def backend(self):
        return {"trace_id": TID, "complete": True, "producer_terminal_verified": True,
                "local_receipt_current": True, "observations": [
                    {"id": RID, "trace_id": TID, "parent_id": None, "ended": True},
                    {"id": CID, "trace_id": TID, "parent_id": RID, "ended": True}]}

    def test_complete_inventory_only(self):
        _, receipt = self.completed()
        self.assertEqual(self.reconcile(receipt, self.backend()), "captured_inventory_delivered")
        self.assertEqual((self.path / (TID + ".json")).stat().st_mode & 0o777, 0o600)
        self.assertNotIn("synthetic-turn", json.dumps(receipt))
        self.assertEqual(receipt["producer"]["pid"], os.getpid())

    def test_incomplete_backend_and_missing_terminal_evidence(self):
        _, receipt = self.completed()
        for key in ["complete", "producer_terminal_verified", "local_receipt_current"]:
            with self.subTest(key=key):
                backend = self.backend(); backend[key] = False
                self.assertEqual(self.reconcile(receipt, backend), "unverified")

    def test_missing_extra_duplicate_wrong_parent_wrong_trace(self):
        _, receipt = self.completed()
        b = self.backend()
        variants = []
        x = copy.deepcopy(b); x["observations"].pop(); variants.append(x)
        x = copy.deepcopy(b); x["observations"].append(dict(x["observations"][1], id="4"*16)); variants.append(x)
        x = copy.deepcopy(b); x["observations"].append(x["observations"][1]); variants.append(x)
        x = copy.deepcopy(b); x["observations"][1]["parent_id"] = "4"*16; variants.append(x)
        x = copy.deepcopy(b); x["observations"][1]["trace_id"] = "4"*32; variants.append(x)
        x = copy.deepcopy(b); x["observations"][1]["ended"] = False; variants.append(x)
        for x in variants:
            self.assertNotEqual(self.reconcile(receipt, x), "captured_inventory_delivered")

    def test_expired_future_bad_identity_and_invalid_types(self):
        _, receipt = self.completed()
        for key, value in [("created_at", time.time()-dr.MAX_AGE-1), ("created_at", time.time()+100),
                           ("sealed_at", float("nan")), ("inventory_valid", 1), ("schema", None)]:
            x = copy.deepcopy(receipt); x[key] = value
            self.assertEqual(self.reconcile(x, self.backend()), "unverified")
        x = copy.deepcopy(receipt); x["producer"]["pid"] = True
        self.assertEqual(self.reconcile(x, self.backend()), "unverified")

    def test_open_child_shutdown_and_overflow_not_complete(self):
        for reason in ["normal", "shutdown", "eviction", "error"]:
            with tempfile.TemporaryDirectory() as directory:
                r = dr.Receipt(directory, TID, RID, "turn")
                r.started(CID); r.ended(RID); r.finish(reason)
                doc = dr.read_receipt(directory, TID)
                self.assertFalse(doc["local_complete"])
        r = self.receipt()
        for n in range(dr.MAX_OBSERVATIONS): r.started(f"{n:016x}")
        r.ended(RID);r.finish()
        self.assertFalse(dr.read_receipt(self.path, TID)["inventory_valid"])

    def test_late_event_invalidates_terminal_proof_without_writing(self):
        r, _ = self.completed()
        before = {p.name: p.read_bytes() for p in self.path.iterdir()}
        r.started("4"*16)
        self.assertEqual(self.reconcile(dr.read_receipt(self.path,TID), self.backend()), "unverified")
        self.assertEqual(before, {p.name:p.read_bytes() for p in self.path.iterdir()})

    def test_no_overwrite_or_symlink_follow(self):
        _, receipt = self.completed()
        before=(self.path/(TID+".json")).read_bytes()
        r=self.receipt();r.ended(RID)
        self.assertFalse(r.finish())
        self.assertEqual(before,(self.path/(TID+".json")).read_bytes())
        target=Path(self.temp.name)/"target";target.write_text("untouched")
        (self.path/("4"*32+".json")).symlink_to(target)
        r=dr.Receipt(self.path,"4"*32,RID,"turn");r.ended(RID)
        self.assertFalse(r.finish());self.assertEqual(target.read_text(),"untouched")

    def test_directory_privacy_and_parent_symlink(self):
        self.path.chmod(0o755)
        r=self.receipt();r.ended(RID);self.assertFalse(r.finish())
        self.path.chmod(0o700)
        link=Path(self.temp.name)/"alias";link.symlink_to(self.path,target_is_directory=True)
        r=dr.Receipt(link,TID,RID,"turn");r.ended(RID);self.assertFalse(r.finish())

    def test_capacity_and_expired_evidence_fail_closed(self):
        self.completed()
        f=self.path/(TID+".json");os.utime(f,(time.time()-dr.MAX_AGE-1,)*2)
        r=dr.Receipt(self.path,"4"*32,RID,"turn");r.ended(RID);self.assertFalse(r.finish())
        os.utime(f,None)
        old=dr.MAX_FILES;dr.MAX_FILES=1
        try:
            r=dr.Receipt(self.path,"4"*32,RID,"turn");r.ended(RID);self.assertFalse(r.finish())
        finally:dr.MAX_FILES=old

    def test_concurrent_local_children(self):
        r=self.receipt()
        def run(n):
            oid=f"{n:016x}";r.started(oid);r.ended(oid)
        threads=[threading.Thread(target=run,args=(n,)) for n in range(32)]
        for t in threads:t.start()
        for t in threads:t.join()
        r.ended(RID);self.assertTrue(r.finish())
        self.assertTrue(dr.read_receipt(self.path,TID)["local_complete"])

    def test_plugin_adapter_and_end_failure(self):
        class Span:
            id=RID
            def set_trace_io(self,**kw):pass
            def start_observation(self,**kw):
                s=Span();s.id=CID;return s
            def end(self):pass
        class Client:
            def create_trace_id(self,**kw):return TID
            def start_observation(self,**kw):return Span()
        from types import SimpleNamespace
        old = plugin._RECEIPT_RUNTIME
        plugin._RECEIPT_RUNTIME = SimpleNamespace(open_trace=lambda trace, root, turn:
                                                  dr.Receipt(self.path, trace, root, turn))
        self.addCleanup(setattr, plugin, "_RECEIPT_RUNTIME", old)
        state=plugin._start_root_trace("key",task_id="task",session_id="session",platform="telegram",provider="",model="",api_mode="",messages=None,client=Client(),turn_id="turn")
        child=plugin._start_child_observation(state,name="private tool name",as_type="tool",input_value="SECRET_SENTINEL")
        plugin._end_observation(child)
        plugin._end_root(state,"root end()")
        receipt=dr.read_receipt(self.path,TID)
        self.assertTrue(receipt["local_complete"])
        self.assertNotIn("SECRET_SENTINEL",json.dumps(receipt))
        self.assertNotIn("private tool name",json.dumps(receipt))
        class Broken:
            id=CID
            def end(self):raise RuntimeError("SECRET_SENTINEL")
        r=dr.Receipt(self.path,"4"*32,RID,"turn");r.started(CID)
        plugin._end_observation(plugin._ReceiptObservation(Broken(),r))
        r.ended(RID);r.finish()
        self.assertFalse(dr.read_receipt(self.path,"4"*32)["local_complete"])

    def test_busy_writer_does_not_wait(self):
        import fcntl
        fd = os.open(self.path / ".writer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.receipt(); r.ended(RID)
            self.assertFalse(r.finish())
            self.assertFalse((self.path / (TID + ".json")).exists())
        finally: os.close(fd)

    def test_truncated_receipt_and_incomplete_schema_rejected(self):
        p=self.path/(TID+".json")
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:f.write('{"schema":')
        with self.assertRaises(ValueError):dr.read_receipt(self.path,TID)
        self.assertEqual(dr.reconcile({},{}),"unverified")

    def test_failed_storage_during_late_event_cannot_reuse_success(self):
        r, receipt = self.completed()
        old=dr._private_directory
        dr._private_directory=lambda p: (_ for _ in ()).throw(PermissionError())
        try:r.started("4"*16)
        finally:dr._private_directory=old
        self.assertEqual(self.reconcile(dr.read_receipt(self.path,TID),self.backend()),"unverified")
        self.assertEqual(dr.reconcile(receipt,self.backend()),"unverified")

    def test_adapter_fault_racing_finish_invalidates_proof(self):
        r=self.receipt();entered=threading.Event();release=threading.Event()
        class BadID:
            @property
            def id(self):raise RuntimeError("synthetic")
        class Root:
            def start_observation(self,**kw):entered.set();release.wait(2);return BadID()
        adapter=plugin._ReceiptObservation(Root(),r)
        t=threading.Thread(target=adapter.start_observation);t.start()
        self.assertTrue(entered.wait(2));r.ended(RID);self.assertTrue(r.finish());release.set();t.join(2)
        self.assertFalse(t.is_alive());self.assertFalse(r.terminal_proof()["valid"])
        self.assertFalse(any(p.suffix==".invalid" for p in self.path.iterdir()))

    def test_end_id_fault_after_sealing_invalidates_proof(self):
        r,_=self.completed()
        class BadID:
            @property
            def id(self):raise RuntimeError("synthetic")
            def end(self):pass
        plugin._ReceiptObservation(BadID(),r).end()
        self.assertFalse(r.terminal_proof()["valid"])

    def test_full_capacity_late_events_never_grow_directory(self):
        old=dr.MAX_FILES;dr.MAX_FILES=1
        try:
            self.completed();before=set(self.path.iterdir())
            for n in range(5):
                r=dr.Receipt(self.path,f"{n:032x}",RID,"turn");r.ended(RID)
                self.assertFalse(r.finish());r.started(CID)
                self.assertFalse(r.terminal_proof()["valid"])
            self.assertEqual(before,set(self.path.iterdir()))
        finally:dr.MAX_FILES=old

    def test_actual_session_shutdown_hook_not_normal(self):
        r=self.receipt()
        class Span:
            id=RID
            def end(self):pass
        class Client:
            def flush(self):pass
            def shutdown(self):pass
        c=Client();oldget=plugin._get_langfuse;oldsettled=plugin._settled_client
        oldstates=plugin._TRACE_STATE
        plugin._get_langfuse=lambda:c;plugin._settled_client=lambda:c
        plugin._TRACE_STATE={"session:synthetic:turn:synthetic":plugin.TraceState(trace_id=TID,root_span=plugin._ReceiptObservation(Span(),r),receipt=r)}
        try:plugin.on_session_finalize(session_id="synthetic",reason="shutdown")
        finally:plugin._get_langfuse=oldget;plugin._settled_client=oldsettled;plugin._TRACE_STATE=oldstates
        doc=dr.read_receipt(self.path,TID)
        self.assertEqual(doc["terminal_reason"],"shutdown");self.assertFalse(doc["local_complete"])
        self.assertFalse(r.terminal_proof()["valid"])

    def test_proof_is_bound_to_exact_receipt_and_producer(self):
        r,doc=self.completed();proof=r.terminal_proof()
        self.assertEqual(dr.reconcile(doc,self.backend(),terminal_proof=proof),"captured_inventory_delivered")
        bad=copy.deepcopy(proof);bad["receipt_sha256"]="0"*64
        self.assertEqual(dr.reconcile(doc,self.backend(),terminal_proof=bad),"unverified")
        bad=copy.deepcopy(proof);bad["producer"]["pid"]+=1
        self.assertEqual(dr.reconcile(doc,self.backend(),terminal_proof=bad),"unverified")

    def test_disabled_has_no_receipt(self):
        old=plugin._secret;plugin._secret=lambda name:""
        self.addCleanup(setattr,plugin,"_secret",old)
        class Span:
            def set_trace_io(self,**kw):pass
        class Client:
            def create_trace_id(self,**kw):return TID
            def start_observation(self,**kw):return Span()
        state=plugin._start_root_trace("key",task_id="task",session_id="session",platform="telegram",provider="",model="",api_mode="",messages=None,client=Client(),turn_id="turn")
        self.assertIsNone(state.receipt)
        self.assertEqual(list(self.path.iterdir()),[])

if __name__ == "__main__": unittest.main()
