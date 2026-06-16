from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime

from backup_audit.snapshot import (
    SnapshotStore,
    SnapshotRecord,
    OperationSnapshot,
    SnapshotSealedError,
    SnapshotNameConflictError,
    SnapshotAction,
    SnapshotStatus,
    _config_dir_fingerprint,
    build_config_summary,
)
from backup_audit.waiver import (
    WaiverStore,
    WaiverRule,
    WaiverTransactionStatus,
)


class TestDuplicateNameMisuse(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.snap_store = SnapshotStore(snapshots_dir=self.tmpdir)
        self.record = SnapshotRecord(
            command="test-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="初始记录",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_duplicate_name_raises_conflict_error(self):
        self.snap_store.create("ops-2025-q1", self.record)
        with self.assertRaises(SnapshotNameConflictError) as ctx:
            self.snap_store.create("ops-2025-q1", self.record)
        msg = str(ctx.exception)
        self.assertIn("ops-2025-q1", msg)
        self.assertIn("已存在", msg)
        self.assertIn("--append", msg)
        self.assertIn("--fork-from", msg)

    def test_duplicate_name_shows_sealed_status(self):
        snap = self.snap_store.create("sealed-snap", self.record)
        self.snap_store.seal("sealed-snap", actor="admin")
        with self.assertRaises(SnapshotNameConflictError) as ctx:
            self.snap_store.create("sealed-snap", self.record)
        msg = str(ctx.exception)
        self.assertIn("已封版", msg)

    def test_duplicate_name_shows_unsealed_status(self):
        self.snap_store.create("open-snap", self.record)
        with self.assertRaises(SnapshotNameConflictError) as ctx:
            self.snap_store.create("open-snap", self.record)
        msg = str(ctx.exception)
        self.assertIn("未封版", msg)
        self.assertIn("仍可追加", msg)

    def test_append_to_existing_unsealed_is_ok(self):
        self.snap_store.create("open-snap", self.record)
        r2 = SnapshotRecord(
            command="second-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="第二条记录",
        )
        result = self.snap_store.append("open-snap", r2)
        self.assertEqual(len(result.records), 2)

    def test_append_to_sealed_without_allow_raises(self):
        self.snap_store.create("sealed-snap", self.record)
        self.snap_store.seal("sealed-snap", actor="admin")
        r2 = SnapshotRecord(
            command="second-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="尝试追加",
        )
        with self.assertRaises(SnapshotSealedError):
            self.snap_store.append("sealed-snap", r2, allow_sealed=False)

    def test_append_to_sealed_with_allow_succeeds(self):
        self.snap_store.create("sealed-snap", self.record)
        self.snap_store.seal("sealed-snap", actor="admin")
        r2 = SnapshotRecord(
            command="append-after-seal",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="封版后续写",
        )
        result = self.snap_store.append("sealed-snap", r2, allow_sealed=True)
        self.assertEqual(len(result.records), 2)

    def test_add_record_on_sealed_snapshot_raises(self):
        snap = self.snap_store.create("my-snap", self.record)
        snap.seal("admin")
        r2 = SnapshotRecord(
            command="blocked",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="不应写入",
        )
        with self.assertRaises(SnapshotSealedError):
            snap.add_record(r2)


class TestCrossProcessAppendFork(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.snap_store = SnapshotStore(snapshots_dir=self.tmpdir)
        self.record = SnapshotRecord(
            command="init-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="初始记录",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_cross_process_append_unsealed(self):
        self.snap_store.create("shared-snap", self.record)
        store2 = SnapshotStore(snapshots_dir=self.tmpdir)
        r2 = SnapshotRecord(
            command="process-2-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="第二个进程追加",
        )
        result = store2.append("shared-snap", r2)
        self.assertEqual(len(result.records), 2)

        store3 = SnapshotStore(snapshots_dir=self.tmpdir)
        loaded = store3.load("shared-snap")
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded.records), 2)

    def test_cross_process_append_sealed_rejected(self):
        self.snap_store.create("shared-sealed", self.record)
        self.snap_store.seal("shared-sealed", actor="admin")

        store2 = SnapshotStore(snapshots_dir=self.tmpdir)
        r2 = SnapshotRecord(
            command="process-2-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="第二个进程尝试追加",
        )
        with self.assertRaises(SnapshotSealedError):
            store2.append("shared-sealed", r2, allow_sealed=False)

    def test_cross_process_append_sealed_with_allow(self):
        self.snap_store.create("shared-sealed", self.record)
        self.snap_store.seal("shared-sealed", actor="admin")

        store2 = SnapshotStore(snapshots_dir=self.tmpdir)
        r2 = SnapshotRecord(
            command="process-2-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="第二个进程封版后续写",
        )
        result = store2.append("shared-sealed", r2, allow_sealed=True)
        self.assertEqual(len(result.records), 2)

    def test_cross_process_fork_from_sealed(self):
        self.snap_store.create("source-snap", self.record)
        self.snap_store.seal("source-snap", actor="admin")

        store2 = SnapshotStore(snapshots_dir=self.tmpdir)
        r2 = SnapshotRecord(
            command="fork-record",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="分叉时的新记录",
        )
        forked = store2.fork_from("source-snap", "forked-snap", r2)
        self.assertEqual(forked.forked_from, "source-snap")
        self.assertEqual(len(forked.records), 2)
        self.assertFalse(forked.sealed)

    def test_cross_process_fork_preserves_records(self):
        r1 = SnapshotRecord(
            command="cmd-1",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="记录1",
            transaction_id="TX-001",
        )
        r2 = SnapshotRecord(
            command="cmd-2",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="记录2",
            transaction_id="TX-002",
        )
        source = self.snap_store.create("source", r1)
        self.snap_store.append("source", r2)

        store2 = SnapshotStore(snapshots_dir=self.tmpdir)
        forked = store2.fork_from("source", "fork-v2")
        self.assertEqual(len(forked.records), 2)
        self.assertEqual(forked.records[0].transaction_id, "TX-001")
        self.assertEqual(forked.records[1].transaction_id, "TX-002")

    def test_fork_to_existing_name_raises(self):
        self.snap_store.create("source", self.record)
        self.snap_store.create("target", self.record)
        with self.assertRaises(SnapshotNameConflictError):
            self.snap_store.fork_from("source", "target")

    def test_sealed_snapshot_survives_reload(self):
        snap = self.snap_store.create("persist-snap", self.record)
        self.snap_store.seal("persist-snap", actor="admin")

        store2 = SnapshotStore(snapshots_dir=self.tmpdir)
        loaded = store2.load("persist-snap")
        self.assertIsNotNone(loaded)
        self.assertTrue(loaded.sealed)
        self.assertIsNotNone(loaded.sealed_at)
        self.assertEqual(loaded.meta.get("sealed_by"), "admin")


class TestSealedExportAndWaiverReconciliation(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.snap_dir = os.path.join(self.tmpdir, "snapshots")
        self.waiver_dir = os.path.join(self.tmpdir, "waiver")
        os.makedirs(self.waiver_dir, exist_ok=True)
        self.snap_store = SnapshotStore(snapshots_dir=self.snap_dir)
        self.waiver_store = WaiverStore(
            rules_path=os.path.join(self.waiver_dir, "rules.json"),
            log_path=os.path.join(self.waiver_dir, "log.json"),
            transactions_path=os.path.join(self.waiver_dir, "tx.json"),
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_record(self, cmd="test-cmd", tx_id=None, success=True, summary="测试"):
        return SnapshotRecord(
            command=cmd,
            timestamp=datetime.now().isoformat(),
            success=success,
            output_summary=summary,
            transaction_id=tx_id,
        )

    def test_export_markdown_includes_staleness_when_tx_rolled_back(self):
        r = self._make_record(tx_id="TX-ROLLBACK-001")
        self.snap_store.create("export-snap", r)
        self.snap_store.seal("export-snap", actor="admin")

        from backup_audit.waiver import WaiverTransaction, WaiverTransactionStatus
        self.waiver_store.transactions.append(WaiverTransaction(
            id="TX-ROLLBACK-001",
            actor="admin",
            timestamp=datetime.now().isoformat(),
            status=WaiverTransactionStatus.ROLLED_BACK,
            mode="merge",
            source_file="test.json",
        ))
        self.waiver_store._save()

        md = self.snap_store.export_markdown("export-snap", self.waiver_store)
        self.assertIn("失效提示", md)
        self.assertIn("transaction_rolled_back", md)

    def test_export_markdown_includes_staleness_when_tx_missing(self):
        r = self._make_record(tx_id="TX-MISSING-999")
        self.snap_store.create("missing-tx-snap", r)
        self.snap_store.seal("missing-tx-snap", actor="admin")

        md = self.snap_store.export_markdown("missing-tx-snap", self.waiver_store)
        self.assertIn("transaction_missing", md)

    def test_export_json_includes_validation_sections(self):
        r = self._make_record(tx_id="TX-001")
        self.snap_store.create("json-snap", r)

        from backup_audit.waiver import WaiverTransaction, WaiverTransactionStatus
        self.waiver_store.transactions.append(WaiverTransaction(
            id="TX-001",
            actor="admin",
            timestamp=datetime.now().isoformat(),
            status=WaiverTransactionStatus.ROLLED_BACK,
            mode="merge",
            source_file="test.json",
        ))
        self.waiver_store._save()

        json_str = self.snap_store.export_json("json-snap", self.waiver_store)
        data = json.loads(json_str)
        self.assertIn("_staleness_warnings", data)
        self.assertIn("_transaction_validations", data)
        self.assertIn("_failed_record_validations", data)
        self.assertTrue(any(w["type"] == "transaction_rolled_back" for w in data["_staleness_warnings"]))

    def test_export_markdown_includes_config_summary(self):
        config_summary = build_config_summary(self.waiver_store)
        r = SnapshotRecord(
            command="import-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="导入完成",
            config_summary=config_summary,
        )
        self.snap_store.create("config-snap", r)
        self.snap_store.seal("config-snap", actor="admin")

        md = self.snap_store.export_markdown("config-snap", self.waiver_store)
        self.assertIn("配置摘要", md)
        self.assertIn("total_rules", md)

    def test_export_stale_detection_after_new_record(self):
        r1 = self._make_record(cmd="first", summary="第一条")
        self.snap_store.create("stale-snap", r1)
        self.snap_store.seal("stale-snap", actor="admin")

        output_path = os.path.join(self.tmpdir, "stale-export.md")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.snap_store.export_markdown("stale-snap", self.waiver_store))
        self.snap_store.record_export("stale-snap", "markdown", output_path)

        r2 = self._make_record(cmd="second", summary="追加记录")
        self.snap_store.append("stale-snap", r2, allow_sealed=True)

        staleness = self.snap_store.check_staleness("stale-snap", self.waiver_store)
        stale_types = [w["type"] for w in staleness]
        self.assertIn("export_stale", stale_types)

    def test_config_dir_change_triggers_staleness(self):
        r = self._make_record()
        snap = self.snap_store.create("fingerprint-snap", r)
        original_fp = snap.config_dir_fingerprint

        snap.config_dir_fingerprint = "DEADBEEF"
        self.snap_store._save(snap)

        staleness = self.snap_store.check_staleness("fingerprint-snap", self.waiver_store)
        stale_types = [w["type"] for w in staleness]
        self.assertIn("config_dir_changed", stale_types)

    def test_waiver_transactions_reconciliation(self):
        from backup_audit.waiver import WaiverTransaction, WaiverTransactionStatus
        tx_committed = WaiverTransaction(
            id="TX-COMMIT-001",
            actor="admin",
            timestamp=datetime.now().isoformat(),
            status=WaiverTransactionStatus.COMMITTED,
            mode="merge",
            source_file="test.json",
        )
        tx_rolled = WaiverTransaction(
            id="TX-ROLL-001",
            actor="admin",
            timestamp=datetime.now().isoformat(),
            status=WaiverTransactionStatus.ROLLED_BACK,
            mode="merge",
            source_file="test.json",
        )
        self.waiver_store.transactions = [tx_committed, tx_rolled]
        self.waiver_store._save()

        r1 = self._make_record(tx_id="TX-COMMIT-001")
        r2 = self._make_record(tx_id="TX-ROLL-001", cmd="rollback-cmd")
        self.snap_store.create("recon-snap", r1)
        self.snap_store.append("recon-snap", r2)
        self.snap_store.seal("recon-snap", actor="admin")

        warnings = self.snap_store.validate_transactions("recon-snap", self.waiver_store)
        has_rollback_warning = any("回滚" in w for w in warnings)
        self.assertTrue(has_rollback_warning)

        md = self.snap_store.export_markdown("recon-snap", self.waiver_store)
        self.assertIn("事务校验结果", md)
        self.assertIn("TX-ROLL-001", md)
        self.assertIn("回滚", md)

    def test_sealed_show_after_restart(self):
        r = self._make_record(tx_id="TX-PERSIST-001")
        self.snap_store.create("restart-snap", r)
        self.snap_store.seal("restart-snap", actor="admin")

        fresh_store = SnapshotStore(snapshots_dir=self.snap_dir)
        loaded = fresh_store.load("restart-snap")
        self.assertIsNotNone(loaded)
        self.assertTrue(loaded.sealed)
        self.assertEqual(len(loaded.records), 1)
        self.assertEqual(loaded.records[0].transaction_id, "TX-PERSIST-001")

        md = fresh_store.export_markdown("restart-snap", self.waiver_store)
        self.assertIn("已封版", md)

    def test_export_history_tracking(self):
        r = self._make_record()
        self.snap_store.create("hist-snap", r)
        self.snap_store.seal("hist-snap", actor="admin")

        output_path = os.path.join(self.tmpdir, "hist-export.md")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.snap_store.export_markdown("hist-snap", self.waiver_store))
        self.snap_store.record_export("hist-snap", "markdown", output_path)

        loaded = self.snap_store.load("hist-snap")
        self.assertEqual(len(loaded.export_history), 1)
        self.assertEqual(loaded.export_history[0]["format"], "markdown")
        self.assertEqual(loaded.export_history[0]["output_path"], output_path)

    def test_list_snapshots_includes_sealed_and_fork(self):
        r = self._make_record()
        self.snap_store.create("base-snap", r)
        self.snap_store.seal("base-snap", actor="admin")
        self.snap_store.fork_from("base-snap", "forked-snap")

        items = self.snap_store.list_snapshots()
        by_name = {s["name"]: s for s in items}
        self.assertTrue(by_name["base-snap"]["sealed"])
        self.assertEqual(by_name["forked-snap"]["forked_from"], "base-snap")
        self.assertFalse(by_name["forked-snap"]["sealed"])

    def test_failed_record_without_tx_or_summary_in_export(self):
        r = SnapshotRecord(
            command="fail-cmd",
            timestamp=datetime.now().isoformat(),
            success=False,
            output_summary="  ",
            transaction_id=None,
        )
        self.snap_store.create("fail-snap", r)
        self.snap_store.seal("fail-snap", actor="admin")

        md = self.snap_store.export_markdown("fail-snap", self.waiver_store)
        self.assertIn("失败记录校验", md)

        json_str = self.snap_store.export_json("fail-snap", self.waiver_store)
        data = json.loads(json_str)
        self.assertTrue(len(data["_failed_record_validations"]) > 0)


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.snap_dir = os.path.join(self.tmpdir, "snapshots")
        self.waiver_dir = os.path.join(self.tmpdir, "waiver")
        os.makedirs(self.waiver_dir, exist_ok=True)
        self.snap_store = SnapshotStore(snapshots_dir=self.snap_dir)
        self.waiver_store = WaiverStore(
            rules_path=os.path.join(self.waiver_dir, "rules.json"),
            log_path=os.path.join(self.waiver_dir, "log.json"),
            transactions_path=os.path.join(self.waiver_dir, "tx.json"),
        )
        self.record = SnapshotRecord(
            command="test-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="初始记录",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_logs_audit_entry(self):
        self.snap_store.create("audit-snap", self.record, actor="alice")
        audit_log = self.snap_store.get_audit_log()
        self.assertTrue(len(audit_log) >= 1)
        create_entries = [e for e in audit_log if e.action == SnapshotAction.CREATE.value]
        self.assertTrue(len(create_entries) >= 1)
        self.assertEqual(create_entries[-1].snapshot_name, "audit-snap")
        self.assertEqual(create_entries[-1].actor, "alice")

    def test_seal_logs_audit_entry(self):
        self.snap_store.create("seal-audit", self.record, actor="alice")
        self.snap_store.seal("seal-audit", actor="bob")
        audit_log = self.snap_store.get_audit_log()
        seal_entries = [e for e in audit_log if e.action == SnapshotAction.SEAL.value and e.snapshot_name == "seal-audit"]
        self.assertEqual(len(seal_entries), 1)
        self.assertEqual(seal_entries[0].actor, "bob")

    def test_append_logs_audit_entry(self):
        self.snap_store.create("append-audit", self.record, actor="alice")
        r2 = SnapshotRecord(
            command="second-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="第二条",
        )
        self.snap_store.append("append-audit", r2, actor="charlie")
        audit_log = self.snap_store.get_audit_log()
        append_entries = [e for e in audit_log if e.action == SnapshotAction.APPEND.value and e.snapshot_name == "append-audit"]
        self.assertEqual(len(append_entries), 1)
        self.assertEqual(append_entries[0].actor, "charlie")

    def test_fork_logs_audit_entry(self):
        self.snap_store.create("source-audit", self.record, actor="alice")
        self.snap_store.seal("source-audit", actor="alice")
        r2 = SnapshotRecord(
            command="fork-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="分叉记录",
        )
        self.snap_store.fork_from("source-audit", "forked-audit", r2, actor="dave")
        audit_log = self.snap_store.get_audit_log()
        fork_entries = [e for e in audit_log if e.action == SnapshotAction.FORK.value and e.snapshot_name == "forked-audit"]
        self.assertEqual(len(fork_entries), 1)
        self.assertEqual(fork_entries[0].actor, "dave")
        self.assertEqual(fork_entries[0].detail.get("forked_from"), "source-audit")
        self.assertIn("inherited_record_count", fork_entries[0].detail)

    def test_export_logs_audit_entry(self):
        self.snap_store.create("export-audit", self.record, actor="alice")
        self.snap_store.seal("export-audit", actor="alice")
        output_path = os.path.join(self.tmpdir, "export.md")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.snap_store.export_markdown("export-audit", self.waiver_store))
        self.snap_store.record_export("export-audit", "markdown", output_path, actor="eve")
        audit_log = self.snap_store.get_audit_log()
        export_entries = [e for e in audit_log if e.action == SnapshotAction.EXPORT.value and e.snapshot_name == "export-audit"]
        self.assertEqual(len(export_entries), 1)
        self.assertEqual(export_entries[0].actor, "eve")

    def test_audit_log_persists_across_restart(self):
        self.snap_store.create("persist-audit", self.record, actor="alice")
        self.snap_store.seal("persist-audit", actor="bob")
        output_path = os.path.join(self.tmpdir, "persist.md")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(self.snap_store.export_markdown("persist-audit", self.waiver_store))
        self.snap_store.record_export("persist-audit", "markdown", output_path, actor="charlie")

        fresh_store = SnapshotStore(snapshots_dir=self.snap_dir)
        audit_log = fresh_store.get_audit_log()
        self.assertTrue(len(audit_log) >= 3)
        actions = [e.action for e in audit_log if e.snapshot_name == "persist-audit"]
        self.assertIn(SnapshotAction.CREATE.value, actions)
        self.assertIn(SnapshotAction.SEAL.value, actions)
        self.assertIn(SnapshotAction.EXPORT.value, actions)

    def test_audit_log_limit(self):
        for i in range(10):
            self.snap_store.create(f"snap-{i}", self.record, actor="user")
        full_log = self.snap_store.get_audit_log()
        self.assertTrue(len(full_log) >= 10)
        limited_log = self.snap_store.get_audit_log(limit=5)
        self.assertEqual(len(limited_log), 5)


class TestSnapshotStatusDetail(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.snap_store = SnapshotStore(snapshots_dir=self.tmpdir)
        self.record = SnapshotRecord(
            command="test-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="测试记录",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_draft_status_detail(self):
        self.snap_store.create("draft-snap", self.record, actor="alice")
        detail = self.snap_store.get_snapshot_status_detail("draft-snap")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], SnapshotStatus.DRAFT.value)
        self.assertIn("草稿", detail["status_label"])
        self.assertIn("未封版", detail["status_label"])
        self.assertIn("仍可追加", detail["status_label"])
        self.assertEqual(detail["record_count"], 1)
        self.assertFalse(detail["sealed"])
        self.assertIsNotNone(detail["stuck_at"])
        self.assertTrue(len(detail["next_steps"]) > 0)

    def test_sealed_status_detail(self):
        self.snap_store.create("sealed-detail", self.record, actor="alice")
        self.snap_store.seal("sealed-detail", actor="bob")
        detail = self.snap_store.get_snapshot_status_detail("sealed-detail")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], SnapshotStatus.SEALED.value)
        self.assertIn("已封版", detail["status_label"])
        self.assertTrue(detail["sealed"])
        self.assertIsNotNone(detail["sealed_at"])

    def test_forked_status_detail(self):
        self.snap_store.create("source-detail", self.record, actor="alice")
        self.snap_store.seal("source-detail", actor="alice")
        self.snap_store.fork_from("source-detail", "forked-detail", actor="bob")
        detail = self.snap_store.get_snapshot_status_detail("forked-detail")
        self.assertIsNotNone(detail)
        self.assertEqual(detail["status"], SnapshotStatus.FORKED.value)
        self.assertIn("已分叉", detail["status_label"])
        self.assertEqual(detail["forked_from"], "source-detail")

    def test_nonexistent_snapshot_returns_none(self):
        detail = self.snap_store.get_snapshot_status_detail("no-such-snap")
        self.assertIsNone(detail)

    def test_next_steps_contains_append_and_fork(self):
        self.snap_store.create("steps-snap", self.record)
        detail = self.snap_store.get_snapshot_status_detail("steps-snap")
        steps_text = " ".join(detail["next_steps"])
        self.assertIn("--append", steps_text)
        self.assertIn("--fork-from", steps_text)

    def test_sealed_next_steps_contains_export(self):
        self.snap_store.create("sealed-steps", self.record)
        self.snap_store.seal("sealed-steps", actor="admin")
        detail = self.snap_store.get_snapshot_status_detail("sealed-steps")
        steps_text = " ".join(detail["next_steps"])
        self.assertIn("--append", steps_text)
        self.assertIn("--fork-from", steps_text)
        self.assertIn("export", steps_text)


class TestNoAutoCreation(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.snap_store = SnapshotStore(snapshots_dir=self.tmpdir)
        self.record = SnapshotRecord(
            command="test-cmd",
            timestamp=datetime.now().isoformat(),
            success=True,
            output_summary="测试记录",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_append_to_nonexistent_raises(self):
        with self.assertRaises((SnapshotNameConflictError, FileNotFoundError, ValueError)):
            self.snap_store.append("no-such-snap", self.record)

    def test_seal_nonexistent_raises(self):
        with self.assertRaises((SnapshotNameConflictError, FileNotFoundError, ValueError)):
            self.snap_store.seal("no-such-snap")

    def test_fork_from_nonexistent_source_raises(self):
        with self.assertRaises((SnapshotNameConflictError, FileNotFoundError, ValueError)):
            self.snap_store.fork_from("no-such-source", "new-snap")

    def test_load_nonexistent_returns_none(self):
        result = self.snap_store.load("no-such-snap")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
