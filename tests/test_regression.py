from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path


CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backup_audit_cli.py")
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )


def make_temp_backup(tmp_dir: str, files: list, batch_id: str = "TEST-001",
                     valid_bl: list = None, revocation: list = None,
                     window_hours: int = 2) -> str:
    data_dir = os.path.join(tmp_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    now = datetime.now()

    manifest_files = []
    for fdef in files:
        name = fdef["name"]
        content = fdef.get("content", b"test")
        fpath = os.path.join(data_dir, name)
        with open(fpath, "wb") as f:
            f.write(content)
        ts = (now - timedelta(minutes=fdef.get("age_minutes", 30))).timestamp()
        os.utime(fpath, (ts, ts))
        manifest_files.append({
            "path": f"data/{name}",
            "sha256": fdef.get("sha256", hashlib.sha256(content).hexdigest()),
            "size": fdef.get("size", len(content)),
            "business_line": fdef.get("business_line", "order_system"),
        })

    manifest = {
        "batch_id": batch_id,
        "backup_window": {
            "start": (now - timedelta(hours=window_hours)).isoformat(),
            "end": now.isoformat(),
        },
        "valid_business_lines": valid_bl or ["order_system"],
        "files": manifest_files,
        "revocation_list": revocation if revocation is not None else [],
    }
    manifest_path = os.path.join(tmp_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return tmp_dir


class TestBadSha256Rejection(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_badsha_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_short_hash_rejected(self):
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": b"hello", "sha256": "abc123"},
        ])
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertNotEqual(r.returncode, 0, "import should fail for short sha256")
        self.assertIn("sha256 必须为 64 位十六进制", r.stderr)
        self.assertIn("files[0].sha256", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, ".audit_state")))

    def test_non_hex_rejected(self):
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": b"hello",
             "sha256": "z" * 64},
        ])
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sha256 必须为 64 位十六进制", r.stderr)

    def test_empty_hash_rejected(self):
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": b"hello", "sha256": ""},
        ])
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sha256 必须为 64 位十六进制", r.stderr)

    def test_multiple_bad_fields_reported(self):
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": b"hello", "sha256": "short"},
            {"name": "b.dat", "content": b"world", "sha256": "also_bad"},
        ])
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("files[0].sha256", r.stderr)
        self.assertIn("files[1].sha256", r.stderr)
        self.assertIn("2 个格式错误", r.stderr)

    def test_no_batch_created_on_bad_manifest(self):
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": b"hello", "sha256": "bad"},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir, ".audit_state")))

    def test_valid_hash_accepted(self):
        content = b"good content"
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": content, "sha256": hashlib.sha256(content).hexdigest()},
        ])
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertEqual(r.returncode, 0, f"valid import should succeed: {r.stderr}")
        self.assertIn("批次已导入", r.stdout)


class TestReviewUndo(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_undo_")
        content = b"test file for undo"
        wrong_hash = hashlib.sha256(b"wrong content").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": content},
            {"name": "b.dat", "content": b"another"},
            {"name": "c.dat", "content": b"bad hash file", "sha256": wrong_hash},
            {"name": "d.dat", "content": b"wrong size", "size": 9999},
        ])
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        r = run_cli("precheck", self.tmp_dir)
        self.assertEqual(r.returncode, 0)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _get_first_confirmable_issue_id(self) -> str:
        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                for issue in data.get("issues", []):
                    if issue.get("severity") == "confirmable":
                        return issue["id"]
        raise ValueError("no confirmable issue found")

    def _get_all_issue_ids(self) -> list:
        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                return [i["id"] for i in data.get("issues", [])]
        return []

    def test_review_then_undo_restores_state(self):
        issue_id = self._get_first_confirmable_issue_id()
        self.assertIsNotNone(issue_id, "could not find a confirmable issue")

        r = run_cli("review", self.tmp_dir, issue_id,
                     "--status", "confirmed", "--assignee", "tester", "--notes", "test note")
        self.assertEqual(r.returncode, 0)
        self.assertIn("confirmed", r.stdout)

        r = run_cli("undo", self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("open", r.stdout)
        self.assertIn("剩余可撤销次数: 0", r.stdout)

        r = run_cli("list", self.tmp_dir, "--status", "open")
        self.assertIn(issue_id, r.stdout)

    def test_empty_undo_gives_message(self):
        r = run_cli("undo", self.tmp_dir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("撤销历史为空", r.stderr)

    def test_undo_after_two_reviews(self):
        issue_ids = self._get_all_issue_ids()
        self.assertGreaterEqual(len(issue_ids), 2, "need at least 2 issues for this test")

        id1, id2 = issue_ids[0], issue_ids[1]

        run_cli("review", self.tmp_dir, id1, "--status", "ignored", "--assignee", "a1")
        run_cli("review", self.tmp_dir, id2, "--status", "confirmed", "--assignee", "a2")

        r = run_cli("undo", self.tmp_dir)
        self.assertIn(id2, r.stdout)

        r = run_cli("undo", self.tmp_dir)
        self.assertIn(id1, r.stdout)

        r = run_cli("undo", self.tmp_dir)
        self.assertIn("撤销历史为空", r.stderr)


class TestCrossProcessExport(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_cross_")
        content = b"cross process test"
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": content},
            {"name": "b.dat", "content": b"bad hash", "sha256": wrong_hash},
        ], revocation=["cert-old"])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _get_first_issue_id(self) -> str:
        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                issues = data.get("issues", [])
                if issues:
                    return issues[0]["id"]
        raise ValueError("no issues found in batch state")

    def test_export_json_csv_consistent_with_review(self):
        issue_id = self._get_first_issue_id()
        self.assertIsNotNone(issue_id)

        run_cli("review", self.tmp_dir, issue_id,
                "--status", "pending_fix", "--assignee", "ops1", "--notes", "need fix")

        reports_dir = os.path.join(self.tmp_dir, "reports")
        r = run_cli("export", self.tmp_dir, "--output", reports_dir)
        self.assertEqual(r.returncode, 0)

        json_path = os.path.join(reports_dir, f"audit_report_TEST-001.json")
        csv_path = os.path.join(reports_dir, f"audit_report_TEST-001.csv")
        self.assertTrue(os.path.exists(json_path), "JSON report should exist")
        self.assertTrue(os.path.exists(csv_path), "CSV report should exist")

        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        found = None
        for issue in report["all_issues"]:
            if issue["id"] == issue_id:
                found = issue
                break
        self.assertIsNotNone(found, f"issue {issue_id} not found in report")
        self.assertEqual(found["status"], "pending_fix")
        self.assertEqual(found["assignee"], "ops1")
        self.assertEqual(found["notes"], "need fix")

        with open(csv_path, "r", encoding="utf-8-sig") as f:
            csv_content = f.read()
        self.assertIn("pending_fix", csv_content)
        self.assertIn("ops1", csv_content)
        self.assertIn("need fix", csv_content)

    def test_resume_after_new_process(self):
        r = run_cli("resume", self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("TEST-001", r.stdout)


class TestSignoffBlocking(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_block_")
        content = b"test for block"
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "good.dat", "content": content},
            {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
            {"name": "missing.dat", "content": b"not there", "size": 9999},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_block_signoff_with_unresolved_blocking(self):
        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "admin", "--reason", "all good")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("未处理的阻断问题", r.stderr)
        self.assertIn("不能签收", r.stderr)

    def test_force_without_reason_rejected(self):
        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "admin", "--force-with-reason")
        self.assertNotEqual(r.returncode, 0)

    def test_reason_required_even_for_clean_batch(self):
        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "admin")
        self.assertNotEqual(r.returncode, 0)


class TestForcedSignoff(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_force_")
        content = b"test for force"
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "good.dat", "content": content},
            {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_forced_signoff_with_reason(self):
        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "manager",
                     "--reason", "经评估风险可控，特批放行",
                     "--force-with-reason")
        self.assertEqual(r.returncode, 0, f"force signoff should succeed: {r.stderr}")
        self.assertIn("批次已签收", r.stdout)
        self.assertIn("强制放行", r.stdout)
        self.assertIn("manager", r.stdout)
        self.assertIn("经评估风险可控", r.stdout)

    def test_batch_readonly_after_signoff(self):
        run_cli("finalize", self.tmp_dir,
                "--signer", "manager",
                "--reason", "risk accepted",
                "--force-with-reason")

        r = run_cli("precheck", self.tmp_dir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("禁止执行 precheck 操作", r.stderr)

    def test_duplicate_finalize_blocked(self):
        run_cli("finalize", self.tmp_dir,
                "--signer", "manager",
                "--reason", "risk accepted",
                "--force-with-reason")

        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "other", "--reason", "again")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("不能重复签收", r.stderr)

    def test_review_blocked_after_signoff(self):
        run_cli("finalize", self.tmp_dir,
                "--signer", "manager",
                "--reason", "risk accepted",
                "--force-with-reason")

        issue_id = self._get_first_issue_id()
        r = run_cli("review", self.tmp_dir, issue_id,
                     "--status", "confirmed")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("禁止执行 review 操作", r.stderr)

    def test_undo_blocked_after_signoff(self):
        run_cli("finalize", self.tmp_dir,
                "--signer", "manager",
                "--reason", "risk accepted",
                "--force-with-reason")

        r = run_cli("undo", self.tmp_dir)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("禁止执行 undo 操作", r.stderr)

    def _get_first_issue_id(self) -> str:
        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                issues = data.get("issues", [])
                if issues:
                    return issues[0]["id"]
        raise ValueError("no issues found")


class TestReopenWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_reopen_")
        content = b"test for reopen"
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "good.dat", "content": content},
            {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)
        run_cli("finalize", self.tmp_dir,
                "--signer", "manager",
                "--reason", "initial signoff",
                "--force-with-reason")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_reopen_requires_reason_and_reopener(self):
        r = run_cli("reopen", self.tmp_dir,
                     "--reopener", "admin")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--reason", r.stderr)

        r = run_cli("reopen", self.tmp_dir,
                     "--reason", "need to fix")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--reopener", r.stderr)

    def test_reopen_restores_editing(self):
        r = run_cli("reopen", self.tmp_dir,
                     "--reopener", "admin",
                     "--reason", "发现漏处理的问题，需要补充复核")
        self.assertEqual(r.returncode, 0, f"reopen should succeed: {r.stderr}")
        self.assertIn("批次已重开", r.stdout)
        self.assertIn("admin", r.stdout)
        self.assertIn("发现漏处理的问题", r.stdout)

        issue_id = self._get_first_issue_id()
        r = run_cli("review", self.tmp_dir, issue_id,
                     "--status", "confirmed",
                     "--assignee", "tester")
        self.assertEqual(r.returncode, 0)

        r = run_cli("undo", self.tmp_dir)
        self.assertEqual(r.returncode, 0)

    def test_reopen_on_open_batch_rejected(self):
        run_cli("reopen", self.tmp_dir,
                "--reopener", "admin", "--reason", "fix")

        r = run_cli("reopen", self.tmp_dir,
                     "--reopener", "admin", "--reason", "again")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("批次未签收，无需重开", r.stderr)

    def test_reopen_record_persisted(self):
        run_cli("reopen", self.tmp_dir,
                "--reopener", "admin",
                "--reason", "fix issues")

        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                self.assertEqual(len(data["reopen_records"]), 1)
                self.assertEqual(data["reopen_records"][0]["reopener"], "admin")
                self.assertEqual(data["reopen_records"][0]["reason"], "fix issues")
                self.assertIn("previous_signoff", data["reopen_records"][0])
                self.assertEqual(data["reopen_records"][0]["previous_signoff"]["signer"], "manager")
                return
        self.fail("batch file not found")

    def test_resignoff_after_reopen(self):
        run_cli("reopen", self.tmp_dir,
                "--reopener", "admin", "--reason", "fix")

        issue_id = self._get_first_issue_id()
        run_cli("review", self.tmp_dir, issue_id,
                "--status", "confirmed", "--assignee", "fixer")

        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "manager2",
                     "--reason", "重新复核完成，所有问题已确认",
                     "--force-with-reason")
        self.assertEqual(r.returncode, 0)
        self.assertIn("manager2", r.stdout)

    def _get_first_issue_id(self) -> str:
        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                issues = data.get("issues", [])
                if issues:
                    return issues[0]["id"]
        raise ValueError("no issues found")


class TestCleanSignoff(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_clean_")
        content = b"all good"
        make_temp_backup(self.tmp_dir, [
            {"name": "good1.dat", "content": content},
            {"name": "good2.dat", "content": b"also good"},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_clean_signoff_without_force(self):
        r = run_cli("finalize", self.tmp_dir,
                     "--signer", "qa_lead",
                     "--reason", "所有校验通过，无阻断问题")
        self.assertEqual(r.returncode, 0)
        self.assertIn("批次已签收", r.stdout)
        self.assertIn("正常签收", r.stdout)
        self.assertIn("qa_lead", r.stdout)
        self.assertNotIn("强制放行", r.stdout)


class TestCrossProcessSignoff(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_cross_sign_")
        content = b"cross process signoff test"
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "a.dat", "content": content},
            {"name": "b.dat", "content": b"bad hash", "sha256": wrong_hash},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)
        run_cli("finalize", self.tmp_dir,
                "--signer", "signer1",
                "--reason", "risk accepted for cross test",
                "--force-with-reason")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_resume_shows_signoff_status(self):
        r = run_cli("resume", self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("finalized", r.stdout)
        self.assertIn("signer1", r.stdout)
        self.assertIn("强制放行", r.stdout)

    def test_list_shows_signoff_status(self):
        r = run_cli("list", self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("finalized", r.stdout)
        self.assertIn("signer1", r.stdout)

    def test_export_includes_signoff_and_log(self):
        reports_dir = os.path.join(self.tmp_dir, "reports")
        r = run_cli("export", self.tmp_dir, "--output", reports_dir)
        self.assertEqual(r.returncode, 0)

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertEqual(report["status"], "finalized")
        self.assertIsNotNone(report["signoff"])
        self.assertEqual(report["signoff"]["signer"], "signer1")
        self.assertEqual(report["signoff"]["reason"], "risk accepted for cross test")
        self.assertTrue(report["signoff"]["forced"])
        self.assertGreater(report["signoff"]["unresolved_blocking_count"], 0)

        self.assertIsInstance(report["operation_log"], list)
        self.assertGreater(len(report["operation_log"]), 0)
        actions = [l["action"] for l in report["operation_log"]]
        self.assertIn("finalize", actions)
        self.assertIn("precheck", actions)
        self.assertIn("export", actions)

        csv_path = os.path.join(reports_dir, "audit_report_TEST-001.csv")
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            csv_content = f.read()
        self.assertIn("signer1", csv_content)
        self.assertIn("risk accepted for cross test", csv_content)
        self.assertIn("强制放行", csv_content)
        self.assertIn("操作日志", csv_content)

    def test_reopen_then_resume_shows_history(self):
        run_cli("reopen", self.tmp_dir,
                "--reopener", "ops",
                "--reason", "cross test reopen")

        r = run_cli("resume", self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("open", r.stdout)
        self.assertIn("重开次数: 1", r.stdout)

        reports_dir = os.path.join(self.tmp_dir, "reports2")
        run_cli("export", self.tmp_dir, "--output", reports_dir)

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertEqual(len(report["reopen_records"]), 1)
        self.assertEqual(report["reopen_records"][0]["reopener"], "ops")
        self.assertEqual(report["reopen_records"][0]["previous_signoff"]["signer"], "signer1")


class TestListSeverityFilter(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_test_list_filter_")
        content = b"test for filter"
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        make_temp_backup(self.tmp_dir, [
            {"name": "good.dat", "content": content},
            {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
            {"name": "old.dat", "content": b"old", "age_minutes": 60 * 24 * 30},
        ])
        run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir)
        run_cli("precheck", self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_list_severity_blocking_shows_details(self):
        r = run_cli("list", self.tmp_dir, "--severity", "blocking")
        self.assertEqual(r.returncode, 0, f"list should succeed: {r.stderr}")
        self.assertIn("阻断问题 (BLOCKING)", r.stdout)
        self.assertIn("bad_checksum", r.stdout)
        self.assertIn("bad.dat", r.stdout)
        self.assertNotIn("outside_backup_window", r.stdout)
        self.assertNotIn("可确认问题 (CONFIRMABLE)", r.stdout)

    def test_list_severity_confirmable_shows_details(self):
        r = run_cli("list", self.tmp_dir, "--severity", "confirmable")
        self.assertEqual(r.returncode, 0, f"list should succeed: {r.stderr}")
        self.assertIn("可确认问题 (CONFIRMABLE)", r.stdout)
        self.assertIn("outside_backup_window", r.stdout)
        self.assertIn("old.dat", r.stdout)
        self.assertNotIn("bad_checksum", r.stdout)
        self.assertNotIn("阻断问题 (BLOCKING)", r.stdout)

    def test_list_no_severity_shows_all(self):
        r = run_cli("list", self.tmp_dir)
        self.assertEqual(r.returncode, 0)
        self.assertIn("阻断问题 (BLOCKING)", r.stdout)
        self.assertIn("可确认问题 (CONFIRMABLE)", r.stdout)
        self.assertIn("bad_checksum", r.stdout)
        self.assertIn("outside_backup_window", r.stdout)

    def test_list_severity_blocking_with_status_filter(self):
        r = run_cli("list", self.tmp_dir, "--severity", "blocking", "--status", "open")
        self.assertEqual(r.returncode, 0)
        self.assertIn("阻断问题 (BLOCKING)", r.stdout)
        self.assertIn("bad.dat", r.stdout)

    def test_list_severity_confirmable_with_status_filter(self):
        r = run_cli("list", self.tmp_dir, "--severity", "confirmable", "--status", "open")
        self.assertEqual(r.returncode, 0)
        self.assertIn("可确认问题 (CONFIRMABLE)", r.stdout)
        self.assertIn("old.dat", r.stdout)

    def test_list_severity_help_shows_correct_options(self):
        r = run_cli("list", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--severity", r.stdout)
        self.assertIn("blocking", r.stdout)
        self.assertIn("confirmable", r.stdout)


if __name__ == "__main__":
    unittest.main()
