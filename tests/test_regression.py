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


if __name__ == "__main__":
    unittest.main()
