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


def run_cli(*args: str, env_overrides: dict = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        [sys.executable, CLI, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=PROJECT_ROOT,
        env=env,
    )


def make_temp_backup(tmp_dir: str, files: list, batch_id: str = "TEST-001",
                     valid_bl: list = None, revocation: list = None,
                     window_hours: int = 2, tz: str = None) -> str:
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

    if tz:
        now_str = now.isoformat()
        start_str = (now - timedelta(hours=window_hours)).isoformat()
    else:
        now_str = now.isoformat()
        start_str = (now - timedelta(hours=window_hours)).isoformat()

    manifest = {
        "batch_id": batch_id,
        "backup_window": {
            "start": start_str,
            "end": now_str,
        },
        "valid_business_lines": valid_bl or ["order_system"],
        "files": manifest_files,
        "revocation_list": revocation if revocation is not None else [],
    }
    manifest_path = os.path.join(tmp_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return tmp_dir


def make_isolated_config(tmp_dir: str) -> dict:
    config_dir = os.path.join(tmp_dir, ".backup_audit_config")
    os.makedirs(config_dir, exist_ok=True)
    return {
        "BACKUP_AUDIT_CONFIG_DIR": config_dir,
        "BACKUP_AUDIT_DATA_DIR": os.path.join(tmp_dir, ".backup_audit_data"),
        "BACKUP_AUDIT_WAIVER_RULES": os.path.join(config_dir, "waiver_rules.json"),
        "BACKUP_AUDIT_WAIVER_LOG": os.path.join(config_dir, "waiver_audit_log.json"),
        "BACKUP_AUDIT_WAIVER_TRANSACTIONS": os.path.join(config_dir, "waiver_transactions.json"),
        "BACKUP_AUDIT_WINDOW_PROFILES": os.path.join(config_dir, "window_profiles.json"),
        "BACKUP_AUDIT_WINDOW_PROFILE_LOG": os.path.join(config_dir, "window_profile_log.json"),
        "BACKUP_AUDIT_WINDOW_PROFILE_APPLICATIONS": os.path.join(config_dir, "window_profile_applications.json"),
        "BACKUP_AUDIT_WINDOW_PROFILE_SNAPSHOTS": os.path.join(config_dir, "window_profile_snapshots"),
    }


class TestWindowProfileCreateValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_create_")
        self.env = make_isolated_config(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_create_profile_success(self):
        now = datetime.now()
        start = (now - timedelta(hours=2)).isoformat()
        end = now.isoformat()
        r = run_cli(
            "window", "create", "daily_backup",
            "--window-start", start,
            "--window-end", end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--business-line", "payment_system",
            "--notes", "日常备份窗口",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"create should succeed: {r.stderr}")
        self.assertIn("窗口模板已创建", r.stdout)
        self.assertIn("daily_backup", r.stdout)
        self.assertIn("+08:00", r.stdout)
        self.assertIn("order_system", r.stdout)
        self.assertIn("payment_system", r.stdout)
        self.assertIn("日常备份窗口", r.stdout)

    def test_timezone_validation_utc(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "utc_test",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "UTC",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"UTC timezone should be valid: {r.stderr}")
        self.assertIn("UTC", r.stdout)

    def test_timezone_validation_z(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "z_test",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "Z",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"Z timezone should be valid: {r.stderr}")

    def test_timezone_validation_invalid(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "bad_tz",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "invalid",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "invalid timezone should fail")
        self.assertIn("时区格式无效", r.stderr)
        self.assertIn("invalid", r.stderr)

    def test_timezone_validation_invalid_format(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "bad_tz2",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "08:00",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "timezone without sign should fail")
        self.assertIn("时区格式无效", r.stderr)

    def test_empty_business_lines_rejected(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "no_bl",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "+08:00",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "missing business-line should fail")

    def test_window_start_after_end_rejected(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "bad_window",
            "--window-start", now.isoformat(),
            "--window-end", (now - timedelta(hours=2)).isoformat(),
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "start after end should fail")
        self.assertIn("窗口起始时间必须早于结束时间", r.stderr)

    def test_actor_required(self):
        now = datetime.now()
        r = run_cli(
            "window", "create", "no_actor",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "+08:00",
            "--business-line", "order_system",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "missing actor should fail")


class TestWindowProfileNameConflict(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_conflict_")
        self.env = make_isolated_config(self.tmp_dir)
        now = datetime.now()
        self.start = (now - timedelta(hours=2)).isoformat()
        self.end = now.isoformat()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_duplicate_name_rejected(self):
        r1 = run_cli(
            "window", "create", "daily_backup",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertEqual(r1.returncode, 0, "first create should succeed")

        r2 = run_cli(
            "window", "create", "daily_backup",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "payment_system",
            "--actor", "other",
            env_overrides=self.env,
        )
        self.assertNotEqual(r2.returncode, 0, "duplicate name should fail")
        self.assertIn("模板名称已存在", r2.stderr)
        self.assertIn("daily_backup", r2.stderr)

    def test_list_profiles(self):
        for name in ["profile1", "profile2", "profile3"]:
            r = run_cli(
                "window", "create", name,
                "--window-start", self.start,
                "--window-end", self.end,
                "--timezone", "+08:00",
                "--business-line", "order_system",
                "--actor", "admin",
                env_overrides=self.env,
            )
            self.assertEqual(r.returncode, 0)

        r = run_cli("window", "list", env_overrides=self.env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("profile1", r.stdout)
        self.assertIn("profile2", r.stdout)
        self.assertIn("profile3", r.stdout)
        self.assertIn("3 个", r.stdout)


class TestWindowProfileApply(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_apply_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=2)).isoformat()
        self.window_end = now.isoformat()

        r = run_cli(
            "window", "create", "test_profile",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--business-line", "payment_system",
            "--notes", "测试窗口模板",
            "--actor", "admin",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "good.dat", "content": b"good content"},
                {"name": "old.dat", "content": b"old", "age_minutes": 60 * 24 * 30},
            ],
            valid_bl=["order_system", "payment_system"],
        )

        r = run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_apply_profile_to_batch(self):
        r = run_cli(
            "window", "apply", "test_profile",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"apply should succeed: {r.stderr}")
        self.assertIn("模板已应用到批次", r.stdout)
        self.assertIn("test_profile", r.stdout)
        self.assertIn("+08:00", r.stdout)
        self.assertIn("order_system", r.stdout)
        self.assertIn("payment_system", r.stdout)

    def test_apply_nonexistent_profile_fails(self):
        r = run_cli(
            "window", "apply", "nonexistent",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("模板不存在或已删除", r.stderr)

    def test_duplicate_apply_fails(self):
        r1 = run_cli(
            "window", "apply", "test_profile",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertEqual(r1.returncode, 0)

        r2 = run_cli(
            "window", "apply", "test_profile",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r2.returncode, 0, "duplicate apply should fail")
        self.assertIn("同一批次不能重复套用同一模板", r2.stderr)

    def test_apply_updates_manifest_window(self):
        run_cli(
            "window", "apply", "test_profile",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )

        state_dir = os.path.join(self.backup_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    batch_data = json.load(fp)
                self.assertEqual(
                    batch_data["manifest"]["backup_window"]["start"],
                    self.window_start,
                )
                self.assertEqual(
                    batch_data["manifest"]["backup_window"]["end"],
                    self.window_end,
                )
                self.assertEqual(
                    batch_data["manifest"]["valid_business_lines"],
                    ["order_system", "payment_system"],
                )
                self.assertIsNotNone(batch_data["window_profile_snapshot"])
                self.assertEqual(
                    batch_data["window_profile_snapshot"]["profile_name"],
                    "test_profile",
                )
                return
        self.fail("batch file not found")


class TestWindowProfileTimezonePrecheck(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_tz_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=4)).isoformat()
        self.window_end = (now - timedelta(hours=1)).isoformat()

        run_cli(
            "window", "create", "tz_profile",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "+00:00",
            "--business-line", "order_system",
            "--notes", "UTC 时区窗口",
            "--actor", "admin",
            env_overrides=self.env,
        )

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "in_window.dat", "content": b"in window", "age_minutes": 120},
                {"name": "out_window.dat", "content": b"out window", "age_minutes": 60 * 24},
            ],
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_precheck_with_timezone_window(self):
        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            "--window-profile", "tz_profile",
            "--actor", "admin",
            env_overrides=self.env,
        )

        r = run_cli(
            "precheck", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"precheck should succeed: {r.stderr}")

        r = run_cli(
            "list", self.backup_dir, "--severity", "confirmable",
            env_overrides=self.env,
        )
        self.assertIn("outside_backup_window", r.stdout)
        self.assertIn("out_window.dat", r.stdout)
        self.assertIn("(+00:00)", r.stdout)


class TestWindowProfileCrossProcess(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_cross_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=2)).isoformat()
        self.window_end = now.isoformat()

        run_cli(
            "window", "create", "cross_profile",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "-05:00",
            "--business-line", "order_system",
            "--notes", "跨进程测试模板",
            "--actor", "admin",
            env_overrides=self.env,
        )

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "file1.dat", "content": b"content1"},
                {"name": "file2.dat", "content": b"content2"},
            ],
        )

        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            "--window-profile", "cross_profile",
            "--actor", "ops",
            env_overrides=self.env,
        )

        run_cli(
            "precheck", self.backup_dir,
            env_overrides=self.env,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_resume_shows_template_info(self):
        r = run_cli(
            "resume", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("窗口模板", r.stdout)
        self.assertIn("cross_profile", r.stdout)
        self.assertIn("-05:00", r.stdout)
        self.assertIn("跨进程测试模板", r.stdout)
        self.assertIn("ops", r.stdout)

    def test_list_shows_template_info(self):
        r = run_cli(
            "list", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("窗口模板", r.stdout)
        self.assertIn("cross_profile", r.stdout)

    def test_export_includes_template_info(self):
        reports_dir = os.path.join(self.tmp_dir, "reports")
        run_cli(
            "export", self.backup_dir,
            "--output", reports_dir,
            env_overrides=self.env,
        )

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertIsNotNone(report.get("window_profile"))
        self.assertEqual(report["window_profile"]["profile_name"], "cross_profile")
        self.assertEqual(report["window_profile"]["timezone"], "-05:00")
        self.assertEqual(report["window_profile"]["notes"], "跨进程测试模板")
        self.assertEqual(report["window_profile"]["applied_by"], "ops")


class TestWindowProfileImportExport(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_ie_")
        self.env1 = make_isolated_config(os.path.join(self.tmp_dir, "config1"))
        self.env2 = make_isolated_config(os.path.join(self.tmp_dir, "config2"))

        now = datetime.now()
        self.start = (now - timedelta(hours=8)).isoformat()
        self.end = now.isoformat()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_export_import_roundtrip(self):
        profiles = [
            ("daily", "+08:00", ["order_system", "payment_system"], "日常备份"),
            ("weekly", "UTC", ["archive_system"], "周备份"),
            ("monthly", "-05:00", ["order_system", "archive_system", "hr_system"], "月归档"),
        ]

        for name, tz, bls, notes in profiles:
            args = [
                "window", "create", name,
                "--window-start", self.start,
                "--window-end", self.end,
                "--timezone", tz,
                "--actor", "admin",
                "--notes", notes,
            ]
            for bl in bls:
                args.extend(["--business-line", bl])
            r = run_cli(*args, env_overrides=self.env1)
            self.assertEqual(r.returncode, 0, f"create {name} failed: {r.stderr}")

        export_path = os.path.join(self.tmp_dir, "window_profiles.json")
        r = run_cli(
            "window", "export", export_path,
            "--actor", "admin",
            env_overrides=self.env1,
        )
        self.assertEqual(r.returncode, 0, f"export failed: {r.stderr}")
        self.assertIn("3", r.stdout)

        self.assertTrue(os.path.exists(export_path))
        with open(export_path, "r", encoding="utf-8") as f:
            exported = json.load(f)
        self.assertEqual(len(exported["profiles"]), 3)
        exported_names = {p["name"] for p in exported["profiles"]}
        self.assertEqual(exported_names, {"daily", "weekly", "monthly"})

        r = run_cli(
            "window", "import", export_path,
            "--actor", "importer",
            env_overrides=self.env2,
        )
        self.assertEqual(r.returncode, 0, f"import failed: {r.stderr}")
        self.assertIn("新增: 3", r.stdout)

        r = run_cli("window", "list", env_overrides=self.env2)
        self.assertEqual(r.returncode, 0)
        for name, tz, bls, notes in profiles:
            self.assertIn(name, r.stdout)
            self.assertIn(tz, r.stdout)

        for name, tz, bls, notes in profiles:
            r = run_cli("window", "show", name, env_overrides=self.env2)
            self.assertEqual(r.returncode, 0)
            self.assertIn(name, r.stdout)
            self.assertIn(tz, r.stdout)
            self.assertIn(notes, r.stdout)
            for bl in bls:
                self.assertIn(bl, r.stdout)

    def test_import_merge_skip_existing(self):
        run_cli(
            "window", "create", "existing",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--notes", "原始版本",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        export_path = os.path.join(self.tmp_dir, "single_profile.json")
        run_cli(
            "window", "export", export_path,
            "--name", "existing",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        run_cli(
            "window", "create", "existing",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+09:00",
            "--business-line", "other_system",
            "--notes", "目标版本",
            "--actor", "admin",
            env_overrides=self.env2,
        )

        r = run_cli(
            "window", "import", export_path,
            "--mode", "merge",
            "--actor", "importer",
            env_overrides=self.env2,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("跳过", r.stdout)
        self.assertIn("已存在，merge 模式不覆盖", r.stdout)

        r = run_cli("window", "show", "existing", env_overrides=self.env2)
        self.assertIn("+09:00", r.stdout)
        self.assertIn("目标版本", r.stdout)
        self.assertIn("other_system", r.stdout)

    def test_import_replace_force_update(self):
        run_cli(
            "window", "create", "to_replace",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--notes", "原始版本",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        export_path = os.path.join(self.tmp_dir, "replace_profile.json")
        run_cli(
            "window", "export", export_path,
            "--name", "to_replace",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        run_cli(
            "window", "create", "to_replace",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+09:00",
            "--business-line", "other_system",
            "--notes", "目标版本",
            "--actor", "admin",
            env_overrides=self.env2,
        )

        r = run_cli(
            "window", "import", export_path,
            "--mode", "replace",
            "--force",
            "--actor", "importer",
            env_overrides=self.env2,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("更新", r.stdout)

        r = run_cli("window", "show", "to_replace", env_overrides=self.env2)
        self.assertIn("+08:00", r.stdout)
        self.assertIn("原始版本", r.stdout)
        self.assertIn("order_system", r.stdout)


class TestWindowProfileSnapshotImmutability(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_snap_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.orig_start = (now - timedelta(hours=2)).isoformat()
        self.orig_end = now.isoformat()

        run_cli(
            "window", "create", "mutable",
            "--window-start", self.orig_start,
            "--window-end", self.orig_end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--notes", "原始备注",
            "--actor", "admin",
            env_overrides=self.env,
        )

        make_temp_backup(
            self.backup_dir,
            [{"name": "test.dat", "content": b"content"}],
        )

        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            "--window-profile", "mutable",
            "--actor", "ops",
            env_overrides=self.env,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_profile_update_preserves_old_batch_snapshot(self):
        r = run_cli(
            "window", "show", "mutable",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("版本: 1", r.stdout)
        orig_fp = None
        for line in r.stdout.split("\n"):
            if "指纹" in line:
                orig_fp = line.split("指纹:")[1].strip()
                break
        self.assertIsNotNone(orig_fp)

        now = datetime.now()
        new_start = (now - timedelta(hours=4)).isoformat()
        new_end = now.isoformat()

        from backup_audit.window_profile import WindowProfileStore
        from backup_audit.waiver import get_global_config_dir
        import os
        os.environ.update(self.env)
        store = WindowProfileStore()
        store.update_profile(
            name="mutable",
            actor="admin",
            window_start=new_start,
            window_end=new_end,
            timezone="+09:00",
            business_lines=["order_system", "payment_system"],
            notes="已更新",
        )

        r = run_cli(
            "window", "show", "mutable",
            env_overrides=self.env,
        )
        self.assertIn("版本: 2", r.stdout)

        r = run_cli(
            "resume", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("mutable", r.stdout)
        self.assertIn("v1", r.stdout)
        self.assertIn("+08:00", r.stdout)
        self.assertIn("原始备注", r.stdout)

        reports_dir = os.path.join(self.tmp_dir, "reports")
        run_cli(
            "export", self.backup_dir,
            "--output", reports_dir,
            env_overrides=self.env,
        )

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertEqual(report["window_profile"]["profile_name"], "mutable")
        self.assertEqual(report["window_profile"]["profile_version"], 1)
        self.assertEqual(report["window_profile"]["timezone"], "+08:00")
        self.assertEqual(report["window_profile"]["notes"], "原始备注")
        self.assertEqual(report["window_profile"]["window_start"], self.orig_start)
        self.assertEqual(report["window_profile"]["window_end"], self.orig_end)
        self.assertEqual(report["window_profile"]["profile_fingerprint"], orig_fp)


class TestWindowProfileAuditLog(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_log_")
        self.env = make_isolated_config(self.tmp_dir)
        now = datetime.now()
        self.start = (now - timedelta(hours=2)).isoformat()
        self.end = now.isoformat()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_audit_log_records_operations(self):
        run_cli(
            "window", "create", "audit_test",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "creator",
            env_overrides=self.env,
        )

        r = run_cli(
            "window", "show", "audit_test",
            "--show-log",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("模板审计日志", r.stdout)
        self.assertIn("创建", r.stdout)
        self.assertIn("creator", r.stdout)


class TestWindowProfileNoEffectWithoutExplicit(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_noeff_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=2)).isoformat()
        self.window_end = now.isoformat()

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "good.dat", "content": b"good content"},
            ],
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_import_without_profile_no_window_config(self):
        r = run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli(
            "resume", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("窗口模板", r.stdout)
        self.assertNotIn("时区", r.stdout)

        state_dir = os.path.join(self.backup_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    batch_data = json.load(fp)
                self.assertIsNone(batch_data.get("window_profile_snapshot"))
                self.assertIsNone(batch_data.get("window_profile_ref"))
                return
        self.fail("batch file not found")

    def test_export_without_profile_no_window_section(self):
        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            env_overrides=self.env,
        )

        reports_dir = os.path.join(self.tmp_dir, "reports")
        run_cli(
            "export", self.backup_dir,
            "--output", reports_dir,
            env_overrides=self.env,
        )

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        self.assertTrue(os.path.exists(json_path))
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        self.assertIsNone(report.get("window_profile"))


class TestWindowProfileBusinessLineValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_blval_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=2)).isoformat()
        self.window_end = now.isoformat()

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "good.dat", "content": b"good content"},
            ],
            valid_bl=["order_system"],
        )

        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            env_overrides=self.env,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_apply_profile_with_incompatible_business_lines_fails(self):
        run_cli(
            "window", "create", "bad_bl",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "+08:00",
            "--business-line", "nonexistent_system",
            "--actor", "admin",
            env_overrides=self.env,
        )

        r = run_cli(
            "window", "apply", "bad_bl",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bad_bl", r.stderr)
        self.assertIn("business_lines", r.stderr)
        self.assertIn("nonexistent_system", r.stderr)
        self.assertIn("未在配置中声明", r.stderr)

    def test_apply_profile_with_compatible_business_lines_succeeds(self):
        run_cli(
            "window", "create", "good_bl",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )

        r = run_cli(
            "window", "apply", "good_bl",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"apply should succeed: {r.stderr}")

    def test_import_with_profile_incompatible_bl_fails(self):
        now = datetime.now()
        backup_dir2 = os.path.join(self.tmp_dir, "backup2")
        os.makedirs(backup_dir2)
        make_temp_backup(
            backup_dir2,
            [
                {"name": "file.dat", "content": b"content"},
            ],
            valid_bl=["order_system"],
        )

        run_cli(
            "window", "create", "import_bad_bl",
            "--window-start", (now - timedelta(hours=2)).isoformat(),
            "--window-end", now.isoformat(),
            "--timezone", "+08:00",
            "--business-line", "unknown_system",
            "--actor", "admin",
            env_overrides=self.env,
        )

        r = run_cli(
            "import",
            os.path.join(backup_dir2, "manifest.json"),
            backup_dir2,
            "--window-profile", "import_bad_bl",
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "incompatible BL should fail")


class TestWindowProfileImportConflictBlocking(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_conflict2_")
        self.env1 = make_isolated_config(os.path.join(self.tmp_dir, "config1"))
        self.env2 = make_isolated_config(os.path.join(self.tmp_dir, "config2"))

        now = datetime.now()
        self.start = (now - timedelta(hours=2)).isoformat()
        self.end = now.isoformat()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_replace_without_force_skips_existing(self):
        run_cli(
            "window", "create", "conflict_prof",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--notes", "源版本",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        export_path = os.path.join(self.tmp_dir, "conflict_prof.json")
        run_cli(
            "window", "export", export_path,
            "--name", "conflict_prof",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        run_cli(
            "window", "create", "conflict_prof",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+09:00",
            "--business-line", "other_system",
            "--notes", "目标版本",
            "--actor", "admin",
            env_overrides=self.env2,
        )

        r = run_cli(
            "window", "import", export_path,
            "--mode", "replace",
            "--actor", "importer",
            env_overrides=self.env2,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("已存在", r.stdout)
        self.assertIn("--force", r.stdout)

        r = run_cli("window", "show", "conflict_prof", env_overrides=self.env2)
        self.assertIn("+09:00", r.stdout)
        self.assertIn("目标版本", r.stdout)

    def test_import_invalid_profile_in_bundle_blocks_entire_import(self):
        run_cli(
            "window", "create", "valid_prof",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env1,
        )

        export_path = os.path.join(self.tmp_dir, "mixed_profiles.json")
        run_cli(
            "window", "export", export_path,
            "--actor", "admin",
            env_overrides=self.env1,
        )

        with open(export_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["profiles"].append({
            "name": "bad_tz_prof",
            "window_start": self.start,
            "window_end": self.end,
            "timezone": "INVALID_TZ",
            "business_lines": ["order_system"],
            "notes": "",
            "actor": "admin",
        })
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        r = run_cli(
            "window", "import", export_path,
            "--actor", "importer",
            env_overrides=self.env2,
        )
        self.assertNotEqual(r.returncode, 0, "bundle 中含非法时区 profile 应整体阻止导入")
        self.assertIn("bad_tz_prof", r.stderr)
        self.assertIn("timezone", r.stderr)
        self.assertIn("INVALID_TZ", r.stderr)
        self.assertIn("阻止", r.stderr)

        r_list = run_cli("window", "list", env_overrides=self.env2)
        self.assertNotIn("valid_prof", r_list.stdout, "合法 profile 也不应被导入（整体阻止）")


class TestWindowProfileCrossProcessFull(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_crossfull_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=2)).isoformat()
        self.window_end = now.isoformat()

        run_cli(
            "window", "create", "cross_full",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--notes", "跨进程完整测试",
            "--actor", "admin",
            env_overrides=self.env,
        )

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "file1.dat", "content": b"content1"},
                {"name": "file2.dat", "content": b"content2"},
            ],
            valid_bl=["order_system"],
        )

        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            "--window-profile", "cross_full",
            "--actor", "ops",
            env_overrides=self.env,
        )

        run_cli(
            "precheck", self.backup_dir,
            env_overrides=self.env,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_cross_process_resume_shows_full_info(self):
        r = run_cli(
            "resume", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("窗口模板", r.stdout)
        self.assertIn("cross_full", r.stdout)
        self.assertIn("+08:00", r.stdout)
        self.assertIn("跨进程完整测试", r.stdout)
        self.assertIn("ops", r.stdout)

    def test_cross_process_list_shows_profile_info(self):
        r = run_cli(
            "list", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("窗口模板", r.stdout)
        self.assertIn("cross_full", r.stdout)

    def test_cross_process_export_preserves_profile(self):
        reports_dir = os.path.join(self.tmp_dir, "reports")
        run_cli(
            "export", self.backup_dir,
            "--output", reports_dir,
            env_overrides=self.env,
        )

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertIsNotNone(report.get("window_profile"))
        self.assertEqual(report["window_profile"]["profile_name"], "cross_full")
        self.assertEqual(report["window_profile"]["timezone"], "+08:00")
        self.assertEqual(report["window_profile"]["notes"], "跨进程完整测试")
        self.assertEqual(report["window_profile"]["applied_by"], "ops")

    def test_cross_process_show_profile_with_applications(self):
        r = run_cli(
            "window", "show", "cross_full",
            "--show-log",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("cross_full", r.stdout)
        self.assertIn("应用记录", r.stdout)
        self.assertIn("TEST-001", r.stdout)
        self.assertIn("模板审计日志", r.stdout)
        self.assertIn("创建", r.stdout)
        self.assertIn("应用", r.stdout)


class TestWindowProfileJsonRoundtrip(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_roundtrip_")
        self.env1 = make_isolated_config(os.path.join(self.tmp_dir, "cfg1"))
        self.env2 = make_isolated_config(os.path.join(self.tmp_dir, "cfg2"))
        now = datetime.now()
        self.start = (now - timedelta(hours=8)).isoformat()
        self.end = now.isoformat()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_json_export_import_preserves_all_fields(self):
        run_cli(
            "window", "create", "roundtrip_prof",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "-05:00",
            "--business-line", "order_system",
            "--business-line", "hr_system",
            "--notes", "全字段导出导入测试",
            "--actor", "creator",
            env_overrides=self.env1,
        )

        export_path = os.path.join(self.tmp_dir, "roundtrip.json")
        r = run_cli(
            "window", "export", export_path,
            "--name", "roundtrip_prof",
            "--actor", "admin",
            env_overrides=self.env1,
        )
        self.assertEqual(r.returncode, 0, f"export failed: {r.stderr}")

        with open(export_path, "r", encoding="utf-8") as f:
            exported = json.load(f)
        self.assertEqual(len(exported["profiles"]), 1)
        p = exported["profiles"][0]
        self.assertEqual(p["name"], "roundtrip_prof")
        self.assertEqual(p["timezone"], "-05:00")
        self.assertEqual(p["business_lines"], ["order_system", "hr_system"])
        self.assertEqual(p["notes"], "全字段导出导入测试")

        r = run_cli(
            "window", "import", export_path,
            "--actor", "importer",
            env_overrides=self.env2,
        )
        self.assertEqual(r.returncode, 0, f"import failed: {r.stderr}")

        r = run_cli("window", "show", "roundtrip_prof", env_overrides=self.env2)
        self.assertEqual(r.returncode, 0)
        self.assertIn("roundtrip_prof", r.stdout)
        self.assertIn("-05:00", r.stdout)
        self.assertIn("order_system", r.stdout)
        self.assertIn("hr_system", r.stdout)
        self.assertIn("全字段导出导入测试", r.stdout)

    def test_export_all_profiles_and_import_to_clean_env(self):
        profiles = [
            ("p1", "+08:00", ["bl_a"], "备注1"),
            ("p2", "UTC", ["bl_b", "bl_c"], "备注2"),
        ]
        for name, tz, bls, notes in profiles:
            args = [
                "window", "create", name,
                "--window-start", self.start,
                "--window-end", self.end,
                "--timezone", tz,
                "--actor", "admin",
                "--notes", notes,
            ]
            for bl in bls:
                args.extend(["--business-line", bl])
            r = run_cli(*args, env_overrides=self.env1)
            self.assertEqual(r.returncode, 0, f"create {name} failed: {r.stderr}")

        export_path = os.path.join(self.tmp_dir, "all_profiles.json")
        run_cli(
            "window", "export", export_path,
            "--actor", "admin",
            env_overrides=self.env1,
        )

        run_cli(
            "window", "import", export_path,
            "--actor", "importer",
            env_overrides=self.env2,
        )

        r = run_cli("window", "list", env_overrides=self.env2)
        self.assertEqual(r.returncode, 0)
        self.assertIn("2 个", r.stdout)
        for name, tz, bls, notes in profiles:
            self.assertIn(name, r.stdout)


class TestWindowProfileAuditLogQuery(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_logq_")
        self.env = make_isolated_config(self.tmp_dir)
        now = datetime.now()
        self.start = (now - timedelta(hours=2)).isoformat()
        self.end = now.isoformat()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_show_log_captures_create_apply_update(self):
        run_cli(
            "window", "create", "logquery",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "creator",
            env_overrides=self.env,
        )

        backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(backup_dir, exist_ok=True)
        make_temp_backup(
            backup_dir,
            [{"name": "test.dat", "content": b"test"}],
            valid_bl=["order_system"],
        )
        run_cli(
            "import",
            os.path.join(backup_dir, "manifest.json"),
            backup_dir,
            env_overrides=self.env,
        )
        run_cli(
            "window", "apply", "logquery",
            backup_dir,
            "--actor", "applier",
            env_overrides=self.env,
        )

        import backup_audit.window_profile as _wp
        _os_environ_backup = os.environ.copy()
        os.environ.update(self.env)
        store = _wp.WindowProfileStore()
        store.update_profile(
            name="logquery",
            actor="updater",
            timezone="+09:00",
            business_lines=["order_system", "payment_system"],
            notes="updated",
        )
        os.environ.clear()
        os.environ.update(_os_environ_backup)

        r = run_cli(
            "window", "show", "logquery",
            "--show-log",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("模板审计日志", r.stdout)
        self.assertIn("创建", r.stdout)
        self.assertIn("应用", r.stdout)
        self.assertIn("更新", r.stdout)
        self.assertIn("creator", r.stdout)
        self.assertIn("applier", r.stdout)
        self.assertIn("updater", r.stdout)

    def test_export_import_logged_in_audit(self):
        run_cli(
            "window", "create", "logie",
            "--window-start", self.start,
            "--window-end", self.end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--actor", "admin",
            env_overrides=self.env,
        )

        export_path = os.path.join(self.tmp_dir, "logie.json")
        run_cli(
            "window", "export", export_path,
            "--name", "logie",
            "--actor", "exporter",
            env_overrides=self.env,
        )

        r = run_cli(
            "window", "show", "logie",
            "--show-log",
            env_overrides=self.env,
        )
        self.assertIn("导出", r.stdout)
        self.assertIn("exporter", r.stdout)


class TestWindowProfileTamperedTemplateBlocking(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_tamper_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=2)).isoformat()
        self.window_end = now.isoformat()

        run_cli(
            "window", "create", "tpl_before_tamper",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "+08:00",
            "--business-line", "order_system",
            "--notes", "模板创建时是合法的",
            "--actor", "admin",
            env_overrides=self.env,
        )

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "good.dat", "content": b"good content"},
            ],
            valid_bl=["order_system"],
        )
        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            env_overrides=self.env,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _tamper_profiles_json(self, bad_timezone: str):
        profiles_path = self.env["BACKUP_AUDIT_WINDOW_PROFILES"]
        with open(profiles_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for p in data["profiles"]:
            if p["name"] == "tpl_before_tamper":
                p["timezone"] = bad_timezone
                break
        with open(profiles_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def test_window_apply_fails_after_hand_tampering_timezone(self):
        self._tamper_profiles_json("+15:00")

        r = run_cli(
            "window", "apply", "tpl_before_tamper",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "手工篡改时区为 +15:00 后 apply 应失败")
        self.assertIn("tpl_before_tamper", r.stderr)
        self.assertIn("timezone", r.stderr)
        self.assertIn("+15:00", r.stderr)

        snap_dir = self.env["BACKUP_AUDIT_WINDOW_PROFILE_SNAPSHOTS"]
        snap_files = []
        if os.path.isdir(snap_dir):
            snap_files = os.listdir(snap_dir)
        self.assertEqual(len(snap_files), 0, "非法模板不应产生快照文件")

        app_path = self.env["BACKUP_AUDIT_WINDOW_PROFILE_APPLICATIONS"]
        with open(app_path, "r", encoding="utf-8") as f:
            app_data = json.load(f)
        self.assertEqual(len(app_data.get("applications", [])), 0, "非法模板不应产生应用记录")

        log_path = self.env["BACKUP_AUDIT_WINDOW_PROFILE_LOG"]
        with open(log_path, "r", encoding="utf-8") as f:
            log_data = json.load(f)
        for entry in log_data.get("log", []):
            self.assertNotEqual(
                entry.get("action"),
                "window_profile_apply",
                "非法模板不应产生 apply 审计日志",
            )

    def test_import_with_window_profile_fails_after_hand_tampering(self):
        self._tamper_profiles_json("+15:00")

        backup_dir2 = os.path.join(self.tmp_dir, "backup2")
        os.makedirs(backup_dir2)
        make_temp_backup(
            backup_dir2,
            [{"name": "file.dat", "content": b"content"}],
            batch_id="TEST-002",
            valid_bl=["order_system"],
        )

        r = run_cli(
            "import",
            os.path.join(backup_dir2, "manifest.json"),
            backup_dir2,
            "--window-profile", "tpl_before_tamper",
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "手工篡改时区后 import --window-profile 应失败")
        self.assertIn("tpl_before_tamper", r.stderr)
        self.assertIn("timezone", r.stderr)
        self.assertIn("+15:00", r.stderr)

    def test_window_apply_fails_with_tampered_invalid_format(self):
        self._tamper_profiles_json("BADTZ")

        r = run_cli(
            "window", "apply", "tpl_before_tamper",
            self.backup_dir,
            "--actor", "ops",
            env_overrides=self.env,
        )
        self.assertNotEqual(r.returncode, 0, "手工篡改为格式非法时区后 apply 应失败")
        self.assertIn("tpl_before_tamper", r.stderr)
        self.assertIn("timezone", r.stderr)
        self.assertIn("BADTZ", r.stderr)


class TestWindowProfileValidCrossProcess(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_win_validcp_")
        self.env = make_isolated_config(self.tmp_dir)
        self.backup_dir = os.path.join(self.tmp_dir, "backup")
        os.makedirs(self.backup_dir)

        now = datetime.now()
        self.window_start = (now - timedelta(hours=4)).isoformat()
        self.window_end = (now - timedelta(hours=1)).isoformat()

        run_cli(
            "window", "create", "valid_cross",
            "--window-start", self.window_start,
            "--window-end", self.window_end,
            "--timezone", "-05:00",
            "--business-line", "order_system",
            "--business-line", "payment_system",
            "--notes", "合法跨进程测试模板",
            "--actor", "admin",
            env_overrides=self.env,
        )

        make_temp_backup(
            self.backup_dir,
            [
                {"name": "inside.dat", "content": b"inside window", "age_minutes": 150},
                {"name": "outside.dat", "content": b"outside window", "age_minutes": 60 * 24 * 5},
            ],
            valid_bl=["order_system", "payment_system"],
        )

        run_cli(
            "import",
            os.path.join(self.backup_dir, "manifest.json"),
            self.backup_dir,
            "--window-profile", "valid_cross",
            "--actor", "ops",
            env_overrides=self.env,
        )

        run_cli(
            "precheck", self.backup_dir,
            env_overrides=self.env,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_valid_resume_shows_all_template_info(self):
        r = run_cli(
            "resume", self.backup_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"resume 应成功: {r.stderr}")
        self.assertIn("窗口模板", r.stdout)
        self.assertIn("valid_cross", r.stdout)
        self.assertIn("-05:00", r.stdout)
        self.assertIn("合法跨进程测试模板", r.stdout)
        self.assertIn("ops", r.stdout)
        self.assertIn("v1", r.stdout)

    def test_valid_show_profile_and_applications(self):
        r = run_cli(
            "window", "show", "valid_cross",
            "--show-log",
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("valid_cross", r.stdout)
        self.assertIn("-05:00", r.stdout)
        self.assertIn("合法跨进程测试模板", r.stdout)
        self.assertIn("应用记录", r.stdout)
        self.assertIn("TEST-001", r.stdout)
        self.assertIn("模板审计日志", r.stdout)
        self.assertIn("创建", r.stdout)
        self.assertIn("应用", r.stdout)
        self.assertIn("admin", r.stdout)
        self.assertIn("ops", r.stdout)

    def test_valid_export_includes_full_template_data(self):
        reports_dir = os.path.join(self.tmp_dir, "reports")
        r = run_cli(
            "export", self.backup_dir,
            "--output", reports_dir,
            env_overrides=self.env,
        )
        self.assertEqual(r.returncode, 0, f"export 应成功: {r.stderr}")

        json_path = os.path.join(reports_dir, "audit_report_TEST-001.json")
        self.assertTrue(os.path.exists(json_path), "应生成 JSON 报告")

        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertIsNotNone(report.get("window_profile"), "报告应含 window_profile 节")
        wp = report["window_profile"]
        self.assertEqual(wp["profile_name"], "valid_cross")
        self.assertEqual(wp["profile_version"], 1)
        self.assertEqual(wp["timezone"], "-05:00")
        self.assertEqual(wp["notes"], "合法跨进程测试模板")
        self.assertEqual(wp["applied_by"], "ops")
        self.assertEqual(wp["window_start"], self.window_start)
        self.assertEqual(wp["window_end"], self.window_end)
        self.assertEqual(wp["business_lines"], ["order_system", "payment_system"])
        self.assertIn("profile_fingerprint", wp)

        out_window_issues = [i for i in report["all_issues"] if i["type"] == "outside_backup_window"]
        self.assertTrue(len(out_window_issues) > 0, "应检测到 outside_backup_window 问题")
        for issue in out_window_issues:
            self.assertIn("(-05:00)", issue["message"], "问题消息应含模板时区")


if __name__ == "__main__":
    unittest.main()
