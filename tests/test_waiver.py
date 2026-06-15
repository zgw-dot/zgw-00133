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


def run_cli(*args: str, extra_env: dict = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    if extra_env:
        env.update(extra_env)
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
        "valid_business_lines": valid_bl or ["order_system", "payment_system", "legacy_system"],
        "files": manifest_files,
        "revocation_list": revocation if revocation is not None else [],
    }
    manifest_path = os.path.join(tmp_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return tmp_dir


class WaiverTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="audit_waiver_test_")
        self.config_dir = os.path.join(self.tmp_dir, "config")
        os.makedirs(self.config_dir, exist_ok=True)
        self.extra_env = {
            "BACKUP_AUDIT_CONFIG_DIR": self.config_dir,
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_batch(self, files=None):
        if files is None:
            wrong_hash = hashlib.sha256(b"wrong").hexdigest()
            files = [
                {"name": "good.dat", "content": b"hello"},
                {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
                {"name": "old.dat", "content": b"old", "age_minutes": 60 * 24 * 30, "business_line": "legacy_system"},
                {"name": "pay.dat", "content": b"payment", "business_line": "payment_system"},
            ]
        make_temp_backup(self.tmp_dir, files)
        r = run_cli("import", os.path.join(self.tmp_dir, "manifest.json"), self.tmp_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0, f"import failed: {r.stderr}")
        r = run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0, f"precheck failed: {r.stderr}")

    def _read_state(self):
        state_dir = os.path.join(self.tmp_dir, ".audit_state")
        for f in os.listdir(state_dir):
            if f.startswith("batch_") and f.endswith(".json"):
                with open(os.path.join(state_dir, f), "r", encoding="utf-8") as fp:
                    return json.load(fp)
        return None

    def _read_waiver_rules(self):
        rules_path = os.path.join(self.config_dir, "waiver_rules.json")
        if not os.path.exists(rules_path):
            return {"rules": []}
        with open(rules_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _read_waiver_log(self):
        log_path = os.path.join(self.config_dir, "waiver_audit_log.json")
        if not os.path.exists(log_path):
            return {"log": []}
        with open(log_path, "r", encoding="utf-8") as f:
            return json.load(f)


class TestWaiverAddBasic(WaiverTestBase):
    def test_add_waiver_by_path_prefix(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops_zhang",
            "--reason", "遗留系统已知问题，暂不处理",
            "--path-prefix", "data/old",
            "--severity", "blocking",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"waiver add failed: {r.stderr}")
        self.assertIn("豁免规则已添加", r.stdout)
        self.assertIn("ops_zhang", r.stdout)
        self.assertIn("遗留系统已知问题", r.stdout)

        rules_data = self._read_waiver_rules()
        self.assertEqual(len(rules_data["rules"]), 1)
        rule = rules_data["rules"][0]
        self.assertEqual(rule["actor"], "ops_zhang")
        self.assertEqual(rule["path_prefix"], "data/old")
        self.assertEqual(rule["severity"], "blocking")

    def test_add_waiver_by_business_line(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "qa_li",
            "--reason", "支付系统历史数据校验位允许不一致",
            "--business-line", "payment_system",
            "--issue-type", "bad_checksum",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"waiver add failed: {r.stderr}")
        self.assertIn("豁免规则已添加", r.stdout)

        rules_data = self._read_waiver_rules()
        self.assertEqual(len(rules_data["rules"]), 1)
        rule = rules_data["rules"][0]
        self.assertEqual(rule["business_line"], "payment_system")
        self.assertEqual(rule["issue_type"], "bad_checksum")

    def test_add_waiver_requires_reason(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops_zhang",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--reason", r.stderr)

    def test_add_waiver_requires_actor(self):
        r = run_cli(
            "waiver", "add",
            "--reason", "no reason",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--actor", r.stderr)


class TestWaiverBlockingFullExemption(WaiverTestBase):
    def test_block_all_blocking_is_rejected(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops_bad",
            "--reason", "豁免所有阻断问题，图省事",
            "--severity", "blocking",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "应拦截全量 blocking 豁免")
        self.assertIn("过于宽泛", r.stderr)
        self.assertIn("至少指定", r.stderr)

    def test_blocking_with_path_prefix_is_ok(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops_good",
            "--reason", "限定路径的豁免是允许的",
            "--severity", "blocking",
            "--path-prefix", "data/legacy/",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"应允许限定路径的 blocking 豁免: {r.stderr}")

    def test_blocking_with_issue_type_is_ok(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops_good",
            "--reason", "限定类型的豁免是允许的",
            "--severity", "blocking",
            "--issue-type", "size_mismatch",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"应允许限定类型的 blocking 豁免: {r.stderr}")

    def test_blocking_with_business_line_is_ok(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops_good",
            "--reason", "限定业务线的豁免是允许的",
            "--severity", "blocking",
            "--business-line", "legacy_system",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"应允许限定业务线的 blocking 豁免: {r.stderr}")


class TestWaiverConflictDetection(WaiverTestBase):
    def test_conflicting_rules_detected(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops1",
            "--reason", "原规则",
            "--path-prefix", "data/old",
            "--severity", "blocking",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli(
            "waiver", "add",
            "--actor", "ops2",
            "--reason", "冲突规则 - 更宽路径前缀",
            "--path-prefix", "data/old/2023",
            "--severity", "blocking",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "应检测到路径前缀冲突")
        self.assertIn("冲突", r.stderr)
        self.assertIn("--force", r.stderr)

    def test_force_add_conflict_allowed(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "ops1",
            "--reason", "原规则",
            "--path-prefix", "data/old",
            "--severity", "blocking",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli(
            "waiver", "add",
            "--actor", "ops2",
            "--reason", "强制添加冲突规则",
            "--path-prefix", "data/old/2023",
            "--severity", "blocking",
            "--force",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"--force 应允许添加冲突规则: {r.stderr}")

        rules_data = self._read_waiver_rules()
        self.assertEqual(len(rules_data["rules"]), 2)


class TestWaiverList(WaiverTestBase):
    def test_list_empty(self):
        r = run_cli("waiver", "list", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("暂无生效的豁免规则", r.stdout)
        self.assertIn("当前生效规则: 0", r.stdout)

    def test_list_rules(self):
        run_cli(
            "waiver", "add",
            "--actor", "ops_a",
            "--reason", "规则A",
            "--path-prefix", "data/a/",
            extra_env=self.extra_env,
        )
        run_cli(
            "waiver", "add",
            "--actor", "ops_b",
            "--reason", "规则B",
            "--business-line", "payment_system",
            "--issue-type", "bad_checksum",
            extra_env=self.extra_env,
        )

        r = run_cli("waiver", "list", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("当前生效规则: 2", r.stdout)
        self.assertIn("规则A", r.stdout)
        self.assertIn("规则B", r.stdout)
        self.assertIn("路径前缀=data/a/", r.stdout)
        self.assertIn("业务线=payment_system", r.stdout)
        self.assertIn("类型=bad_checksum", r.stdout)

    def test_list_with_audit_log(self):
        run_cli(
            "waiver", "add",
            "--actor", "logger",
            "--reason", "第一条规则",
            "--path-prefix", "data/x/",
            extra_env=self.extra_env,
        )
        rules_data = self._read_waiver_rules()
        rid = rules_data["rules"][0]["id"]
        run_cli("waiver", "delete", rid, "--actor", "logger", "--yes", extra_env=self.extra_env)

        r = run_cli("waiver", "list", "--show-log", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("规则变更操作日志", r.stdout)
        self.assertIn("waiver_add", r.stdout)
        self.assertIn("waiver_delete", r.stdout)
        self.assertIn("logger", r.stdout)


class TestWaiverDelete(WaiverTestBase):
    def _add_rule(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "deler",
            "--reason", "待删除规则",
            "--path-prefix", "data/del/",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        rules = self._read_waiver_rules()["rules"]
        return rules[0]["id"]

    def test_delete_nonexistent_returns_error(self):
        r = run_cli("waiver", "delete", "no_such_id", "--actor", "deler", "--yes", extra_env=self.extra_env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("未找到规则", r.stderr)

    def test_delete_requires_confirmation(self):
        rid = self._add_rule()
        r = run_cli("waiver", "delete", rid, "--actor", "deler", extra_env=self.extra_env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--force", r.stderr)
        self.assertIn("--yes", r.stderr)
        self.assertEqual(len(self._read_waiver_rules()["rules"]), 1)

    def test_delete_with_yes_confirmed(self):
        rid = self._add_rule()
        r = run_cli("waiver", "delete", rid, "--actor", "deler", "--yes", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0, f"delete with --yes should succeed: {r.stderr}")
        self.assertIn("规则已删除", r.stdout)
        self.assertEqual(len(self._read_waiver_rules()["rules"]), 0)

        log_data = self._read_waiver_log()
        actions = [e["action"] for e in log_data["log"]]
        self.assertIn("waiver_delete", actions)


class TestWaiverExportImport(WaiverTestBase):
    def test_export_then_import_merge(self):
        run_cli(
            "waiver", "add",
            "--actor", "exporter",
            "--reason", "导出测试规则1",
            "--path-prefix", "data/exp1/",
            extra_env=self.extra_env,
        )
        run_cli(
            "waiver", "add",
            "--actor", "exporter",
            "--reason", "导出测试规则2",
            "--business-line", "payment_system",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "waivers_export.json")
        r = run_cli("waiver", "export", export_path, "--actor", "exporter", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0, f"export failed: {r.stderr}")
        self.assertIn("豁免规则已导出", r.stdout)
        self.assertTrue(os.path.exists(export_path))

        with open(export_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["rules"]), 2)
        self.assertEqual(data["exported_by"], "exporter")

        config2 = os.path.join(self.tmp_dir, "config2")
        os.makedirs(config2, exist_ok=True)
        env2 = {"BACKUP_AUDIT_CONFIG_DIR": config2}

        r = run_cli("waiver", "import", export_path, "--actor", "importer", extra_env=env2)
        self.assertEqual(r.returncode, 0, f"import failed: {r.stderr}")
        self.assertIn("成功添加: 2", r.stdout)

        rules_path2 = os.path.join(config2, "waiver_rules.json")
        with open(rules_path2, "r", encoding="utf-8") as f:
            imported = json.load(f)
        self.assertEqual(len(imported["rules"]), 2)

        r = run_cli("waiver", "import", export_path, "--actor", "importer", extra_env=env2)
        self.assertEqual(r.returncode, 0)
        self.assertIn("跳过 (已存在): 2", r.stdout)

    def test_import_replace_mode(self):
        run_cli(
            "waiver", "add",
            "--actor", "exporter",
            "--reason", "原始规则",
            "--path-prefix", "data/original/",
            extra_env=self.extra_env,
        )
        export_path = os.path.join(self.tmp_dir, "waivers_replace.json")
        run_cli("waiver", "export", export_path, "--actor", "exporter", extra_env=self.extra_env)

        run_cli(
            "waiver", "add",
            "--actor", "other",
            "--reason", "其他规则",
            "--path-prefix", "data/other/",
            extra_env=self.extra_env,
        )
        self.assertEqual(len(self._read_waiver_rules()["rules"]), 2)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "replacer",
            "--mode", "replace",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"import replace failed: {r.stderr}")
        self.assertEqual(len(self._read_waiver_rules()["rules"]), 1)


class TestWaiverPrecheckIntegration(WaiverTestBase):
    def test_waiver_applied_in_precheck(self):
        self._setup_batch()
        state_before = self._read_state()
        before_waived = sum(1 for i in state_before["issues"] if i.get("waived"))
        self.assertEqual(before_waived, 0, "初始时不应有豁免问题")

        r = run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "遗留数据 old.dat 的超时允许",
            "--path-prefix", "data/old",
            "--severity", "confirmable",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0, f"precheck failed: {r.stderr}")
        self.assertIn("本次豁免命中", r.stdout)

        state_after = self._read_state()
        waived_issues = [i for i in state_after["issues"] if i.get("waived")]
        self.assertGreaterEqual(len(waived_issues), 1)
        for wi in waived_issues:
            self.assertIsNotNone(wi.get("waived_by_rule_id"))
            self.assertIsNotNone(wi.get("waived_reason"))
            self.assertIsNotNone(wi.get("waived_at"))

        ops_log = state_after.get("operation_log", [])
        actions = [e["action"] for e in ops_log]
        self.assertIn("waiver_rescan", actions)

    def test_waiver_by_business_line_applied(self):
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        files = [
            {"name": "good.dat", "content": b"hello"},
            {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
            {"name": "old.dat", "content": b"old", "age_minutes": 60 * 24 * 30, "business_line": "legacy_system"},
            {"name": "pay.dat", "content": b"payment", "sha256": wrong_hash, "business_line": "payment_system"},
        ]
        self._setup_batch(files=files)

        r = run_cli(
            "waiver", "add",
            "--actor", "payops",
            "--reason", "支付系统历史校验和允许",
            "--business-line", "payment_system",
            "--issue-type", "bad_checksum",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        state = self._read_state()
        waived = [i for i in state["issues"] if i.get("waived")]
        self.assertGreaterEqual(len(waived), 1)
        pay_waived = [i for i in waived if "pay" in i["file_path"]]
        self.assertGreaterEqual(len(pay_waived), 1)


class TestWaiverListShowsWaivedIssues(WaiverTestBase):
    def test_list_shows_waived_section(self):
        self._setup_batch()
        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "豁免 old",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        r = run_cli("list", self.tmp_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("[活跃]", r.stdout)
        self.assertIn("[已豁免]", r.stdout)
        self.assertIn("豁免理由: 豁免 old", r.stdout)
        self.assertIn("生效人: ops", r.stdout)

    def test_list_waived_exclude(self):
        self._setup_batch()
        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "豁免 old",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        r = run_cli("list", self.tmp_dir, "--waived", "exclude", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("[已豁免]", r.stdout)

    def test_list_waived_only(self):
        self._setup_batch()
        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "豁免 old",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        r = run_cli("list", self.tmp_dir, "--waived", "only", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("[活跃]", r.stdout)
        self.assertIn("[已豁免]", r.stdout)


class TestWaiverDeleteReExposesIssues(WaiverTestBase):
    def test_delete_rule_unwaives_issues(self):
        self._setup_batch()

        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "临时豁免 bad_checksum",
            "--issue-type", "bad_checksum",
            "--severity", "blocking",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )
        rules_data = self._read_waiver_rules()
        rule_id = rules_data["rules"][0]["id"]

        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        state1 = self._read_state()
        waived_count1 = sum(1 for i in state1["issues"] if i.get("waived"))
        self.assertGreater(waived_count1, 0)

        run_cli("waiver", "delete", rule_id, "--actor", "ops", "--yes", extra_env=self.extra_env)
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        state2 = self._read_state()
        waived_count2 = sum(1 for i in state2["issues"] if i.get("waived"))
        self.assertEqual(waived_count2, 0, "删除规则后问题应重新暴露")

        ops_log = state2.get("operation_log", [])
        wb_entries = [e for e in ops_log if e["action"] == "waiver_rescan"]
        self.assertGreaterEqual(len(wb_entries), 2)
        last_entry = wb_entries[-1]
        self.assertGreater(last_entry["detail"]["newly_unwaived"], 0)


class TestWaiverPersistenceAcrossRestarts(WaiverTestBase):
    def test_rules_and_log_persist(self):
        r = run_cli(
            "waiver", "add",
            "--actor", "persister",
            "--reason", "跨重启持久化规则",
            "--path-prefix", "data/persist/",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli("waiver", "list", extra_env=self.extra_env)
        self.assertIn("当前生效规则: 1", r.stdout)
        self.assertIn("跨重启持久化规则", r.stdout)

        r = run_cli("waiver", "list", "--show-log", extra_env=self.extra_env)
        self.assertIn("waiver_add", r.stdout)
        self.assertIn("persister", r.stdout)

    def test_waived_status_persists_in_batch(self):
        self._setup_batch()
        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "持久豁免",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        r = run_cli("resume", self.tmp_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("已豁免总计:", r.stdout)

        state = self._read_state()
        self.assertGreater(sum(1 for i in state["issues"] if i.get("waived")), 0)


class TestWaiverExpiry(WaiverTestBase):
    def test_expired_rule_not_applied(self):
        past = (datetime.now() - timedelta(days=1)).isoformat()
        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "已过期规则",
            "--path-prefix", "data/old",
            "--expires-at", past,
            extra_env=self.extra_env,
        )
        self._setup_batch()
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        state = self._read_state()
        waived_count = sum(1 for i in state["issues"] if i.get("waived"))
        self.assertEqual(waived_count, 0, "过期规则不应命中问题")

    def test_future_rule_applied_then_expires(self):
        self._setup_batch()
        future = (datetime.now() + timedelta(days=1)).isoformat()
        run_cli(
            "waiver", "add",
            "--actor", "ops",
            "--reason", "短期豁免",
            "--path-prefix", "data/old",
            "--expires-at", future,
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        state = self._read_state()
        waived_count = sum(1 for i in state["issues"] if i.get("waived"))
        self.assertGreater(waived_count, 0)

        past = (datetime.now() - timedelta(days=1)).isoformat()
        rules_data = self._read_waiver_rules()
        rules_data["rules"][0]["expires_at"] = past
        rules_path = os.path.join(self.config_dir, "waiver_rules.json")
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump(rules_data, f, ensure_ascii=False, indent=2)

        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)
        state2 = self._read_state()
        waived_count2 = sum(1 for i in state2["issues"] if i.get("waived"))
        self.assertEqual(waived_count2, 0, "规则过期后问题应重新暴露")


class TestWaiverProtectsSignedOffBatch(WaiverTestBase):
    def test_rescan_blocked_on_signed_batch(self):
        self._setup_batch()
        r = run_cli(
            "finalize", self.tmp_dir,
            "--signer", "approver",
            "--reason", "all good",
            "--force-with-reason",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli(
            "waiver", "rescan", self.tmp_dir,
            "--actor", "ops",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("禁止执行", r.stderr)
        self.assertIn("waiver rescan", r.stderr)


class TestWaiverReportExport(WaiverTestBase):
    def test_export_json_includes_waived_info(self):
        self._setup_batch()
        run_cli(
            "waiver", "add",
            "--actor", "reporter",
            "--reason", "报告测试豁免",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        out_dir = os.path.join(self.tmp_dir, "reports")
        r = run_cli("export", self.tmp_dir, "--output", out_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)

        json_path = os.path.join(out_dir, "audit_report_TEST-001.json")
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        self.assertIn("waived_total", report["summary"])
        self.assertIn("waived_by_severity", report["summary"])
        self.assertIn("waived_blocking_issues", report)
        self.assertIn("waived_confirmable_issues", report)
        total_waived = len(report["waived_blocking_issues"]) + len(report["waived_confirmable_issues"])
        self.assertGreater(total_waived, 0)
        for wi in report["waived_confirmable_issues"]:
            if wi.get("waived_by_rule_id"):
                self.assertIn("waived_by_rule", wi)
                self.assertEqual(wi["waived_by_rule"]["actor"], "reporter")

    def test_export_csv_includes_waived_section(self):
        self._setup_batch()
        run_cli(
            "waiver", "add",
            "--actor", "reporter",
            "--reason", "CSV豁免",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        run_cli("precheck", self.tmp_dir, extra_env=self.extra_env)

        out_dir = os.path.join(self.tmp_dir, "reports_csv")
        run_cli("export", self.tmp_dir, "--output", out_dir, "--format", "csv", extra_env=self.extra_env)

        csv_path = os.path.join(out_dir, "audit_report_TEST-001.csv")
        with open(csv_path, "r", encoding="utf-8-sig") as f:
            csv_content = f.read()

        self.assertIn("已豁免", csv_content)
        self.assertIn("豁免规则ID", csv_content)
        self.assertIn("已豁免阻断问题", csv_content)
        self.assertIn("CSV豁免", csv_content)


class TestWaiverAuditLogComprehensive(WaiverTestBase):
    def test_all_operations_logged(self):
        run_cli(
            "waiver", "add",
            "--actor", "logger_user",
            "--reason", "日志测试规则",
            "--path-prefix", "data/log/",
            extra_env=self.extra_env,
        )
        rules = self._read_waiver_rules()["rules"]
        rid = rules[0]["id"]

        export_file = os.path.join(self.tmp_dir, "log_waivers.json")
        run_cli("waiver", "export", export_file, "--actor", "logger_user", extra_env=self.extra_env)

        run_cli("waiver", "import", export_file, "--actor", "logger_user", extra_env=self.extra_env)

        run_cli("waiver", "delete", rid, "--actor", "logger_user", "--yes", extra_env=self.extra_env)

        log_data = self._read_waiver_log()
        actions = [e["action"] for e in log_data["log"]]
        actors = [e["actor"] for e in log_data["log"]]

        self.assertIn("waiver_add", actions)
        self.assertIn("waiver_export", actions)
        self.assertIn("waiver_import", actions)
        self.assertIn("waiver_delete", actions)
        for a in actors:
            self.assertEqual(a, "logger_user")


class TestWaiverRescanCommand(WaiverTestBase):
    def test_rescan_updates_status(self):
        self._setup_batch()
        r = run_cli(
            "waiver", "rescan", self.tmp_dir,
            "--actor", "rescanner",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("豁免规则重新扫描完成", r.stdout)

        run_cli(
            "waiver", "add",
            "--actor", "rescanner",
            "--reason", "rescan test",
            "--path-prefix", "data/old",
            extra_env=self.extra_env,
        )
        r = run_cli(
            "waiver", "rescan", self.tmp_dir,
            "--actor", "rescanner",
            extra_env=self.extra_env,
        )
        self.assertIn("新命中豁免", r.stdout)

        state = self._read_state()
        ops = [e for e in state["operation_log"] if e["action"] == "waiver_rescan"]
        self.assertGreaterEqual(len(ops), 2)


if __name__ == "__main__":
    unittest.main()
