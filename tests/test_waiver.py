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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backup_audit.waiver import WaiverStore


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
            "--replace-confirm-manual-delete",
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


class TestSignedOffWaiverLockin(WaiverTestBase):
    def _setup_signed_batch_with_blocking(self):
        wrong_hash = hashlib.sha256(b"wrong").hexdigest()
        files = [
            {"name": "good.dat", "content": b"hello"},
            {"name": "bad.dat", "content": b"tampered", "sha256": wrong_hash},
        ]
        self._setup_batch(files=files)
        r = run_cli(
            "finalize", self.tmp_dir,
            "--signer", "approver",
            "--reason", "先签收，豁免后补",
            "--force-with-reason",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"finalize should succeed: {r.stderr}")

    def test_finalize_then_add_waiver_resume_does_not_change_blocking_count(self):
        self._setup_signed_batch_with_blocking()

        state_before = self._read_state()
        signoff_blocking_before = state_before["signoff"]["unresolved_blocking_count"]
        self.assertGreater(signoff_blocking_before, 0, "签收时应有未处理阻断")

        run_cli(
            "waiver", "add",
            "--actor", "ops_after",
            "--reason", "签收后补的豁免",
            "--issue-type", "bad_checksum",
            "--severity", "blocking",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )

        r = run_cli("resume", self.tmp_dir, extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("豁免规则已锁定在签收时刻", r.stdout)

        state_after = self._read_state()
        signoff_blocking_after = state_after["signoff"]["unresolved_blocking_count"]
        self.assertEqual(
            signoff_blocking_after, signoff_blocking_before,
            "签收记录中的未处理阻断数不应因后续豁免规则而改变"
        )

        waived_after = sum(1 for i in state_after["issues"] if i.get("waived"))
        self.assertEqual(waived_after, 0, "已签收批次的问题不应被后续豁免规则修改")

    def test_list_after_new_waiver_on_signed_batch_shows_same_status(self):
        self._setup_signed_batch_with_blocking()

        run_cli(
            "waiver", "add",
            "--actor", "ops_after",
            "--reason", "签收后补的豁免",
            "--issue-type", "bad_checksum",
            "--severity", "blocking",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )

        r = run_cli("list", self.tmp_dir, "--waived", "include", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("[已豁免]", r.stdout, "已签收批次 list 不应显示被后续规则豁免的问题")
        self.assertIn("[活跃]", r.stdout)

    def test_export_after_new_waiver_on_signed_batch_keeps_signoff_consistent(self):
        self._setup_signed_batch_with_blocking()
        out_dir = os.path.join(self.tmp_dir, "reports")

        run_cli(
            "waiver", "add",
            "--actor", "ops_after",
            "--reason", "签收后补的豁免",
            "--issue-type", "bad_checksum",
            "--severity", "blocking",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )

        run_cli("export", self.tmp_dir, "--output", out_dir, "--format", "json", extra_env=self.extra_env)
        json_path = os.path.join(out_dir, "audit_report_TEST-001.json")
        with open(json_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        summary_blocking = report["summary"]["unresolved_blocking"]
        signoff_blocking = report["signoff"]["unresolved_blocking_count"]
        self.assertEqual(
            summary_blocking, signoff_blocking,
            "导出报告的未处理阻断统计应与签收记录一致"
        )

        waived_total = report["summary"]["waived_total"]
        self.assertEqual(waived_total, 0, "已签收批次导出不应显示被后续规则豁免的问题")

    def test_reopen_then_rescan_applies_new_waivers(self):
        self._setup_signed_batch_with_blocking()

        state_before = self._read_state()
        waived_before = sum(1 for i in state_before["issues"] if i.get("waived"))
        self.assertEqual(waived_before, 0)

        run_cli(
            "waiver", "add",
            "--actor", "ops_after",
            "--reason", "重开后生效的豁免",
            "--issue-type", "bad_checksum",
            "--severity", "blocking",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "reopen", self.tmp_dir,
            "--reopener", "reopener_zhang",
            "--reason", "发现之前的阻断可以豁免",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"reopen should succeed: {r.stderr}")

        state_after_reopen = self._read_state()
        waived_after_reopen = sum(1 for i in state_after_reopen["issues"] if i.get("waived"))
        self.assertEqual(waived_after_reopen, 0, "重开后不自动应用豁免，等用户触发")

        run_cli(
            "waiver", "rescan", self.tmp_dir,
            "--actor", "reopener_zhang",
            extra_env=self.extra_env,
        )

        state_after_rescan = self._read_state()
        waived_after_rescan = sum(1 for i in state_after_rescan["issues"] if i.get("waived"))
        self.assertGreater(waived_after_rescan, 0, "重开后 rescan 应使新豁免规则生效")

    def test_cross_restart_signed_batch_waived_count_stable(self):
        self._setup_signed_batch_with_blocking()

        state_before = self._read_state()
        waived_before = sum(1 for i in state_before["issues"] if i.get("waived"))
        blocking_before = sum(
            1 for i in state_before["issues"]
            if i["severity"] == "blocking" and not i.get("waived")
        )

        run_cli(
            "waiver", "add",
            "--actor", "ops_after",
            "--reason", "重启后也不该生效",
            "--issue-type", "bad_checksum",
            "--severity", "blocking",
            "--path-prefix", "data/",
            extra_env=self.extra_env,
        )

        for _ in range(3):
            r = run_cli("resume", self.tmp_dir, extra_env=self.extra_env)
            self.assertEqual(r.returncode, 0)

        state_after = self._read_state()
        waived_after = sum(1 for i in state_after["issues"] if i.get("waived"))
        blocking_after = sum(
            1 for i in state_after["issues"]
            if i["severity"] == "blocking" and not i.get("waived")
        )

        self.assertEqual(waived_after, waived_before, "跨重启后已签收批次的豁免数应保持不变")
        self.assertEqual(blocking_after, blocking_before, "跨重启后已签收批次的活跃阻断数应保持不变")


class TestWaiverImportDryRun(WaiverTestBase):
    def test_dry_run_shows_new_rules(self):
        export_path = os.path.join(self.tmp_dir, "dry_run_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "dryrun1",
                    "path_prefix": "data/new1/",
                    "reason": "预演测试规则1",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
                {
                    "id": "dryrun2",
                    "path_prefix": "data/new2/",
                    "reason": "预演测试规则2",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"dry run should succeed: {r.stderr}")
        self.assertIn("新增规则: 2", r.stdout)
        self.assertIn("预演通过，可以执行导入", r.stdout)

        rules = self._read_waiver_rules()
        self.assertEqual(len(rules["rules"]), 0, "dry run 不应实际添加规则")

    def test_dry_run_detects_conflicts(self):
        run_cli(
            "waiver", "add",
            "--actor", "tester",
            "--reason", "已存在的冲突规则",
            "--path-prefix", "data/conflict/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "conflict_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "conflict_rule",
                    "path_prefix": "data/conflict/sub/",
                    "reason": "冲突测试规则",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("冲突/风险 (跳过): 1", r.stdout)
        self.assertIn("存在范围重叠", r.stdout)

    def test_dry_run_detects_expired_rules(self):
        past = (datetime.now() - timedelta(days=1)).isoformat()
        export_path = os.path.join(self.tmp_dir, "expired_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "expired_rule",
                    "path_prefix": "data/expired/",
                    "reason": "已过期规则",
                    "actor": "tester",
                    "created_at": "2026-01-01T00:00:00",
                    "expires_at": past,
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("已过期 (跳过): 1", r.stdout)

    def test_dry_run_detects_invalid_file(self):
        bad_path = os.path.join(self.tmp_dir, "bad.json")
        with open(bad_path, "w", encoding="utf-8") as f:
            f.write("{invalid json}")

        r = run_cli(
            "waiver", "import", bad_path,
            "--actor", "tester",
            "--dry-run",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("文件错误", r.stdout)


class TestWaiverImportValidation(WaiverTestBase):
    def test_invalid_json_blocks_import(self):
        bad_path = os.path.join(self.tmp_dir, "bad_import.json")
        with open(bad_path, "w", encoding="utf-8") as f:
            f.write("not a json")

        r = run_cli(
            "waiver", "import", bad_path,
            "--actor", "tester",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "无效JSON应被拦截")
        self.assertIn("校验失败", r.stderr)

    def test_missing_reason_blocks_import(self):
        bad_path = os.path.join(self.tmp_dir, "no_reason.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "bad_rule",
                    "path_prefix": "data/bad/",
                    "reason": "",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(bad_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", bad_path,
            "--actor", "tester",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "缺少reason应被拦截")
        self.assertIn("校验失败", r.stderr)

        rules = self._read_waiver_rules()
        self.assertEqual(len(rules["rules"]), 0, "坏数据不应写入配置")

    def test_invalid_issue_type_blocks_import(self):
        bad_path = os.path.join(self.tmp_dir, "bad_type.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "bad_type",
                    "path_prefix": "data/bad/",
                    "reason": "测试规则",
                    "actor": "tester",
                    "issue_type": "invalid_type",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(bad_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", bad_path,
            "--actor", "tester",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "无效issue_type应被拦截")


class TestWaiverTransactionAndRollback(WaiverTestBase):
    def test_import_creates_transaction(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "手工规则",
            "--path-prefix", "data/manual/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "tx_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "txrule1",
                    "path_prefix": "data/tx1/",
                    "reason": "事务测试规则1",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
                {
                    "id": "txrule2",
                    "path_prefix": "data/tx2/",
                    "reason": "事务测试规则2",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"import failed: {r.stderr}")
        self.assertIn("事务ID: TX-", r.stdout)

        rules = self._read_waiver_rules()
        self.assertEqual(len(rules["rules"]), 3)

        manual_rule = [r for r in rules["rules"] if r["source"] == "manual"]
        self.assertEqual(len(manual_rule), 1)

        batch_rules = [r for r in rules["rules"] if r["source"] == "batch_import"]
        self.assertEqual(len(batch_rules), 2)
        for br in batch_rules:
            self.assertIsNotNone(br.get("transaction_id"))

    def test_rollback_preserves_manual_rules(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "手工规则应保留",
            "--path-prefix", "data/manual_keep/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "rollback_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "rollback_rule",
                    "path_prefix": "data/rollback/",
                    "reason": "将被回滚的规则",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        rules_before = self._read_waiver_rules()
        self.assertEqual(len(rules_before["rules"]), 2)

        r = run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            "--yes",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"rollback failed: {r.stderr}")
        self.assertIn("保留手工规则数: 1", r.stdout)
        self.assertIn("移除导入规则数: 1", r.stdout)

        rules_after = self._read_waiver_rules()
        self.assertEqual(len(rules_after["rules"]), 1)
        self.assertEqual(rules_after["rules"][0]["path_prefix"], "data/manual_keep/")
        self.assertEqual(rules_after["rules"][0]["source"], "manual")

    def test_rollback_requires_confirmation(self):
        export_path = os.path.join(self.tmp_dir, "noconfirm_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "noconfirm",
                    "path_prefix": "data/noconfirm/",
                    "reason": "测试规则",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "缺少--yes应被拒绝")
        self.assertIn("--yes", r.stdout)

    def test_no_transaction_rollback_fails(self):
        r = run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            "--yes",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "无事务时回滚应失败")
        self.assertIn("没有可回滚", r.stderr)

    def test_transactions_list_shows_history(self):
        export_path = os.path.join(self.tmp_dir, "tx_list.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "txlist",
                    "path_prefix": "data/txlist/",
                    "reason": "事务列表测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "transactions",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("导入事务历史", r.stdout)
        self.assertIn("committed", r.stdout)
        self.assertIn("importer", r.stdout)


class TestWaiverReplaceModeProtection(WaiverTestBase):
    def test_replace_blocks_when_manual_rules_exist(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "手工规则",
            "--path-prefix", "data/manual/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "replace_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "replace_rule",
                    "path_prefix": "data/replace/",
                    "reason": "替换模式测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "replacer",
            "--mode", "replace",
            extra_env=self.extra_env,
        )
        self.assertNotEqual(r.returncode, 0, "有手工规则时replace应被拒绝")
        self.assertIn("--replace-confirm-manual-delete", r.stderr)

        rules = self._read_waiver_rules()
        self.assertEqual(len(rules["rules"]), 1, "手工规则应保留")

    def test_replace_with_confirm_succeeds(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "将被替换的手工规则",
            "--path-prefix", "data/to_be_replaced/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "replace_confirm.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "replace_ok",
                    "path_prefix": "data/ok/",
                    "reason": "确认替换测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "replacer",
            "--mode", "replace",
            "--replace-confirm-manual-delete",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0, f"confirm后replace应成功: {r.stderr}")

        rules = self._read_waiver_rules()
        self.assertEqual(len(rules["rules"]), 1)
        self.assertEqual(rules["rules"][0]["id"], "replace_ok")


class TestWaiverListShowsSource(WaiverTestBase):
    def test_list_shows_source_and_transaction(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "手工规则",
            "--path-prefix", "data/manual_src/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "src_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "batch_src",
                    "path_prefix": "data/batch_src/",
                    "reason": "批量导入规则",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "list",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("[手工]", r.stdout)
        self.assertIn("[批量导入]", r.stdout)
        self.assertIn("来源: manual", r.stdout)
        self.assertIn("来源: batch_import", r.stdout)
        self.assertIn("事务ID: TX-", r.stdout)

    def test_list_show_log_includes_rollback(self):
        export_path = os.path.join(self.tmp_dir, "log_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "log_test",
                    "path_prefix": "data/log_test/",
                    "reason": "日志测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            "--yes",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "list", "--show-log",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("导入规则", r.stdout)
        self.assertIn("回滚导入", r.stdout)


class TestWaiverExportIncludesSource(WaiverTestBase):
    def test_export_includes_source_and_transaction(self):
        export_path = os.path.join(self.tmp_dir, "export_src.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "export_src",
                    "path_prefix": "data/export_src/",
                    "reason": "导出测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )

        re_export_path = os.path.join(self.tmp_dir, "re_export.json")
        run_cli(
            "waiver", "export", re_export_path,
            "--actor", "exporter",
            extra_env=self.extra_env,
        )

        with open(re_export_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(len(data["rules"]), 1)
        self.assertEqual(data["rules"][0]["source"], "batch_import")
        self.assertIsNotNone(data["rules"][0].get("transaction_id"))


class TestWaiverPersistenceAcrossRestartsNew(WaiverTestBase):
    def test_transactions_persist_across_restart(self):
        export_path = os.path.join(self.tmp_dir, "persist_tx.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "persist_tx",
                    "path_prefix": "data/persist_tx/",
                    "reason": "事务持久化测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli(
            "waiver", "transactions",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("committed", r.stdout)

        store2 = WaiverStore(
            rules_path=os.path.join(self.config_dir, "waiver_rules.json"),
            log_path=os.path.join(self.config_dir, "waiver_audit_log.json"),
            transactions_path=os.path.join(self.config_dir, "waiver_transactions.json"),
        )
        tx2 = store2.get_last_committed_transaction()
        self.assertIsNotNone(tx2)
        self.assertEqual(tx2.status.value, "committed")
        self.assertEqual(tx2.actor, "importer")

    def test_rollback_works_after_restart(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "重启后应保留",
            "--path-prefix", "data/restart_keep/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "restart_rb.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "restart_rb",
                    "path_prefix": "data/restart_rb/",
                    "reason": "重启后回滚测试",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )

        rules_before = self._read_waiver_rules()
        self.assertEqual(len(rules_before["rules"]), 2)

        r = run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            "--yes",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("保留手工规则数: 1", r.stdout)

        rules_after = self._read_waiver_rules()
        self.assertEqual(len(rules_after["rules"]), 1)
        self.assertEqual(rules_after["rules"][0]["path_prefix"], "data/restart_keep/")


class TestWaiverFullWorkflow(WaiverTestBase):
    def test_full_dry_run_import_rollback_workflow(self):
        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "全程测试手工规则",
            "--path-prefix", "data/full_manual/",
            extra_env=self.extra_env,
        )

        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "冲突规则",
            "--path-prefix", "data/conflict/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "full_workflow.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "full_new",
                    "path_prefix": "data/full_new/",
                    "reason": "全新规则",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
                {
                    "id": "full_conflict",
                    "path_prefix": "data/conflict/sub/",
                    "reason": "冲突规则",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            "--dry-run",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("新增规则: 1", r.stdout)
        self.assertIn("冲突/风险 (跳过): 1", r.stdout)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("成功添加: 1", r.stdout)
        self.assertIn("跳过 (冲突/风险): 1", r.stdout)

        rules_after_import = self._read_waiver_rules()
        self.assertEqual(len(rules_after_import["rules"]), 3)

        r = run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            "--yes",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("移除导入规则数: 1", r.stdout)
        self.assertIn("保留手工规则数: 2", r.stdout)

        rules_after_rollback = self._read_waiver_rules()
        self.assertEqual(len(rules_after_rollback["rules"]), 2)
        for r in rules_after_rollback["rules"]:
            self.assertEqual(r["source"], "manual")

        r = run_cli(
            "waiver", "transactions",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("rolled_back", r.stdout)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("成功添加: 1", r.stdout)

        rules_final = self._read_waiver_rules()
        self.assertEqual(len(rules_final["rules"]), 3)


class TestWaiverSafeEncodingOutput(WaiverTestBase):
    def test_dry_run_output_has_no_emoji_and_uses_ascii_status(self):
        export_path = os.path.join(self.tmp_dir, "enc_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "enc1",
                    "path_prefix": "data/enc/",
                    "reason": "encoding test",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("[OK]", r.stdout)
        self.assertIn("预演通过", r.stdout)
        for ch in ["✅", "❌", "↩️", "⏳", "🎉", "💡"]:
            self.assertNotIn(ch, r.stdout, f"输出不应包含 emoji: {ch}")

    def test_transactions_output_has_no_emoji(self):
        export_path = os.path.join(self.tmp_dir, "tx_enc.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": "tx_enc_1",
                    "path_prefix": "data/enc_tx/",
                    "reason": "enc tx test",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "transactions",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("[COMMITTED]", r.stdout)
        for ch in ["✅", "❌", "↩️", "⏳"]:
            self.assertNotIn(ch, r.stdout, f"事务输出不应包含 emoji: {ch}")

    def test_gbk_friendly_output_does_not_crash(self):
        export_path = os.path.join(self.tmp_dir, "gbk_test.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "测试者",
            "rules": [
                {
                    "id": "gbk_1",
                    "path_prefix": "data/中文路径/",
                    "reason": "中文理由测试",
                    "actor": "操作人",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        env = dict(self.extra_env)
        env["PYTHONIOENCODING"] = "ascii"
        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "测试人",
            "--dry-run",
            extra_env=env,
        )
        self.assertEqual(r.returncode, 0, f"ASCII 编码下不应崩溃: stderr={r.stderr}")


class TestWaiverAffectedBatchAnalysis(WaiverTestBase):
    def setUp(self):
        super().setUp()
        self._setup_batch()

    def test_dry_run_with_backup_dir_shows_affected_batches(self):
        export_path = os.path.join(self.tmp_dir, "affect.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "aff_hash",
                    "issue_type": "bad_checksum",
                    "reason": "ignore hash issue",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            "--dry-run",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("受影响批次", r.stdout)

    def test_import_stores_affected_batches_in_transaction(self):
        export_path = os.path.join(self.tmp_dir, "txaffect.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "tx_aff_1",
                    "issue_type": "bad_checksum",
                    "reason": "order rule",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("波及批次", r.stdout)

        tx_path = os.path.join(self.config_dir, "waiver_transactions.json")
        with open(tx_path, "r", encoding="utf-8") as f:
            txs_raw = json.load(f)
        txs = txs_raw.get("transactions", []) if isinstance(txs_raw, dict) else txs_raw
        self.assertTrue(len(txs) >= 1)
        last_tx = txs[-1]
        self.assertIn("affected_batches", last_tx)
        self.assertIsInstance(last_tx["affected_batches"], list)
        self.assertTrue(len(last_tx["affected_batches"]) >= 1)

    def test_transactions_shows_affected_batches(self):
        export_path = os.path.join(self.tmp_dir, "txshow.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "showaff",
                    "issue_type": "bad_checksum",
                    "reason": "pay rule",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "transactions",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("波及批次", r.stdout)


class TestWaiverHelpConsistency(WaiverTestBase):
    def test_waiver_import_help_mentions_dry_run_and_backup_dir(self):
        r = run_cli("waiver", "import", "--help", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--dry-run", r.stdout)
        self.assertIn("--backup-dir", r.stdout)
        self.assertIn("受影响批次", r.stdout)

    def test_waiver_rollback_help_has_backup_dir(self):
        r = run_cli("waiver", "rollback", "--help", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--backup-dir", r.stdout)
        self.assertIn("--yes", r.stdout)

    def test_waiver_transactions_help_has_backup_dir(self):
        r = run_cli("waiver", "transactions", "--help", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--backup-dir", r.stdout)

    def test_import_rollback_output_mentions_yes_flag(self):
        export_path = os.path.join(self.tmp_dir, "helpcheck.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "hchk1",
                    "path_prefix": "data/hchk/",
                    "reason": "help check",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("--yes", r.stdout)


class TestWaiverFullWorkflowWithBatches(WaiverTestBase):
    def test_full_workflow_with_batch_impact_analysis(self):
        self._setup_batch()

        run_cli(
            "waiver", "add",
            "--actor", "manual_user",
            "--reason", "batch workflow test manual",
            "--path-prefix", "data/manual_batch/",
            extra_env=self.extra_env,
        )

        export_path = os.path.join(self.tmp_dir, "batchwf.json")
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "importer",
            "rules": [
                {
                    "id": "wf_pay_new",
                    "issue_type": "bad_checksum",
                    "reason": "ignore bad checksum",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
                {
                    "id": "wf_conflict",
                    "path_prefix": "data/manual_batch/sub/",
                    "reason": "conflict test",
                    "actor": "importer",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            "--dry-run",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("新增规则: 1", r.stdout)
        self.assertIn("冲突/风险 (跳过): 1", r.stdout)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "importer",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("波及批次", r.stdout)

        rules = self._read_waiver_rules()
        self.assertEqual(len(rules["rules"]), 2)

        r = run_cli(
            "waiver", "rollback",
            "--actor", "rollbacker",
            "--yes",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("导入时波及批次", r.stdout)

        r = run_cli(
            "waiver", "transactions",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("波及批次", r.stdout)
        self.assertIn("[ROLLED_BACK]", r.stdout)

        rules_rb = self._read_waiver_rules()
        self.assertEqual(len(rules_rb["rules"]), 1)
        self.assertEqual(rules_rb["rules"][0]["source"], "manual")

        store2 = WaiverStore(
            rules_path=os.path.join(self.config_dir, "waiver_rules.json"),
            log_path=os.path.join(self.config_dir, "waiver_audit_log.json"),
            transactions_path=os.path.join(self.config_dir, "waiver_transactions.json"),
        )
        txs_after = store2.list_transactions(limit=5)
        self.assertEqual(txs_after[0].status.value, "rolled_back")
        self.assertIsNotNone(txs_after[0].affected_batches)

        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "reimporter",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        rules_final = self._read_waiver_rules()
        self.assertEqual(len(rules_final["rules"]), 2)


class TestWaiverSnapshotBasic(WaiverTestBase):
    def _make_import_file(self, name: str, rule_id: str = "snap_rule_1",
                          issue_type: str = "bad_checksum") -> str:
        export_path = os.path.join(self.tmp_dir, name)
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": rule_id,
                    "issue_type": issue_type,
                    "reason": "snapshot test rule",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)
        return export_path

    def test_dry_run_creates_snapshot(self):
        self._setup_batch()
        export_path = self._make_import_file("snap_dry.json", "snap_dry_1")
        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "test_snap",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("预演通过", r.stdout)

        r2 = run_cli("waiver", "snapshot", "list", extra_env=self.extra_env)
        self.assertEqual(r2.returncode, 0)
        self.assertIn("test_snap", r2.stdout)

        r3 = run_cli("waiver", "snapshot", "show", "test_snap", extra_env=self.extra_env)
        self.assertEqual(r3.returncode, 0)
        self.assertIn("waiver import --dry-run", r3.stdout)
        self.assertIn("[OK]", r3.stdout)

    def test_import_and_rollback_append_to_snapshot(self):
        self._setup_batch()
        export_path = self._make_import_file("snap_imp.json", "snap_imp_1")
        r = run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "multi_step",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli(
            "waiver", "rollback",
            "--actor", "tester",
            "--yes",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "multi_step",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)

        r = run_cli("waiver", "snapshot", "show", "multi_step", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("waiver import", r.stdout)
        self.assertIn("waiver rollback", r.stdout)

    def test_duplicate_snapshot_name_blocked(self):
        self._setup_batch()
        export_path = self._make_import_file("snap_dup.json", "snap_dup_1")
        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            "--snapshot", "dup_name",
            extra_env=self.extra_env,
        )
        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--dry-run",
            "--snapshot", "dup_name",
            extra_env=self.extra_env,
        )

        r = run_cli("waiver", "snapshot", "show", "dup_name", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        lines = r.stdout.strip().split("\n")
        import_lines = [l for l in lines if "waiver import --dry-run" in l]
        self.assertEqual(len(import_lines), 2)

    def test_snapshot_export_markdown(self):
        self._setup_batch()
        export_path = self._make_import_file("snap_exp.json", "snap_exp_1")
        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "export_test",
            extra_env=self.extra_env,
        )

        md_path = os.path.join(self.tmp_dir, "export_test.md")
        r = run_cli(
            "waiver", "snapshot", "export", "export_test",
            "--format", "markdown",
            "--output", md_path,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue(os.path.exists(md_path))
        with open(md_path, "r", encoding="utf-8") as f:
            md = f.read()
        self.assertIn("# 操作快照: export_test", md)
        self.assertIn("waiver import", md)

    def test_snapshot_export_json(self):
        self._setup_batch()
        export_path = self._make_import_file("snap_expj.json", "snap_expj_1")
        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--snapshot", "json_test",
            extra_env=self.extra_env,
        )

        json_path = os.path.join(self.tmp_dir, "json_test.json")
        r = run_cli(
            "waiver", "snapshot", "export", "json_test",
            "--format", "json",
            "--output", json_path,
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["name"], "json_test")
        self.assertTrue(len(data["records"]) >= 1)
        self.assertIn("transaction_id", data["records"][0])


class TestWaiverSnapshotValidation(WaiverTestBase):
    def _make_import_file(self, name: str, rule_id: str) -> str:
        export_path = os.path.join(self.tmp_dir, name)
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": rule_id,
                    "issue_type": "bad_checksum",
                    "reason": "validation test",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)
        return export_path

    def test_validate_detects_rolled_back_transaction(self):
        self._setup_batch()
        export_path = self._make_import_file("val_rb.json", "val_rb_1")
        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "validate_test",
            extra_env=self.extra_env,
        )
        run_cli(
            "waiver", "rollback",
            "--actor", "tester",
            "--yes",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )

        export_path2 = self._make_import_file("val_rb2.json", "val_rb_2")
        run_cli(
            "waiver", "import", export_path2,
            "--actor", "tester",
            "--backup-dir", self.tmp_dir,
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "snapshot", "show", "validate_test",
            "--validate",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("校验警告", r.stdout)

    def test_validate_passed_when_consistent(self):
        self._setup_batch()
        export_path = self._make_import_file("val_ok.json", "val_ok_1")
        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--snapshot", "valid_snap",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "snapshot", "show", "valid_snap",
            "--validate",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("校验通过", r.stdout)

    def test_failed_command_gap_warning(self):
        self._setup_batch()
        bad_path = os.path.join(self.tmp_dir, "nonexistent.json")
        with open(bad_path, "w", encoding="utf-8") as f:
            f.write("not json")

        run_cli(
            "waiver", "import", bad_path,
            "--actor", "tester",
            "--snapshot", "fail_snap",
            extra_env=self.extra_env,
        )

        r = run_cli(
            "waiver", "snapshot", "show", "fail_snap",
            "--validate",
            extra_env=self.extra_env,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("[FAIL]", r.stdout)


class TestWaiverSnapshotPersistence(WaiverTestBase):
    def _make_import_file(self, name: str, rule_id: str) -> str:
        export_path = os.path.join(self.tmp_dir, name)
        test_rules = {
            "exported_at": "2026-06-16T00:00:00",
            "exported_by": "tester",
            "rules": [
                {
                    "id": rule_id,
                    "issue_type": "bad_checksum",
                    "reason": "persistence test",
                    "actor": "tester",
                    "created_at": "2026-06-16T00:00:00",
                    "active": True,
                },
            ],
        }
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(test_rules, f)
        return export_path

    def test_snapshot_survives_restart(self):
        self._setup_batch()
        export_path = self._make_import_file("persist1.json", "persist_1")

        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "restart_test",
            extra_env=self.extra_env,
        )

        r = run_cli("waiver", "snapshot", "show", "restart_test", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("waiver import", r.stdout)

        export_path2 = self._make_import_file("persist2.json", "persist_2")
        run_cli(
            "waiver", "import", export_path2,
            "--actor", "tester2",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "restart_test",
            extra_env=self.extra_env,
        )

        r = run_cli("waiver", "snapshot", "show", "restart_test", extra_env=self.extra_env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("记录条数: 2", r.stdout)

    def test_snapshot_consistent_with_transactions(self):
        self._setup_batch()
        export_path = self._make_import_file("consist.json", "consist_1")

        run_cli(
            "waiver", "import", export_path,
            "--actor", "tester",
            "--backup-dir", self.tmp_dir,
            "--snapshot", "consist_test",
            extra_env=self.extra_env,
        )

        r_tx = run_cli("waiver", "transactions", extra_env=self.extra_env)
        self.assertEqual(r_tx.returncode, 0)
        self.assertIn("COMMITTED", r_tx.stdout)

        r_snap = run_cli("waiver", "snapshot", "show", "consist_test", extra_env=self.extra_env)
        self.assertEqual(r_snap.returncode, 0)

        snap_dir = os.path.join(self.config_dir, "waiver_snapshots")
        snap_file = os.path.join(snap_dir, "consist_test.json")
        self.assertTrue(os.path.exists(snap_file))
        with open(snap_file, "r", encoding="utf-8") as f:
            snap_data = json.load(f)
        tx_ids_in_snap = [r["transaction_id"] for r in snap_data["records"] if r.get("transaction_id")]
        self.assertTrue(len(tx_ids_in_snap) >= 1)

        tx_path = os.path.join(self.config_dir, "waiver_transactions.json")
        with open(tx_path, "r", encoding="utf-8") as f:
            tx_data = json.load(f)
        tx_ids_in_tx = [t["id"] for t in tx_data.get("transactions", [])]
        for tid in tx_ids_in_snap:
            self.assertIn(tid, tx_ids_in_tx)


if __name__ == "__main__":
    unittest.main()
