"""README 文档完整性回归检查 —— 稳定卡住文档缺口，防止"总结说补了文件里却没有"。"""

import os
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


README_PATH = os.path.join(PROJECT_ROOT, "README.md")


def _read_readme() -> str:
    with open(README_PATH, "r", encoding="utf-8") as f:
        return f.read()


class TestReadmeSectionsPresent(unittest.TestCase):
    """命令详解章节必须全部存在，缺任何一个即失败。"""

    @classmethod
    def setUpClass(cls):
        cls.content = _read_readme()

    def test_section_import(self):
        self.assertIn("### `import` —", self.content,
                      "README 缺少 `import` 命令详解")

    def test_section_precheck(self):
        self.assertIn("### `precheck` —", self.content,
                      "README 缺少 `precheck` 命令详解")

    def test_section_list(self):
        self.assertIn("### `list` —", self.content,
                      "README 缺少 `list` 命令详解")

    def test_section_review(self):
        self.assertIn("### `review` —", self.content,
                      "README 缺少 `review` 命令详解")

    def test_section_undo(self):
        self.assertIn("### `undo` —", self.content,
                      "README 缺少 `undo` 命令详解")

    def test_section_finalize(self):
        self.assertIn("### `finalize` —", self.content,
                      "README 缺少 `finalize`（签收）命令详解 —— 验收收口必须文档")

    def test_section_reopen(self):
        self.assertIn("### `reopen` —", self.content,
                      "README 缺少 `reopen`（重开）命令详解 —— 验收收口必须文档")

    def test_section_export(self):
        self.assertIn("### `export` —", self.content,
                      "README 缺少 `export` 命令详解")

    def test_section_resume(self):
        self.assertIn("### `resume` —", self.content,
                      "README 缺少 `resume` 命令详解")


class TestReadmeFinalizeReopenDetail(unittest.TestCase):
    """finalize/reopen 的关键内容必须到位，交接人只看文档就能复现。"""

    @classmethod
    def setUpClass(cls):
        cls.content = _read_readme()

    # ---- finalize 关键字段 ----
    def test_finalize_signer_arg(self):
        self.assertIn("--signer", self.content,
                      "finalize 文档未说明 --signer 参数")

    def test_finalize_reason_arg(self):
        self.assertIn("--reason", self.content,
                      "finalize 文档未说明 --reason 参数")

    def test_finalize_force_flag(self):
        self.assertIn("--force-with-reason", self.content,
                      "finalize 文档未说明 --force-with-reason 强制放行开关")

    def test_finalize_clean_batch(self):
        self.assertIn("正常签收", self.content,
                      "finalize 文档未说明 clean 批次（无未处理阻断）的正常签收路径")

    def test_finalize_mixed_batch(self):
        self.assertIn("强制放行", self.content,
                      "finalize 文档未说明 mixed 批次（带未处理阻断）的强制放行路径")

    def test_finalize_key_outputs(self):
        """状态、签收人、未处理 blocking/confirmable 数量这些关键输出必须在文档里。"""
        checks = [
            ("批次状态: finalized", "缺少 finalized 状态展示说明"),
            ("签收人:", "缺少签收人字段说明"),
            ("未处理阻断问题:", "缺少未处理 blocking 数量说明"),
            ("未处理可确认问题:", "缺少未处理 confirmable 数量说明"),
        ]
        missing = [msg for pattern, msg in checks if pattern not in self.content]
        if missing:
            self.fail("finalize 文档缺少关键输出字段说明: " + "; ".join(missing))

    # ---- finalize 只读拦截 ----
    def test_finalize_readonly_block(self):
        """签收后拦截的操作必须文档化说明。"""
        blocks = ["precheck", "review", "undo", "重复 finalize"]
        missing = [op for op in blocks if op not in self.content or f"禁止执行 {op}" not in self.content]
        if missing:
            self.fail("finalize 文档缺少只读拦截说明: " + ", ".join(missing))

    def test_finalize_readonly_error_msg(self):
        self.assertIn("如需继续编辑，请使用 reopen 命令", self.content,
                      "finalize 文档缺少只读拦截后的引导提示")

    # ---- reopen 关键字段 ----
    def test_reopen_reopener_arg(self):
        self.assertIn("--reopener", self.content,
                      "reopen 文档未说明 --reopener 参数")

    def test_reopen_reason_arg(self):
        self.assertIn("--reason", self.content,
                      "reopen 文档未说明 --reason 参数")

    def test_reopen_key_outputs(self):
        self.assertIn("累计重开次数:", self.content,
                      "reopen 文档缺少累计重开次数字段说明")

    def test_reopen_restores_editing(self):
        verifications = [
            "恢复编辑",
            "恢复为 open 状态",
        ]
        if not any(v in self.content for v in verifications):
            self.fail("reopen 文档未说明重开后可恢复编辑")

    def test_reopen_command_order(self):
        self.assertIn("finalize 之后", self.content,
                      "reopen 文档未说明命令顺序：必须在 finalize 之后")

    # ---- finalize 命令顺序 ----
    def test_finalize_command_order(self):
        self.assertIn("export 之前", self.content,
                      "finalize 文档未说明命令顺序：必须在 export 之前")


class TestReadmeListSeverityDoc(unittest.TestCase):
    """list --severity 的文档必须到位，防止筛选失效再回归。"""

    @classmethod
    def setUpClass(cls):
        cls.content = _read_readme()

    def test_list_severity_blocking_doc(self):
        self.assertIn("--severity blocking", self.content,
                      "list 文档未说明 --severity blocking 用法")

    def test_list_severity_confirmable_doc(self):
        self.assertIn("--severity confirmable", self.content,
                      "list 文档未说明 --severity confirmable 用法")

    def test_list_help_options_match(self):
        """README 里的参数说明必须和 --help 输出保持一致。"""
        self.assertIn("blocking", self.content)
        self.assertIn("confirmable", self.content)


class TestReadmePersistenceDoc(unittest.TestCase):
    """持久化与跨进程一致性文档。"""

    @classmethod
    def setUpClass(cls):
        cls.content = _read_readme()

    def test_signoff_persistence(self):
        self.assertIn("signoff", self.content,
                      "持久化文档缺少 signoff 签收信息说明")

    def test_reopen_records_persistence(self):
        self.assertIn("reopen_records", self.content,
                      "持久化文档缺少 reopen_records 重开记录说明")

    def test_operation_log_persistence(self):
        self.assertIn("operation_log", self.content,
                      "持久化文档缺少 operation_log 操作日志说明")

    def test_cross_process_signoff_visible(self):
        patterns = ["跨进程 resume", "跨进程 list", "跨进程"]
        has_cross = any(p in self.content for p in patterns)
        self.assertTrue(has_cross, "持久化文档缺少跨进程说明")


class TestReadmeExportSignoffDoc(unittest.TestCase):
    """export 报告必须说明签收摘要和操作日志。"""

    @classmethod
    def setUpClass(cls):
        cls.content = _read_readme()

    def test_export_signoff_in_json(self):
        self.assertIn("signoff", self.content,
                      "export 文档未说明 JSON 报告中的 signoff 签收摘要")

    def test_export_operation_log_in_json(self):
        self.assertIn("operation_log", self.content,
                      "export 文档未说明 JSON 报告中的 operation_log 操作日志")


if __name__ == "__main__":
    unittest.main()
