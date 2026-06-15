"""Build complete README.md with all sections.

Reads the current minimal README and augments with all the missing sections:
- finalize command docs (clean/mixed, readonly block, exit codes)
- reopen command docs (restore editing, reopen count, workflow)
- export signoff/operation_log/reopen_records fields
- resume 3 scenarios
- persistence field table + cross-process examples
- test coverage table with signoff/filter tests
- project structure with test_readme_doc.py
"""
import os

PROJECT = os.path.dirname(os.path.abspath(__file__))
README = os.path.join(PROJECT, "README.md")

FINALIZE_SECTION = r"""
### `finalize` — 签收批次（验收收口，export 之前执行）

```bash
python backup_audit_cli.py finalize <备份包目录> --signer SIGNER --reason REASON [--force-with-reason] [--batch-id ID]
```

- **必须在 export 之前执行**：签收后 export 的报告才会带上 signoff/reopen_records/operation_log
- **命令顺序**：`import → precheck → list/review/undo → finalize → export → resume`
- **默认规则**：未处理 blocking 问题数 = 0 才能签收（`正常签收`）
- **强制放行**：有未处理 blocking 时必须显式传 `--force-with-reason` 并同时提供 `--reason`，否则被拒绝（退出码 5）
- **参数说明**：

| 参数 | 必填 | 说明 |
|------|------|------|
| `--signer` | ✅ | 签收人（记录到 signoff.signer 和操作日志） |
| `--reason` | ✅ | 签收理由；强制放行时必须写清审批来源和依据 |
| `--force-with-reason` | ❌ | 强制放行开关：即使有未处理 blocking 也签收 |

**批次类型对比：**

| 批次类型 | 未处理 blocking | 是否需要 --force-with-reason | 签收后显示 |
|---------|-----------------|---------------------------|-----------|
| **clean 批次** | = 0 | 不需要 | `批次状态: finalized` + `签收状态: 正常签收` |
| **mixed 批次** | ≥ 1 | **必须传**，否则退出码 5 | `批次状态: finalized` + `签收状态: 强制放行` + `[!] 未处理阻断问题: N 个` |

**clean 批次（无未处理 blocking）正常签收：**

```bash
# 正常签收：未处理 blocking = 0，不需要 force
python backup_audit_cli.py finalize sample_backup_clean --signer wangwu --reason "所有校验通过，未处理问题数为 0，可归档"
```

```
批次已签收: TEST-001
  状态: 正常签收
  签收人: wangwu
  签收理由: 所有校验通过，未处理问题数为 0，可归档
  签收时间: 2026-06-16T03:49:42.147040
  未处理可确认问题: 1 个

批次 ID: TEST-001
批次状态: finalized
签收状态: 正常签收
签收人: wangwu
签收时间: 2026-06-16T03:49:42.147040
未处理可确认问题: 1 个
备份目录: /path/to/backup_clean
Manifest: /path/to/manifest.json

=== 概要 ===
  问题总数:    1
  阻断问题:    0 (必须修复)
  可确认问题:  1 (人工确认)
  未处理阻断:  0
  未处理可确认:1
...
```

**mixed 批次（有未处理 blocking）不带 force 被拒绝：**

```bash
# 未处理 blocking = 3，不带 force → 拒绝（退出码 5）
python backup_audit_cli.py finalize sample_backup --signer wangwu --reason "误尝试无 force 签收"
```

```
错误: 存在 3 个未处理的阻断问题，不能签收。
请先处理所有阻断问题，或使用 --force-with-reason 强制放行（需同时提供 --reason）。
```

**关键输出：** `退出码 = 5`，`存在 N 个未处理的阻断问题`

**mixed 批次（有未处理 blocking）强制放行：**

```bash
# 未处理 blocking = 1，显式传 --force-with-reason 并写清审批理由
python backup_audit_cli.py finalize sample_backup --signer dept_manager \
  --reason "经 2024-Q2 备份风险评审会审批，剩余 1 条 SHA 不匹配可追溯到源端已知故障，特批放行" \
  --force-with-reason
```

```
批次已签收: BATCH-2024-001
  状态: 强制放行
  签收人: dept_manager
  签收理由: 经 2024-Q2 备份风险评审会审批，剩余 1 条 SHA 不匹配可追溯到源端已知故障，特批放行
  签收时间: 2026-06-16T03:49:44.841083
  [!] 未处理阻断问题: 1 个
  未处理可确认问题: 3 个

批次 ID: BATCH-2024-001
批次状态: finalized
签收状态: 强制放行
签收人: dept_manager
签收时间: 2026-06-16T03:49:44.841083
[!] 未处理阻断问题: 1 个
未处理可确认问题: 3 个
...
```

**关键输出：** `批次状态: finalized`、`签收状态: 强制放行`、`签收人: dept_manager`、`[!] 未处理阻断问题: 1 个`、`未处理可确认问题: 3 个`

**签收后：只读拦截（禁止执行 precheck / review / undo / 重复 finalize）：**

签收后批次进入 `finalized` 状态，**禁止执行 precheck**、**禁止执行 review**、**禁止执行 undo**、**禁止重复 finalize**；所有写操作统一返回退出码 3（重复签收返回退出码 4）。

```bash
# 签收后再跑 precheck → 拦截（退出码 3）
python backup_audit_cli.py precheck sample_backup
```

```
错误: 批次已签收，禁止执行 precheck 操作。
  签收人: dept_manager
  签收时间: 2026-06-16T03:49:44.841083
如需继续编辑，请使用 reopen 命令。
```

```bash
# 签收后再跑 review → 拦截（退出码 3）
python backup_audit_cli.py review sample_backup 79ddd6fc0c30 --status confirmed
```

```
错误: 批次已签收，禁止执行 review 操作。
  签收人: dept_manager
  签收时间: 2026-06-16T03:49:44.841083
如需继续编辑，请使用 reopen 命令。
```

```bash
# 签收后再跑 undo → 拦截（退出码 3）
python backup_audit_cli.py undo sample_backup
```

```
错误: 批次已签收，禁止执行 undo 操作。
  签收人: wangwu
  签收时间: 2026-06-16T03:49:42.147040
如需继续编辑，请使用 reopen 命令。
```

```bash
# 重复 finalize → 拦截（退出码 4）
python backup_audit_cli.py finalize sample_backup_clean --signer other --reason "重复签收测试"
```

```
错误: 批次已签收，不能重复签收。
  签收人: wangwu
  签收时间: 2026-06-16T03:49:42.147040
如需重新签收，请先使用 reopen 命令。
```

**退出码约定（签收相关）：**

| 退出码 | 含义 |
|--------|------|
| 0 | 签收成功（正常签收 / 强制放行） |
| 3 | 只读拦截（批次已 finalized，禁止写操作） |
| 4 | 重复签收 |
| 5 | 阻断问题未处理且未传 --force-with-reason |
"""

REOPEN_SECTION = r"""
### `reopen` — 重开已签收批次（恢复编辑，finalize 之后执行）

```bash
python backup_audit_cli.py reopen <备份包目录> --reopener REOPENER --reason REASON [--batch-id ID]
```

- **必须在 finalize 之后执行**：只有已 finalized 的批次才能 reopen
- 重开后批次**恢复为 open 状态**，可继续 review / undo / precheck
- 前一次签收信息完整存入 `reopen_records`，不会丢失（export 的 JSON 报告里可见）
- **累计重开次数**写入批次状态，`resume` / `list` 会显示 `重开次数: N`
- **参数说明**：

| 参数 | 必填 | 说明 |
|------|------|------|
| `--reopener` | ✅ | 重开人（记录到 reopen_records 和操作日志） |
| `--reason` | ✅ | 重开理由：说明为什么需要推翻之前的签收 |

**重开成功（恢复编辑）：**

```bash
# 已 finalized 的批次执行 reopen → 恢复为 open，重开次数 +1
python backup_audit_cli.py reopen sample_backup --reopener zhangsan --reason "上轮签收漏处理 1 条 blocking，需补复核"
```

```
批次已重开，恢复编辑: BATCH-2024-001
  重开人: zhangsan
  重开理由: 上轮签收漏处理 1 条 blocking，需补复核
  累计重开次数: 1

批次 ID: BATCH-2024-001
批次状态: open
重开次数: 1
备份目录: /path/to/backup
Manifest: /path/to/manifest.json
...
```

**关键输出：** `累计重开次数: 1`、`批次状态: open`、`重开次数: 1`

**重开规则：**

| 当前状态 | 能否 reopen | 结果 |
|---------|------------|------|
| `finalized`（已签收） | ✅ 可以 | 恢复为 `open`，`重开次数 += 1`，前次签收写入 `reopen_records` |
| `open`（未签收 / 已重开） | ❌ 拒绝 | 报错：`批次未签收，不能重开`（退出码 7） |

**重开后：继续 review → 重新签收（完整循环）：**

```bash
# 1. 重开后恢复编辑，补完最后 1 条 blocking
python backup_audit_cli.py review sample_backup 79ddd6fc0c30 --status confirmed \
  --assignee zhangsan --notes "重开后补充完成复核"

# 2. 现在未处理 blocking = 0 → 正常签收
python backup_audit_cli.py finalize sample_backup --signer dept_manager \
  --reason "所有 blocking 已复核完成，批次可归档"

# 3. resume 看到：重开次数: 1 + 签收状态: 正常签收
python backup_audit_cli.py resume sample_backup
```

```
批次 ID: BATCH-2024-001
批次状态: finalized
签收状态: 正常签收
签收人: dept_manager
签收时间: 2026-06-16T03:49:47.397242
未处理可确认问题: 3 个
重开次数: 1
备份目录: /path/to/backup
...
```

**关键输出：** `重开次数: 1`（保留历次重开历史）、`签收状态: 正常签收`（本次重新签收的结果）
"""

EXPORT_EXTENSION = r"""
- **finalize 之后 export 的报告会多出以下签收相关字段**，交接审计用：

**JSON 报告新增字段（finalize/reopen 之后）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | string | `open` 或 `finalized`，批次当前状态 |
| `signoff` | object | 签收摘要：`signer` 签收人、`reason` 理由、`timestamp` 时间、`forced` 是否强制放行、`unresolved_blocking_count` / `unresolved_confirmable_count` 未处理问题数；未签收时为 `null` |
| `reopen_records` | array | 重开历史：每条包含 `reopener` 重开人、`reason` 理由、`timestamp` 时间、`previous_signoff` 完整保留的上一次签收信息；未重开过为空数组 |
| `operation_log` | array | 完整操作日志：`precheck`/`review`/`undo`/`finalize`/`reopen`/`export` 都有记录，每条含 `action`/`actor`/`reason`/`timestamp`/`detail` |
| `summary.unresolved_blocking` | number | 未处理阻断问题数，和 print_summary 显示一致 |
| `summary.unresolved_confirmable` | number | 未处理可确认问题数，和 print_summary 显示一致 |

**CSV 报告新增段（finalize/reopen 之后）：**
- 批次状态行（第 2 行）
- **签收摘要段**（如已签收）：签收状态、签收人、理由、时间、未处理问题统计
- **重开记录段**（如存在）：每次重开的重开人、理由、时间、前次签收人/时间
- 未处理问题统计行
- **操作日志段**：完整历史操作列表
"""

RESUME_EXTENSION = r"""
- 在新 CLI 进程中恢复之前的工作批次（换个终端/隔天来都可以继续）
- 显示完整批次概要：批次 ID、**当前状态（open / finalized）**、签收人、重开次数、问题数、状态分布、操作日志条数

**预期输出（open 批次 · 重开过 1 次）：**

```
批次 ID: BATCH-2024-001
批次状态: open
重开次数: 1
备份目录: /path/to/backup
Manifest: /path/to/manifest.json

=== 概要 ===
  问题总数:    6
  阻断问题:    3 (必须修复)
  可确认问题:  3 (人工确认)
  未处理阻断:  0
  未处理可确认:3
  按状态:
    confirmed: 3
    open: 3
  已扫描文件:  7/7
  操作日志:    8 条
```

**预期输出（finalized 批次 · 强制放行）：**

```
批次 ID: BATCH-2024-001
批次状态: finalized
签收状态: 强制放行
签收人: dept_manager
签收时间: 2026-06-16T04:02:11.388211
[!] 未处理阻断问题: 1 个
未处理可确认问题: 3 个
备份目录: /path/to/backup
Manifest: /path/to/manifest.json

=== 概要 ===
  问题总数:    6
  阻断问题:    3 (必须修复)
  可确认问题:  3 (人工确认)
  未处理阻断:  1
  未处理可确认:3
  按状态:
    confirmed: 2
    open: 4
  已扫描文件:  7/7
  操作日志:    5 条
```

**预期输出（finalized 批次 · 正常签收 clean 批次）：**

```
批次 ID: BATCH-2024-001
批次状态: finalized
签收状态: 正常签收
签收人: wangwu
签收时间: 2026-06-16T03:45:29.244668
未处理可确认问题: 1 个
备份目录: /path/to/backup_clean
Manifest: /path/to/manifest.json

=== 概要 ===
  问题总数:    1
  阻断问题:    0 (必须修复)
  可确认问题:  1 (人工确认)
  未处理阻断:  0
  未处理可确认:1
  按状态:
    open: 1
  已扫描文件:  3/3
  操作日志:    2 条
```
"""

PERSISTENCE_EXTENSION = r"""
- **签收 / 重开 / 操作日志的持久化字段**（跨进程 resume/list/export 都能看到）：

| 字段 | 类型 | 说明 | 出现在哪些命令 |
|------|------|------|--------------|
| `status` | string | `open` / `finalized` | `resume`、`list`、`export` 报告 |
| `signoff` | object | 当前签收信息（未签收为 null）：signer/reason/timestamp/forced/unresolved_*_count | `resume`、`list`、`export` 报告 |
| `reopen_records` | array | 全部重开历史（每次重开保留前一次签收）：reopener/reason/timestamp/previous_signoff | `export` 报告 |
| `operation_log` | array | 所有关键操作完整历史：precheck/review/undo/finalize/reopen/export | `export` 报告、print_summary 显示条数 |

- 跨进程场景：
  - 终端 A：import → precheck → review → finalize（强制放行）
  - 终端 B（新进程）：`resume` → 看到 `批次状态: finalized`、`签收状态: 强制放行`、`签收人: dept_manager`
  - 终端 B：`list` → 同样看到 finalized 状态、签收信息
  - 终端 B：`export` → JSON/CSV 里有完整 signoff、reopen_records、operation_log
  - 终端 B：`reopen` → 成功恢复编辑，累计重开次数 +1
  - 终端 A（原进程，再跑一次）：`resume` → 看到 `重开次数: 1`，与终端 B 的操作完全一致
"""

TEST_COVERAGE_EXTENSION = r"""
| `TestSignoffBlocking` | 阻断问题未处理禁止签收、强制无理由拒绝、无理由拒绝 |
| `TestForcedSignoff` | 强制放行成功、只读拦截 precheck/review/undo/重复 finalize |
| `TestReopenWorkflow` | 参数校验、恢复编辑、重开记录持久化、重开开放批次拒绝、重新签收 |
| `TestCleanSignoff` | 无阻断批次正常签收 |
| `TestCrossProcessSignoff` | 跨进程 resume/list 显示签收状态、export 包含签收摘要和日志、reopen 历史保留 |
| `TestListSeverityFilter` | blocking/confirmable 筛选正确、组合筛选、帮助说明一致 |
"""

PROJECT_STRUCTURE_EXTENSION = r"""tests/
  test_regression.py   # 回归测试（10个测试类，35个测试用例）
  test_readme_doc.py   # README 文档完整性回归检查
"""


def _read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)
    print(f"Wrote {p}: {len(s)} chars, {len(s.splitlines())} lines")


def main():
    content = _read(README)

    # 1. Insert FINALIZE + REOPEN between undo and export sections
    anchor1 = "### `export` — 导出验收报告"
    if FINALIZE_SECTION.strip() not in content:
        replacement = FINALIZE_SECTION + "\n" + REOPEN_SECTION + "\n" + anchor1
        content = content.replace(anchor1, replacement, 1)
        print(f"[OK] Inserted finalize + reopen sections before '{anchor1}'")
    else:
        print("[SKIP] finalize section already present")

    # 2. Extend export section: after "CSV 报告分两个表格段输出" add signoff fields
    old_export_tail = "- CSV 报告分两个表格段输出\n\n### `resume` —"
    if EXPORT_EXTENSION.strip() not in content:
        new_export_tail = "- CSV 报告分两个表格段输出" + EXPORT_EXTENSION + "\n\n### `resume` —"
        content = content.replace(old_export_tail, new_export_tail, 1)
        print("[OK] Extended export section with signoff fields")
    else:
        print("[SKIP] export signoff fields already present")

    # 3. Extend resume section: replace "- 显示批次概要（问题数、状态分布）" with full description
    old_resume_tail = "- 显示批次概要（问题数、状态分布）\n\n## 持久化与跨进程一致性"
    if RESUME_EXTENSION.strip() not in content:
        new_resume_tail = RESUME_EXTENSION.strip() + "\n\n## 持久化与跨进程一致性"
        content = content.replace(old_resume_tail, new_resume_tail, 1)
        print("[OK] Extended resume section with 3 scenarios")
    else:
        print("[SKIP] resume scenarios already present")

    # 4. Extend persistence section: before "## 运行测试"
    old_persist_tail = "- export 的 JSON/CSV 报告中，问题 ID、状态、备注、处理人与批次状态文件完全一致\n\n## 运行测试"
    if PERSISTENCE_EXTENSION.strip() not in content:
        new_persist_tail = ("- export 的 JSON/CSV 报告中，问题 ID、状态、备注、处理人与批次状态文件完全一致"
                            + PERSISTENCE_EXTENSION + "\n\n## 运行测试")
        content = content.replace(old_persist_tail, new_persist_tail, 1)
        print("[OK] Extended persistence section with field table")
    else:
        print("[SKIP] persistence field table already present")

    # 5. Extend test coverage table
    old_cover_tail = "| `TestCrossProcessExport` | JSON/CSV 报告与 review 状态一致、跨进程 resume |\n\n## 项目结构"
    if TEST_COVERAGE_EXTENSION.strip() not in content:
        new_cover_tail = ("| `TestCrossProcessExport` | JSON/CSV 报告与 review 状态一致、跨进程 resume |\n"
                          + TEST_COVERAGE_EXTENSION + "\n## 项目结构")
        content = content.replace(old_cover_tail, new_cover_tail, 1)
        print("[OK] Extended test coverage table")
    else:
        print("[SKIP] test coverage already extended")

    # 6. Extend project structure: add test_readme_doc.py
    old_struct_tail = "  test_regression.py   # 回归测试（10个测试类，35个测试用例）\ngenerate_samples.py"
    if PROJECT_STRUCTURE_EXTENSION.strip() not in content:
        new_struct_tail = PROJECT_STRUCTURE_EXTENSION.strip() + "\ngenerate_samples.py"
        content = content.replace(old_struct_tail, new_struct_tail, 1)
        print("[OK] Extended project structure with test_readme_doc.py")
    else:
        print("[SKIP] project structure already extended")

    _write(README, content)

    # Verify key markers
    checks = [
        ("### `finalize` —", "finalize section header"),
        ("### `reopen` —", "reopen section header"),
        ("正常签收", "clean batch signoff"),
        ("强制放行", "mixed batch signoff"),
        ("批次状态: finalized", "finalized status display"),
        ("签收人:", "signer field"),
        ("未处理阻断问题:", "unresolved blocking count"),
        ("未处理可确认问题:", "unresolved confirmable count"),
        ("禁止执行 precheck", "readonly precheck block"),
        ("禁止执行 review", "readonly review block"),
        ("禁止执行 undo", "readonly undo block"),
        ("重复 finalize", "repeat signoff mention"),
        ("如需继续编辑，请使用 reopen 命令", "readonly reopen hint"),
        ("累计重开次数:", "reopen count display"),
        ("恢复为 open 状态", "reopen restores open"),
        ("finalize 之后", "reopen requires prior finalize"),
        ("export 之前", "finalize before export"),
        ("signoff", "signoff persistence"),
        ("reopen_records", "reopen_records persistence"),
        ("operation_log", "operation_log persistence"),
    ]
    all_ok = True
    for pattern, name in checks:
        present = pattern in content
        print(f"  [{'✓' if present else '✗'}] {name}: '{pattern}'")
        if not present:
            all_ok = False
    if all_ok:
        print("\n=== ALL DOC CHECKS PASSED ===")
    else:
        print("\n=== SOME DOC CHECKS FAILED ===")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
