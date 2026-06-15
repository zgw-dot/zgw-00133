# 离线备份包验收 CLI (backup-audit)

读取 manifest，校验文件路径、SHA256、大小、备份窗口和业务线，生成批次问题清单；
运维可将问题标记为待补/已确认/忽略，支持撤销复核，导出区分阻断/可确认的报告。

## 快速开始

```bash
# 1. 生成样例备份数据
python generate_samples.py

# 2. 导入 manifest 并创建验收批次
python backup_audit_cli.py import sample_backup/manifest.json sample_backup

# 3. 运行预检（只读，不修改源文件）
python backup_audit_cli.py precheck sample_backup

# 4. 按严重程度筛选问题，方便逐条处理
python backup_audit_cli.py list sample_backup --severity blocking
python backup_audit_cli.py list sample_backup --severity confirmable

# 5. 复核：标记问题状态
python backup_audit_cli.py review sample_backup <问题ID> --status pending_fix --assignee zhangsan --notes "联系运维补传"

# 6. 撤销上一条复核
python backup_audit_cli.py undo sample_backup

# 7. 签收批次（阻断问题必须全部处理，否则需要 --force-with-reason）
python backup_audit_cli.py finalize sample_backup --signer wangwu --reason "所有阻断问题已修复，可确认问题已人工审核"

# 8. 如确需带阻断问题放行，使用强制签收（必须写清理由）
python backup_audit_cli.py finalize sample_backup --signer manager --reason "经风险评估委员会审批，特批该批次带问题放行" --force-with-reason

# 9. 签收后只读，禁止 precheck/review/undo/重复 finalize
# 如需重新编辑，重开已签收批次
python backup_audit_cli.py reopen sample_backup --reopener zhangsan --reason "发现漏处理的阻断问题，需补充复核"

# 10. 导出报告（JSON + CSV，包含签收摘要和操作日志）
python backup_audit_cli.py export sample_backup --output sample_backup/reports

# 11. 新进程恢复已有批次
python backup_audit_cli.py resume sample_backup
```

## 命令详解

### `import` — 导入 manifest 并创建验收批次

```bash
python backup_audit_cli.py import <manifest.json路径> <备份包目录> [--force]
```

- 校验 manifest 中每条文件的 `sha256` 字段（必须为 64 位十六进制）
- 校验 `size` 字段（必须为非负整数）和 `path` 字段（不能为空）
- 格式非法时：列出所有错误行号和字段，**不创建批次，不污染已有状态**
- 如果备份目录已有批次，需 `--force` 覆盖或使用 `resume` 继续

**预期输出（成功）：**

```
批次已导入: BATCH-2024-001
  Manifest: /path/to/manifest.json
  备份目录: /path/to/backup
  Manifest 中的文件数: 7
```

**预期输出（格式错误）：**

```
错误: Manifest 格式校验失败:
  files[1].sha256 (data/short_hash.dat): sha256 必须为 64 位十六进制字符串，当前值: 'abc123'
  files[2].sha256 (data/non_hex.dat): sha256 必须为 64 位十六进制字符串，当前值: 'zzz...'

发现 2 个格式错误，批次未创建。请修正 manifest 后重新导入。
```

### `precheck` — 运行预检

```bash
python backup_audit_cli.py precheck <备份包目录> [--batch-id ID]
```

- 逐项校验：文件路径合法性、文件存在性、SHA256、大小、备份窗口、业务线
- 检测 manifest 中的重复条目
- 检测空撤销列表
- **只读操作，不修改源备份文件**
- 幂等：重复运行不产生重复问题

**问题严重程度：**

| 严重程度 | 含义 | 触发条件 |
|---------|------|---------|
| `blocking` | 阻断问题，必须修复 | 缺失文件、SHA256 不匹配、大小不匹配、路径非法、重复条目 |
| `confirmable` | 可人工确认 | 文件在备份窗口外、未知业务线、空撤销列表 |

**预期输出：**

```
运行预检: 批次 BATCH-2024-001
  (预检不会修改源备份文件)

预检完成:
  新增问题: 6
  累计问题: 6

批次 ID: BATCH-2024-001
...
=== 概要 ===
  问题总数:    6
  阻断问题:    3 (必须修复)
  可确认问题:  3 (人工确认)
```

### `list` — 列出批次问题

```bash
python backup_audit_cli.py list <备份包目录> [--status STATUS] [--severity SEVERITY] [--batch-id ID]
```

- 按严重程度分组显示，区分阻断/可确认
- 可按状态（`open`/`pending_fix`/`confirmed`/`ignored`）或严重程度过滤
- 显示处理人和备注

### `review` — 复核/标记问题状态

```bash
python backup_audit_cli.py review <备份包目录> <问题ID> --status STATUS [--assignee WHO] [--notes NOTE] [--batch-id ID]
```

**状态说明：**

| 状态 | 含义 |
|------|------|
| `pending_fix` | 待补 — 需要补传/修复 |
| `confirmed` | 已确认 — 人工确认可接受 |
| `ignored` | 忽略 — 不影响本次验收 |
| `open` | 重置为开放状态 |

- 每次复核会自动记录快照（状态、处理人、备注），可用于 `undo` 撤销
- 快照持久化到批次文件，跨进程后仍可撤销

### `undo` — 撤销上一条复核

```bash
python backup_audit_cli.py undo <备份包目录> [--batch-id ID]
```

- 恢复最近一条 review 前的状态、处理人和备注
- 可连续撤销多条
- 空撤销时给出提示：`没有可撤销的复核操作（撤销历史为空）。`
- 跨新 CLI 进程后仍可 undo（快照存储在 `.audit_state/batch_*.json` 中）

**预期输出：**

```
已撤销上一条复核: 问题 79ddd6fc0c30
  状态: open
  处理人: (无)
  备注: (无)
  剩余可撤销次数: 0
```

### `export` — 导出验收报告

```bash
python backup_audit_cli.py export <备份包目录> [--format FORMAT] [--output DIR] [--batch-id ID]
```

- `--format`：`json`/`csv`/`all`（默认 `all`）
- 报告区分**阻断问题**和**可人工确认问题**，不是一行总数
- JSON 报告包含：`blocking_issues`、`confirmable_issues`、`all_issues` 三个独立列表
- CSV 报告分两个表格段输出

### `resume` — 恢复/查看已有批次

```bash
python backup_audit_cli.py resume <备份包目录> [--batch-id ID]
```

- 在新 CLI 进程中恢复之前的工作批次
- 显示批次概要（问题数、状态分布）

## 持久化与跨进程一致性

- 所有状态存储在 `<备份目录>/.audit_state/batch_<批次ID>.json`
- 问题 ID 由 `type:file_path:message` 的 SHA1 前 12 位生成，跨进程一致
- review 历史快照持久化，新进程可继续 undo
- export 的 JSON/CSV 报告中，问题 ID、状态、备注、处理人与批次状态文件完全一致

## 运行测试

```bash
# 先生成样例数据
python generate_samples.py

# 运行回归测试
python -m pytest tests/test_regression.py -v
```

**测试覆盖：**

| 测试类 | 覆盖场景 |
|--------|---------|
| `TestBadSha256Rejection` | 短哈希、非十六进制、空哈希、多条错误报告、不创建批次、合法哈希通过 |
| `TestReviewUndo` | 标记后撤销恢复原状态、空撤销提示、连续撤销两条 |
| `TestCrossProcessExport` | JSON/CSV 报告与 review 状态一致、跨进程 resume |

## 项目结构

```
backup_audit/
  __init__.py          # 包定义
  models.py            # 数据模型：Issue, Manifest, AuditBatch, review_history
                        # 新增：BatchStatus, Signoff, ReopenRecord, OperationLogEntry
                        # 新增方法：finalize(), reopen(), is_readonly(), count_unresolved_*()
  validator.py         # 校验逻辑 + ManifestValidationError
  reporter.py          # 报告导出（JSON/CSV）+ 概要打印（含签收状态）
  cli.py               # CLI 命令入口：import/precheck/list/review/undo/export/resume
                        # 新增：finalize（签收）、reopen（重开）
                        # 新增：只读拦截逻辑，防止已签收批次被修改
backup_audit_cli.py    # 可执行入口
tests/
  test_regression.py   # 回归测试（10个测试类，35个测试用例）
generate_samples.py    # 生成样例备份数据（含各种异常场景）
```
