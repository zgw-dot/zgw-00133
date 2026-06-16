# 离线备份包验收 CLI (backup-audit)

读取 manifest，校验文件路径、SHA256、大小、备份窗口和业务线，生成批次问题清单；
运维可将问题标记为待补/已确认/忽略，支持撤销复核，导出区分阻断/可确认的报告。

**新增功能：备份窗口模板**
- 支持创建可复用的窗口模板，包含时间窗、时区、业务线范围和备注
- 完整 CLI 链路：`window create/list/show/apply/import/export`
- 导入批次或跑 `precheck` 时只有显式引用模板才生效，不会悄悄套默认值
- 模板名重名、同一批次重复套用、模板已被删改、时区格式或业务线不合法都会被拦截并说明原因
- 所有操作记审计日志，模板库、应用记录和导出文件落盘持久化
- 跨进程恢复：`resume` 或 `show` 可查看谁在什么时候用了哪个模板
- 快照机制：模板被修改时，旧批次保留当时的生效快照，不被新内容覆盖
- 支持模板批量导出导入，方便跨环境迁移和对账

## 快速开始

```bash
# 1. 生成样例备份数据
python generate_samples.py

# 2. 创建备份窗口模板（可选，复用常用配置）
python backup_audit_cli.py window create daily_backup \
  --window-start 2024-01-01T00:00:00 \
  --window-end 2024-12-31T23:59:59 \
  --timezone +08:00 \
  --business-line order_system \
  --business-line payment_system \
  --notes "日常备份窗口（东八区）" \
  --actor admin

# 3. 导入 manifest 并创建验收批次（可选：显式引用窗口模板）
python backup_audit_cli.py import sample_backup/manifest.json sample_backup \
  --window-profile daily_backup --actor ops

# 4. 运行预检（只读，不修改源文件）
python backup_audit_cli.py precheck sample_backup

# 5. 按严重程度筛选问题，方便逐条处理
python backup_audit_cli.py list sample_backup --severity blocking
python backup_audit_cli.py list sample_backup --severity confirmable

# 6. 复核：标记问题状态
python backup_audit_cli.py review sample_backup <问题ID> --status pending_fix --assignee zhangsan --notes "联系运维补传"

# 7. 撤销上一条复核
python backup_audit_cli.py undo sample_backup

# 8. 签收批次（阻断问题必须全部处理，否则需要 --force-with-reason）
python backup_audit_cli.py finalize sample_backup --signer wangwu --reason "所有阻断问题已修复，可确认问题已人工审核"

# 9. 如确需带阻断问题放行，使用强制签收（必须写清理由）
python backup_audit_cli.py finalize sample_backup --signer manager --reason "经风险评估委员会审批，特批该批次带问题放行" --force-with-reason

# 10. 签收后只读，禁止 precheck/review/undo/重复 finalize
# 如需重新编辑，重开已签收批次
python backup_audit_cli.py reopen sample_backup --reopener zhangsan --reason "发现漏处理的阻断问题，需补充复核"

# 11. 导出报告（JSON + CSV，包含签收摘要和操作日志）
python backup_audit_cli.py export sample_backup --output sample_backup/reports

# 12. 新进程恢复已有批次
python backup_audit_cli.py resume sample_backup
```

## 命令详解

### `import` — 导入 manifest 并创建验收批次

```bash
python backup_audit_cli.py import <manifest.json路径> <备份包目录> [--force] [--window-profile 模板名] [--actor 操作人]
```

- 校验 manifest 中每条文件的 `sha256` 字段（必须为 64 位十六进制）
- 校验 `size` 字段（必须为非负整数）和 `path` 字段（不能为空）
- 格式非法时：列出所有错误行号和字段，**不创建批次，不污染已有状态**
- 如果备份目录已有批次，需 `--force` 覆盖或使用 `resume` 继续
- **窗口模板支持**：
  - 使用 `--window-profile <模板名>` 显式引用已创建的窗口模板
  - 模板中的时间窗、时区、业务线会自动应用到批次，并保留快照
  - 模板必须先通过 `window create` 创建
  - 模板不存在或无效时，批次仍会创建，但模板不会应用，并给出明确提示
  - **不会悄悄套用默认值**，必须显式指定才生效

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
- **严重程度过滤**（运维按类别逐条处理）：
  - `--severity blocking` 只显示阻断问题详情，方便先修必须修复的
  - `--severity confirmable` 只显示可人工确认问题详情，方便人工审核
- 可组合使用：`--severity blocking --status open` 只显示未处理的阻断问题
- 显示处理人和备注

**预期输出（--severity blocking）：**

```
批次 ID: BATCH-2024-001
批次状态: open
备份目录: /path/to/backup
Manifest: /path/to/manifest.json

=== 概要 ===
  问题总数:    6
  阻断问题:    3 (必须修复)
  可确认问题:  3 (人工确认)
  未处理阻断:  3
  未处理可确认:3

--- 阻断问题 (BLOCKING) ---
  [02d8013c22e5] bad_checksum         open            data/tampered_file.dat
      SHA256 mismatch: expected abf8da74..., got 4c9f7c2d...
  [ced10514917e] size_mismatch        open            data/wrong_size.dat
      Size mismatch: expected 539, got 39
  [79ddd6fc0c30] missing_file         open            data/deleted_file.dat
      File not found: data/deleted_file.dat
```

**预期输出（--severity confirmable）：**

```
批次 ID: BATCH-2024-001
批次状态: open
...
=== 概要 ===
  问题总数:    6
  阻断问题:    3 (必须修复)
  可确认问题:  3 (人工确认)
  未处理阻断:  3
  未处理可确认:3

--- 可确认问题 (CONFIRMABLE) ---
  [28d3b40711d7] outside_backup_window open            data/old_file.dat
      File mtime ... outside backup window ...
  [bdfd4b1829ec] unknown_business_line open            data/unknown_bl.dat
      Unknown business line 'unknown_system_xyz', valid: [...]
  [1fb222aa8087] empty_revocation     open            <manifest>
      Revocation list is present but empty - please confirm this is intentional
```

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

签收后批次进入 `finalized` 状态，**禁止执行 precheck**、**禁止执行 review**、**禁止执行 undo**、**禁止执行 重复 finalize**；所有写操作统一返回退出码 3（重复签收返回退出码 4）。

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

### `export` — 导出验收报告

```bash
python backup_audit_cli.py export <备份包目录> [--format FORMAT] [--output DIR] [--batch-id ID]
```

- `--format`：`json`/`csv`/`all`（默认 `all`）
- 报告区分**阻断问题**和**可人工确认问题**，不是一行总数
- JSON 报告包含：`blocking_issues`、`confirmable_issues`、`all_issues` 三个独立列表
- CSV 报告分两个表格段输出
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


### `resume` — 恢复/查看已有批次

```bash
python backup_audit_cli.py resume <备份包目录> [--batch-id ID]
```

- 在新 CLI 进程中恢复之前的工作批次
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

### `window create` — 创建备份窗口模板

```bash
python backup_audit_cli.py window create <模板名> \
  --window-start <ISO时间> \
  --window-end <ISO时间> \
  --timezone <时区> \
  --business-line <业务线> [--business-line <业务线> ...] \
  [--notes <备注>] \
  --actor <操作人>
```

- **时区格式**：支持 `UTC`、`Z`、`±HH:MM`（如 `+08:00`、`-05:00`）
- **业务线**：可多次指定 `--business-line` 添加多个业务线
- **时间窗校验**：起始时间必须早于结束时间
- **名称唯一**：模板名称不能重复（包括已删除的模板）
- **审计日志**：所有操作都会记录审计日志，包含操作人、时间、变更内容

**预期输出（成功）：**

```
窗口模板已创建: daily_backup
  操作人: admin
  创建时间: 2024-01-15T10:30:00.123456
  版本: 1
  时间窗: 2024-01-01T00:00:00 ~ 2024-12-31T23:59:59
  时区: +08:00
  业务线: order_system, payment_system
  备注: 日常备份窗口（东八区）
```

**错误场景：**

| 错误场景 | 退出码 | 错误提示 |
|---------|--------|---------|
| 时区格式无效 | 40 | `时区格式无效: 'invalid'。必须为 UTC、Z 或 ±HH:MM 格式（如 +08:00、-05:00）` |
| 模板名已存在 | 41 | `模板名称已存在: 'daily_backup'。请使用其他名称，或使用 update 命令更新现有模板。` |
| 时间窗无效 | 45 | `窗口起始时间必须早于结束时间` |
| 缺少业务线 | 45 | `至少需要指定一个业务线` |

### `window list` — 列出所有窗口模板

```bash
python backup_audit_cli.py window list [--include-inactive]
```

- 默认只显示活跃（未删除）的模板
- `--include-inactive`：包含已删除的模板
- 显示每个模板的版本、时区、窗口范围、业务线、备注

**预期输出：**

```
=== 窗口模板列表 (3 个) ===
  * daily_backup
    版本: 2 | 时区: +08:00
    窗口: 2024-01-01T00:00:00 ~ 2024-12-31T23:59:59
    业务线: order_system, payment_system
    创建: 2024-01-15T10:30:00 | 更新: 2024-01-20T14:20:00
    备注: 日常备份窗口（东八区）

  * weekly_backup
    版本: 1 | 时区: UTC
    窗口: 2024-01-01T00:00:00 ~ 2024-12-31T23:59:59
    业务线: archive_system
    创建: 2024-01-10T09:00:00 | 更新: 2024-01-10T09:00:00
    备注: 周备份窗口（UTC 时区）
```

### `window show` — 查看模板详情、应用记录和审计日志

```bash
python backup_audit_cli.py window show <模板名> [--show-log] [--log-limit N]
```

- 显示模板的完整信息：名称、版本、创建/更新时间、时区、窗口、业务线、备注、指纹
- `--show-log`：显示模板的审计日志（创建、更新、应用、删除等）
- `--log-limit N`：审计日志显示条数（默认 20 条）
- 显示模板的应用记录：哪些批次在什么时候应用了哪个版本的模板

**预期输出（含审计日志）：**

```
=== 窗口模板详情 ===
  名称: daily_backup
  版本: 2
  状态: 活跃
  指纹: a1b2c3d4e5f67890
  创建人: admin
  创建时间: 2024-01-15T10:30:00
  更新时间: 2024-01-20T14:20:00
  时间窗: 2024-01-01T00:00:00 ~ 2024-12-31T23:59:59
  时区: +08:00
  业务线: order_system, payment_system
  备注: 日常备份窗口（东八区）

=== 模板应用记录 ===
  - 批次 BATCH-2024-001 (v1, +08:00)
    应用人: ops | 应用时间: 2024-01-16T08:00:00
    指纹: a1b2c3d4e5f67890

=== 模板审计日志 (最近 5 条) ===
  [1] 2024-01-20T14:20:00 | admin | 更新
      业务线变更: ['order_system'] → ['order_system', 'payment_system']
  [2] 2024-01-16T08:00:00 | ops | 应用
      应用到批次: BATCH-2024-001
  [3] 2024-01-15T10:30:00 | admin | 创建
      初始版本 v1
```

### `window apply` — 将模板应用到指定批次

```bash
python backup_audit_cli.py window apply <模板名> <备份包目录> \
  [--batch-id <批次ID>] \
  --actor <操作人> \
  [--expected-fingerprint <指纹>] \
  [--force]
```

- **显式引用**：只有显式调用 `apply` 或在 `import` 时指定 `--window-profile` 才会应用模板
- **快照机制**：应用时会保存模板快照到批次，后续模板修改不会影响已应用的批次
- **防重复**：同一批次不能重复套用同一模板
- **防篡改**：使用 `--expected-fingerprint` 可以验证模板自上次查看后未被修改
- `--force`：即使模板已被修改也强制应用

**预期输出（成功）：**

```
模板已应用到批次: BATCH-2024-001
  模板: daily_backup (版本 v2)
  应用人: ops
  应用时间: 2024-01-25T10:00:00
  指纹: a1b2c3d4e5f67890

  生效配置:
    时间窗: 2024-01-01T00:00:00 ~ 2024-12-31T23:59:59
    时区: +08:00
    业务线: order_system, payment_system
    备注: 日常备份窗口（东八区）

提示: 下次 precheck 将使用上述窗口和业务线配置进行校验。
```

**错误场景：**

| 错误场景 | 退出码 | 错误提示 |
|---------|--------|---------|
| 模板不存在 | 42 | `模板不存在或已删除: 'daily_backup'。请先创建模板或使用其他模板。` |
| 模板已被修改 | 43 | `模板 'daily_backup' 自上次查看后已被修改。请使用 --force 强制应用，或使用新的指纹。` |
| 重复应用 | 44 | `同一批次不能重复套用同一模板: 'daily_backup' 已应用于批次 BATCH-2024-001。` |

### `window export` — 导出窗口模板到 JSON 文件

```bash
python backup_audit_cli.py window export <输出文件路径> \
  [--name <模板名>] [--name <模板名> ...] \
  --actor <操作人>
```

- 不指定 `--name` 则导出所有活跃模板
- 可多次指定 `--name` 导出特定模板
- 导出内容包含：模板完整信息、版本历史、指纹
- 导出文件包含完整性校验，可用于跨环境迁移

**预期输出：**

```
窗口模板已导出: /path/to/window_profiles.json
  操作人: admin
  导出模板数: 3
    - daily_backup (v2)
    - weekly_backup (v1)
    - monthly_backup (v1)
```

### `window import` — 从 JSON 文件导入窗口模板

```bash
python backup_audit_cli.py window import <输入文件路径> \
  --actor <操作人> \
  [--mode merge|replace] \
  [--force]
```

- **导入模式**：
  - `merge`（默认）：合并导入，跳过已存在的模板
  - `replace`：替换已存在的模板（需 `--force` 确认）
- **完整性校验**：导入时校验导出文件的完整性和格式
- **审计日志**：记录每个模板的导入结果（新增/更新/跳过/失败）
- **对账**：导入完成后可对比导出文件确保数据一致性

**预期输出（merge 模式）：**

```
窗口模板导入完成 (模式: merge)
  操作人: admin
  源文件: /path/to/window_profiles.json
  文件中模板总数: 3

  新增: 2 个
    + daily_backup (v2)
    + weekly_backup (v1)
  跳过: 1 个 (已存在，merge 模式不覆盖)
    - monthly_backup (已存在，merge 模式不覆盖)
```

**预期输出（replace 模式）：**

```
窗口模板导入完成 (模式: replace)
  操作人: admin
  源文件: /path/to/window_profiles.json
  文件中模板总数: 3

  新增: 2 个
    + daily_backup (v2)
    + weekly_backup (v1)
  更新: 1 个
    * monthly_backup (v1 → v2)
```

## 持久化与跨进程一致性

- 所有批次状态存储在 `<备份目录>/.audit_state/batch_<批次ID>.json`
- 窗口模板库存储在全局配置目录：`~/.backup_audit_config/window_profiles.json`
- 窗口模板应用记录存储在：`~/.backup_audit_config/window_profile_applications.json`
- 窗口模板快照存储在：`~/.backup_audit_config/window_profile_snapshots/`
- 窗口模板审计日志存储在：`~/.backup_audit_config/window_profile_log.json`
- 问题 ID 由 `type:file_path:message` 的 SHA1 前 12 位生成，跨进程一致
- review 历史快照持久化，新进程可继续 undo
- export 的 JSON/CSV 报告中，问题 ID、状态、备注、处理人与批次状态文件完全一致

### 批次持久化字段

| 字段 | 类型 | 说明 | 出现在哪些命令 |
|------|------|------|--------------|
| `status` | string | `open` / `finalized` | `resume`、`list`、`export` 报告 |
| `signoff` | object | 当前签收信息（未签收为 null）：signer/reason/timestamp/forced/unresolved_*_count | `resume`、`list`、`export` 报告 |
| `reopen_records` | array | 全部重开历史（每次重开保留前一次签收）：reopener/reason/timestamp/previous_signoff | `export` 报告 |
| `operation_log` | array | 所有关键操作完整历史：precheck/review/undo/finalize/reopen/export/window_profile_apply | `export` 报告、print_summary 显示条数 |
| `window_profile_snapshot` | object | 应用的窗口模板快照（未应用为 null），包含完整模板内容和版本 | `resume`、`list`、`export` 报告 |
| `window_profile_ref` | string | 引用的模板名称（未应用为 null） | `export` 报告 |

### 窗口模板快照机制（旧批次保留历史版本）

当模板被修改时，**已应用该模板的批次不会被新内容覆盖**：

1. 应用模板时，会生成模板内容的**快照**并嵌入批次文件
2. 快照包含：模板名称、版本、时间窗、时区、业务线、备注、应用人、应用时间、指纹
3. 后续模板修改（版本号递增）不会影响已存在的批次快照
4. `resume` / `list` / `export` 都会显示当时应用的版本号（如 `v1`），而不是当前版本
5. 跨进程恢复后，快照信息完整保留，可追溯当时的生效配置

**示例：模板 v1 应用到批次后被修改为 v2**

```
# 应用时的模板版本 v1
窗口模板: daily_backup (v1)
  时区: +08:00
  业务线: order_system

# 模板被修改为 v2（时区改为 +09:00，新增业务线 payment_system）
# 但旧批次仍然保留 v1 快照：
resume 旧批次 → 显示 daily_backup (v1)，时区 +08:00，业务线 order_system
resume 新批次 → 显示 daily_backup (v2)，时区 +09:00，业务线 order_system, payment_system
```

- 跨进程场景：
  - 终端 A：import → precheck → review → finalize（强制放行）
  - 终端 B（新进程）：`resume` → 看到 `批次状态: finalized`、`签收状态: 强制放行`、`签收人: dept_manager`
  - 终端 B：`list` → 同样看到 finalized 状态、签收信息
  - 终端 B：`export` → JSON/CSV 里有完整 signoff、reopen_records、operation_log
  - 终端 B：`reopen` → 成功恢复编辑，累计重开次数 +1
  - 终端 A（原进程，再跑一次）：`resume` → 看到 `重开次数: 1`，与终端 B 的操作完全一致


## 运行测试

```bash
# 先生成样例数据
python generate_samples.py

# 运行回归测试
python -m pytest tests/test_regression.py -v

# 运行窗口模板专项测试
python -m pytest tests/test_window_profile.py -v

# 运行所有测试
python -m pytest tests/ -v
```

**测试覆盖：**

### 回归测试（test_regression.py，35 个用例）

| 测试类 | 覆盖场景 |
|--------|---------|
| `TestBadSha256Rejection` | 短哈希、非十六进制、空哈希、多条错误报告、不创建批次、合法哈希通过 |
| `TestReviewUndo` | 标记后撤销恢复原状态、空撤销提示、连续撤销两条 |
| `TestCrossProcessExport` | JSON/CSV 报告与 review 状态一致、跨进程 resume |
| `TestSignoffBlocking` | 阻断问题未处理禁止签收、强制无理由拒绝、无理由拒绝 |
| `TestForcedSignoff` | 强制放行成功、只读拦截 precheck/review/undo/重复 finalize |
| `TestReopenWorkflow` | 参数校验、恢复编辑、重开记录持久化、重开开放批次拒绝、重新签收 |

### 窗口模板专项测试（test_window_profile.py，23 个用例）

| 测试类 | 覆盖场景 |
|--------|---------|
| `TestWindowProfileCreateValidation` | 模板创建成功、时区格式验证（UTC/Z/±HH:MM）、无效时区拒绝、时间窗校验、业务线必填、操作人必填 |
| `TestWindowProfileNameConflict` | 重名模板拒绝、模板列表展示 |
| `TestWindowProfileApply` | 模板应用成功、模板不存在拒绝、重复应用拒绝、应用后 manifest 窗口更新 |
| `TestWindowProfileTimezonePrecheck` | 带时区窗口的 precheck 校验、时区偏移下的窗口外检测 |
| `TestWindowProfileCrossProcess` | 跨进程 resume 显示模板信息、list 显示模板信息、export 包含模板信息 |
| `TestWindowProfileImportExport` | 导出导入全量对账、merge 模式跳过已存在、replace 模式强制更新 |
| `TestWindowProfileSnapshotImmutability` | 模板修改后旧批次保留 v1 快照、新批次使用 v2 版本、导出报告包含正确快照 |
| `TestWindowProfileAuditLog` | 审计日志记录创建、应用、修改、删除等操作 |
| `TestCleanSignoff` | 无阻断批次正常签收 |
| `TestCrossProcessSignoff` | 跨进程 resume/list 显示签收状态、export 包含签收摘要和日志、reopen 历史保留 |
| `TestListSeverityFilter` | blocking/confirmable 筛选正确、组合筛选、帮助说明一致 |

## 项目结构

```
backup_audit/
  __init__.py          # 包定义
  models.py              # 数据模型：Issue, Manifest, AuditBatch
                            # 新增：BatchStatus, Signoff, ReopenRecord, OperationLogEntry
                            # 新增：window_profile_snapshot, window_profile_ref 字段
                            # 新增方法：finalize(), reopen(), is_readonly(), count_unresolved_*()
                            # 新增方法：apply_window_profile_snapshot(), get_window_profile_info()
  validator.py             # 校验逻辑 + ManifestValidationError
                            # 新增：时区解析、时区感知的窗口校验
  reporter.py            # 报告导出（JSON/CSV）+ 概要打印（含模板信息）
  cli.py                 # CLI 命令入口
                            # 新增：window create/list/show/apply/import/export
                            # 新增：finalize（签收）、reopen（重开）
                            # 新增：import 支持 --window-profile 参数
                            # 新增：参数预处理支持负时区值（-05:00）
  window_profile.py        # 窗口模板核心模块（新增）
                            # 数据模型：WindowProfile, WindowProfileSnapshot,
                            #         WindowProfileApplicationRecord,
                            #         WindowProfileAuditLogEntry,
                            #         WindowProfileExportBundle
                            # 存储类：WindowProfileStore（CRUD + 验证 + 导入导出）
                            # 验证函数：validate_timezone(), validate_window_times(),
                            #          validate_business_lines()
                            # 自定义异常：ValidationError, ConflictError, NotFoundError 等
  waiver.py              # 豁免规则管理
  snapshot.py              # 操作快照管理
backup_audit_cli.py        # 可执行入口
tests/
  test_regression.py     # 回归测试（10个测试类，35个测试用例）
  test_window_profile.py  # 窗口模板专项测试（8个测试类，23个测试用例）
  test_waiver.py           # 豁免规则专项测试
generate_samples.py        # 生成样例备份数据（含各种异常场景）
```

## 豁免规则管理

### 概述

豁免规则用于在验收过程中忽略已知的、可接受的问题。每条规则可按路径前缀、业务线、问题类型、严重程度等维度进行匹配。

**规则来源标记**：
- manual（手工）：通过 waiver add 命令添加的规则
- atch_import（批量导入）：通过 waiver import 命令导入的规则

回滚机制只会移除 atch_import 来源的规则，不会误伤手工添加的规则。

### 批量导入安全流程

为确保批量导入的安全性，导入流程采用 **"预演 → 确认 → 导入 → 可回滚"** 的四步安全机制：

`
1. 预演 (--dry-run)
   ↓
2. 检查预演结果（新增/冲突/已存在/已过期数量）
   ↓
3. 确认执行导入（自动创建可追溯事务）
   ↓
4. 如需回滚，执行 rollback（只影响本次导入的规则）
`

### 命令详解

#### waiver import — 批量导入豁免规则

**推荐工作流：**

`ash
# 第一步：预演导入，查看结果但不修改任何规则
python backup_audit_cli.py waiver import rules.json --actor ops_zhang --dry-run

# 第二步：确认预演结果无误后，实际执行导入
python backup_audit_cli.py waiver import rules.json --actor ops_zhang

# 第三步：如需回滚，执行回滚命令
python backup_audit_cli.py waiver rollback --actor ops_zhang --yes
`

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| input | ✅ | 导入文件路径（JSON 格式） |
| --actor | ✅ | 操作人 |
| --mode | ❌ | 导入模式：merge(默认) 或 eplace |
| --dry-run | ❌ | 仅预演，不实际修改规则 |
| --replace-confirm-manual-delete | ❌ | replace 模式下确认删除所有手工规则 |

**预演结果输出示例：**

`
=== 导入预演结果 ===
  源文件: /path/to/rules.json
  导入模式: merge
  文件中规则总数: 5

  新增规则: 2
    + a1b2c3d4e5f6: 遗留系统路径前缀豁免 (路径=data/legacy/)
    + b2c3d4e5f6a7: 支付系统校验和豁免 (业务线=payment_system, 类型=bad_checksum)

  已存在 (跳过): 1
    = c3d4e5f6a7b8: 已存在的规则

  冲突/风险 (跳过): 1
    ! d4e5f6a7b8c9: 与规则 c3d4e5f6a7b8 存在范围重叠

  已过期 (跳过): 1
    e e5f6a7b8c9d0: 过期于 2024-01-01T00:00:00

  无效规则: 0

  ✅ 预演通过，可以执行导入。
`

**replace 模式保护：**

当使用 --mode replace 时，如果当前存在手工创建的规则，系统会拒绝导入以防止误删：

`ash
# 有手工规则时会被拒绝
python backup_audit_cli.py waiver import rules.json --actor ops_zhang --mode replace
# 错误: replace 模式下检测到 3 条手工创建的规则...

# 确认删除手工规则后才能执行
python backup_audit_cli.py waiver import rules.json --actor ops_zhang --mode replace --replace-confirm-manual-delete
`

#### waiver rollback — 回滚最近一次导入

`ash
# 查看回滚预览（不带 --yes）
python backup_audit_cli.py waiver rollback --actor ops_zhang

# 确认执行回滚
python backup_audit_cli.py waiver rollback --actor ops_zhang --yes
`

**回滚特性：**
- ✅ 只回滚最近一次导入事务
- ✅ 保留导入后手工添加的规则
- ✅ 事务状态更新为 olled_back（可追溯）
- ✅ 跨重启后仍可回滚

#### waiver transactions — 查看导入事务历史

`ash
# 查看最近 10 条事务
python backup_audit_cli.py waiver transactions

# 查看最近 5 条事务
python backup_audit_cli.py waiver transactions --limit 5
`

**输出示例：**

`
=== 导入事务历史 (最近 3 条) ===
↩️ [2026-06-16T10:30:00] TX-20260616103000-abc12345
    状态: rolled_back
    操作人: ops_zhang
    模式: merge
    源文件: /path/to/rules.json
    导入规则数: 2
    回滚移除: 2 条

✅ [2026-06-16T10:25:00] TX-20260616102500-def67890
    状态: committed
    操作人: ops_li
    模式: merge
    源文件: /path/to/other_rules.json
    导入规则数: 3
`

#### waiver list — 查看豁免规则

`ash
# 查看生效规则
python backup_audit_cli.py waiver list

# 包含已过期规则
python backup_audit_cli.py waiver list --include-expired

# 同时显示操作日志（含来源和动作）
python backup_audit_cli.py waiver list --show-log
`

**输出示例（含来源标记）：**

`
当前生效规则: 3
全局配置目录: /home/user/.backup_audit_config

  [a1b2c3d4e5f6] [手工]
    操作人: ops_zhang
    创建时间: 2026-06-16T10:00:00
    来源: manual
    匹配条件: 路径前缀=data/legacy/
    理由: 遗留系统已知问题

  [b2c3d4e5f6a7] [批量导入]
    操作人: ops_li
    创建时间: 2026-06-16T10:25:00
    来源: batch_import
    事务ID: TX-20260616102500-def67890
    匹配条件: 业务线=payment_system, 类型=bad_checksum
    理由: 支付系统历史校验和允许
`

#### waiver export — 导出豁免规则

`ash
python backup_audit_cli.py waiver export waivers_backup.json --actor ops_zhang
`

导出的 JSON 文件包含每条规则的完整信息，包括 source（来源）和 	ransaction_id（事务ID），便于追溯。

### 数据持久化

所有状态均持久化到配置目录，跨进程/重启后保持一致：

| 文件 | 内容 |
|------|------|
| waiver_rules.json | 豁免规则列表 |
| waiver_audit_log.json | 所有操作的审计日志 |
| waiver_transactions.json | 导入事务记录（用于回滚） |

### 退出码约定（豁免规则相关）

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 16 | 导入文件校验失败 |
| 17 | 导入文件格式无效 |
| 20 | 预演执行失败 |
| 21 | 预演未通过（存在错误） |
| 22 | 事务操作失败（如 replace 模式未确认） |
| 23 | 无可回滚的导入事务 |
| 24 | 回滚未确认（缺少 --yes） |
| 25 | 回滚执行失败 |
