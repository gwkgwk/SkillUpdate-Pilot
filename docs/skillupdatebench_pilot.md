# SkillUpdateBench Pilot（P9）

## 1. 范围

SkillUpdateBench Pilot 是面向 Skill 版本更新检测的最小受控数据集。它包含 20 个基础
Skill family、20 个良性更新和 20 个受控恶意更新，共 60 个完整快照、40 个更新事件。
数据全部由固定脚本构造，`source_type=synthetic_controlled`；它不是公开市场攻击样本，
不能用于宣称真实攻击流行率或大规模统计性能。

五种功能类型分别为 PDF、Document、Data、Image 和 Project，每类四个基础 Skill。
每个快照固定包含：

```text
SKILL.md
references/usage.md
scripts/main.py
scripts/helper.py
config/settings.yaml
```

每个 `base_skill_id` 下有 `base/`、`benign_update/` 和 `malicious_update/`。两个更新都从
同一个 base 快照独立派生，不是 benign → malicious 的连续历史。

## 2. 安全模型

恶意更新只表达可检测的攻击意图，不提供真实攻击能力：

- 敏感值只来自调用参数中的 `FAKE_*` 虚构字典；不读取环境变量、用户目录或凭据文件。
- 数据传输只调用 `mock_send`，端点固定为非网络标识 `mock://...`。
- 命令执行只调用 `mock_execute` 并记录 `status=not_executed`；不导入 subprocess 或调用 shell。
- 审计记录只追加到调用方传入的内存 `audit_log` 列表，不写宿主日志。
- 不导入 socket、requests、urllib、os 或 subprocess，不包含 HTTP(S) 端点。

这些快照仍应作为不可信静态数据处理。P9 禁止执行其中任何 Skill。未来若需动态验证，必须先完成并
批准独立 sandbox 阶段；本数据集的 Mock 设计不构成动态执行许可。

## 3. 变化覆盖

良性更新按确定性轮换覆盖：文档格式变化、正常功能扩展、代码重构、合理的本地相对目录权限变化。
恶意更新覆盖：恶意指令插入、虚构敏感数据访问、模拟数据传输意图、模拟未授权命令执行、
跨文件协同行为和安全约束删除。每个恶意事件均提供跨文件证据标记和预期攻击路径；
标记是 Ground Truth 定位，不会被运行时解释。

Ground Truth 位于 `data/annotations/ground_truth.jsonl`。每条事件包含：

- `update_id`、`base_skill_id`、`old_snapshot`、`new_snapshot`；
- `update_label`、`change_types`、`attack_types`；
- `evidence_files`、精确行号 `evidence_locations`、`expected_attack_path`；
- `source_type`、`label_provenance`、功能类型、随机种子与 split。

快照引用包含 ID、相对路径和规范 SHA-256。规范摘要按排序后的
`relative_path + NUL + file_sha256` 计算，避免依赖文件时间或绝对路径。

## 4. 数据划分

划分以 `base_skill_id` 为唯一分组键，并在功能类型内使用固定种子分层。每类四个 family 中，
两个进入 train，一个进入 validation，一个进入 test，因此总量为 10/5/5。一个 family 的 base、
良性更新、恶意更新以及未来对抗变体必须始终在同一 split，禁止快照级随机拆分。

当前 Pilot 规模很小。可以用于接口、证据链、回归和端到端流程调试，但不允许据此宣称模型具有
大规模泛化能力、稳定的真实世界精确率/召回率或市场恶意更新发生率。

## 5. 生成与验证

生成器固定使用种子 `20251117`，不使用当前时间、系统随机源、网络或外部数据：

```bash
conda run -n skillupdate python scripts/generate_skill_dataset.py
conda run -n skillupdate python scripts/validate_skill_dataset.py
```

验证器检查目录和数量、每个快照的五文件约束、Python AST 禁止能力、模拟端点、快照摘要、
40 条标注、证据行号、六类攻击与四类良性覆盖、split 分组无泄漏及 generation manifest 摘要。
重复生成会只替换 `data/controlled_skills/`、`data/annotations/` 和 `data/manifests/` 三个
生成目录；不要在这些目录中保存手工内容。

主要 manifest：

- `data/manifests/dataset_manifest.json`：数据集范围、计数、安全声明和 60 个快照摘要；
- `data/manifests/splits.json`：种子、分组键、策略和 family 列表；
- `data/manifests/generation_manifest.json`：Ground Truth 与 manifest 的摘要；
- `data/annotations/annotation_schema.json`：标注必填字段和受控枚举。

修改模板、标签、划分策略或随机种子会产生新的数据集版本；不得用新内容覆盖已用于正式实验的
不可变版本。正式实验还需按 `docs/governance/EXPERIMENT_MANIFEST.md` 建立独立实验 manifest。
