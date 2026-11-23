# SkillUpdate

只保留自研 Skill 更新安全分析方法与数据工具。

```text
skillupdate/
  hsda/                  异构语义差分
  behavior_graph/        增量行为图与风险路径
  llm/                   证据约束 LLM 分析
  decision/              当前安全状态与更新影响
  sandbox/               Docker 受控 Mock 隔离
  dynamic_verification/  风险引导动态验证
  marketplace/           来源、身份、快照与元数据
  versioning/            离线 Git 版本重建
  evaluation/            自研方法评估指标
scripts/                 运行与数据维护入口
data/                    公开数据和受控 Pilot
tests/                   自研方法与数据测试
docs/                    当前方法设计说明
config/javascript/       Babel 静态解析依赖
results/                 自研方法已有实验记录
```

Python 3.11 环境安装 `pip install -r requirements.txt`；JavaScript 解析使用 Node 与
config/javascript 下已固定的 Babel。Docker 仅用于显式启用的受控 Mock 测试。

GitHub 源码不包含 node_modules、独立公开数据仓库和大型实验中间产物。首次获取后准备依赖与数据：

```bash
pip install -r requirements.txt
npm ci --ignore-scripts --prefix config/javascript
git clone https://github.com/gwkgwk/skill-version-dataset.git data/skill-version-dataset
git -C data/skill-version-dataset checkout --detach 864a26872f6f0a4426870c507cd82e1024a7065d
```

数据集固定到 2026-11-23 的 main 提交，避免实验过程中上游变化。当前数据口径由
[UPDATE_DETECTION_MAIN_SET.json](https://github.com/gwkgwk/skill-version-dataset/blob/main/UPDATE_DETECTION_MAIN_SET.json) 定义：

- 500 对真实 Git 更新：用户报告已人工确认良性，标签属于 user attestation；审核人、方法和逐条记录未提供，不能声称独立复核。
- 53 对 Skill-Inject 受控攻击内容更新：作者最终明显攻击标签与精确注入 diff；本次未独立验证执行成功。
- 47 对 SkillLifeBench 安全回归：单独诊断，不与恶意意图或攻击注入混为一谈。
- 37 对恶意来源更新不作为正例，因为来源恶意标签不能证明本次 diff 引入恶意行为。
- 原恶意克隆子集已从上游当前版本移除；克隆快照不作为更新对。

运行：

```bash
python -m pytest
python scripts/validate_skill_dataset.py
python scripts/run_public_dataset.py --output-root results/static-dataset-main-20261123
python scripts/run_own_method.py --output-root results/own-method-main-20261123
```

静态脚本仅运行 HSDA 和行为图，不执行 Skill 样本，不调用 LLM。真实模型脚本最多选择 10 对（5 对用户确认良性对照、5 对受控攻击内容更新），调用 DeepSeek API 会产生用量；密钥只从本地 secret 文件读入环境变量。模型输入不包含标签、metadata、evidence 或 oracle。47 对工具实现安全回归因输入形态不同，单独静态评估，不混入完整 Skill 包模型抽样。

原始 API 审计与完整静态图保留本地，仓库上传实验报告、用量、汇总和逐样本决策。旧实验输出保持原样，不把历史 B1 统计改写为新方法结果。

[模型实验结果](results/public-own-method-deepseek-v1/REPORT.md) ·
[静态分析历史结果](results/public-dataset-static-v1/REPORT.md) ·
[自研方法评估](docs/evaluation_framework.md) ·
[代码导航](skillupdate/README.md)

公开更新安全标签仍不完整，结果不支持与其他检测器的性能优越性结论。Skill 样本仅作为数据处理。
