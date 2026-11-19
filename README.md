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
git -C data/skill-version-dataset checkout --detach 7af3c962202bdb34f5e7647c555fe29d6c83a85a
```

原始 API 审计与完整静态图保留本地，仓库上传实验报告、用量、汇总和逐样本决策。

```bash
python -m pytest
python scripts/validate_skill_dataset.py
python scripts/run_public_dataset.py --output-root results/static-new
python scripts/run_own_method.py --output-root results/own-method-new
```

静态脚本仅运行 HSDA 和行为图，不再调用 B1。真实模型脚本最多选择 11 对公开更新，调用 DeepSeek API
会产生用量，密钥只从本地 secret 文件读入环境变量。旧实验输出保持原样，不把历史 B1 统计改写为新方法结果。
`reconstruct_skill_history.py` 用于本地 Git 重建；generate/validate_skill_dataset.py 用于受控数据。

[模型实验结果](results/public-own-method-deepseek-v1/REPORT.md) ·
[静态分析历史结果](results/public-dataset-static-v1/REPORT.md) ·
[自研方法评估](docs/evaluation_framework.md) ·
[代码导航](skillupdate/README.md)

公开更新安全标签仍不完整，结果不支持与其他检测器的性能优越性结论。Skill 样本仅作为数据处理。

非当前方法的代码、对照实验和旧环境移至项目外
`../SkillUpdate-Pilot-archive-20261119/`，按原相对路径保留，可恢复；冻结的 `../raid2025/` 未修改。
详细移出范围见 [收敛记录](docs/cleanup.md)。
