# 自研方法收敛记录

2026-11-19 按用户要求，当前仓库只保留自研分析链与数据工具。

移出内容集中保存在 `../SkillUpdate-Pilot-archive-20261119/`，沿用原项目相对路径：
B1–B7 detector、A–E 消融 runner、传统文本/AST/依赖图对照、P8 占位协议/Schema、
旧复现环境与锁文件、旧 P15 结果及其测试和文档。恢复时先检查目标冲突，避免覆盖当前实现。

JavaScript 分析依赖已从旧 RAID Node 环境独立：config/javascript 下保留 Babel parser、types、
helper-string-parser、helper-validator-identifier，源码内容与原包逐文件 SHA256 核验一致。
原环境仍在外部归档；冻结 ../raid2025 未修改。原始 API 响应及公开数据实验结果保留原样。

run_public_dataset.py 现只运行 HSDA＋增量行为图，不再生成 B1 predictions.jsonl；旧实验已有输出
仍包含当时的 B1 数据，不能把历史记录改写为新版输出。

受控 Pilot 数据保留，因为自研 LLM、HSDA、图和动态安全测试需要它；公开数据完整保留上游结构，
不拆除来源档案或修改标签。新运行默认只收集 tests/，不会执行数据集中的测试或 Skill。
