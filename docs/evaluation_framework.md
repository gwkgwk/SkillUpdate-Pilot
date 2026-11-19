# 自研方法评估

当前保留 classification、pr_curve、grouped_bootstrap、mcnemar_family_exact、efficiency、
evidence_metrics 等统计工具，位于 skillupdate/evaluation/。framework.evaluate 支持已经标注的数据，
要求同一 Skill 及其变体不跨 split；UNKNOWN/SUSPICIOUS 作为拒判并报告覆盖率。

公开数据的主入口为 run_public_dataset.py（HSDA＋增量行为图）与 run_own_method.py
（再加入真实 LLM 与 Decision Engine）。前者不生成 snapshot_status 安全标签，后者保存真实模型
响应和最终决策。B1–B7/消融 runner 已归档，不属于当前方法。

当前公开数据没有完整良性/恶意更新真值。不能将 500 对真实更新当成良性，把恶意来源身份当成更新影响，
或将克隆快照组成版本对。因此只报告静态风险路径、模型校验成功率、最终状态分布、用量及问题案例。
有恶意概率与独立 GT 后才能计算 AUPRC；confidence 不等于恶意概率。按 Skill 分组的 Bootstrap
不弥补标签缺失，Pilot 不支持正式显著性结论。
