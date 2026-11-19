# 自研方法：公开数据首批真实 LLM 实验

使用 HSDA → 增量行为图 → DeepSeek flash（thinking disabled）→ P13 Decision Engine。
数据固定在 7af3c962202bdb34f5e7647c555fe29d6c83a85a；seed=20251117。仅将源码、差分、图及证据
送入模型，没有发送来源恶意标签。动态验证未启用，没有执行 Skill。

固定抽取 5 对未标注真实更新、5 对恶意来源更新，加 MCU-0001 确认行为变化，共 11 对。

| 项目 | 数量 |
|---|---:|
| 模型响应通过 Schema 与证据校验 | 3 |
| Schema 拒绝 | 2 |
| 证据落地校验拒绝 | 4 |
| 输入预算超限，请求前拒绝 | 2 |
| 最终 SUSPICIOUS | 8 |
| 最终 UNKNOWN | 3 |
| 实际 API 响应 | 9 |
| 实际输入 tokens | 533776 |
| 实际输出 tokens | 10467 |

注意 summary.json 的 input_tokens 总和混入了预算拒绝项的估算输入量，不能解释为实际 API 用量；
上表按 usage.estimated=false 筛选，才是服务端实测用量。费用没有估算或编造。

MCU-0001 模型响应有效，最终 snapshot_status=SUSPICIOUS、update_impact=NEW_RISK，仍要求人工验证。
旧版本整体安全未知，因此不能描述成已证实的 T1。来源恶意标签也不等于每条更新都新增恶意行为。

发现的实现限制：BENIGN 若附 new_behaviors 会被当前 Schema 一律拒绝，即使陈述可能是正常功能变化；
需独立修订 Schema 后另建实验身份复跑。证据文件必须与全部引用精确一致，模型漏列文件或行号不一致
同样被拒绝。本次没有静默修复、重试修复或选择性丢弃失败。

当前结果反映首次真实公开样本上的可用性及证据约束失败率，不支持优于其他检测器的结论。
逐样本输出见 results.jsonl，独立请求/原始响应/解析输出见 audit/。密钥扫描命中为 0。
