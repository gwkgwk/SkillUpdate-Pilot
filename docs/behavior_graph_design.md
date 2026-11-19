# Incremental Behavioral Graph Analysis（P12）

## 1. 目标与非目标

P12 面向 Skill 更新中的跨文件新增风险行为路径。系统分别构建旧版本图和新版本图，增量复用
未变化文件的局部图，对齐节点和关系，再用显式语义规则识别新增风险路径。

公共入口：

```python
from skillupdate.behavior_graph import IncrementalBehaviorGraphAnalyzer

delta = IncrementalBehaviorGraphAnalyzer().compare(old_skill, new_skill)
```

图变化本身不是恶意证据。新增节点或新增边只有满足数据访问、端点连接、工具调用、指令或权限等
语义模板，并且能回链原始文件和行号时，才形成 `RiskPath`。P12 不执行 Skill、不调用 LLM，
也不产生最终 BENIGN/MALICIOUS 判定。

## 2. 图 Schema

节点类型固定为：

- `Instruction`：Markdown 中静态提取的指令；
- `File`：快照中的文件；
- `Function`：Python/JavaScript AST 函数；
- `Tool`：静态调用目标、依赖或推断能力；
- `Permission`：安全约束和配置权限；
- `Data`：文件数据、字符串中的敏感数据或操作对象；
- `Endpoint`：源码、配置或引用中的端点。

关系固定为 `INSTRUCTS`、`REFERENCES`、`CALLS`、`INVOKES`、`READS`、`WRITES`、
`CONNECTS_TO` 和 `GRANTS`。图 Schema 校验节点 ID、边 ID 唯一，且所有边端点真实存在。

节点 ID 由 `(kind, semantic_key)` 确定性生成；边 ID 由源节点、关系、目标节点和语义键生成。
同一语义实体跨未变化版本保持稳定 ID，重命名实体通过 Alignment 显式关联，不伪造相同 ID。

## 3. 证据与事实等级

每个节点和每条边至少有一项 `GraphEvidence`：OLD/NEW、相对文件、1-based 闭区间行号、摘录、
producer 和依据类型。四种依据严格区分：

- `STATIC_FACT`：AST、Markdown、配置或引用中直接可见；
- `RULE_INFERENCE`：函数名归类、唯一函数调用解析、指令能力或权限能力推导；
- `LLM_INFERENCE`：Schema 保留该类型，但 P12 静态构建器不产生；
- `DYNAMIC_OBSERVATION`：Schema 保留该类型，但没有 runtime trace 时绝不产生。

RiskPath 始终是 `RULE_INFERENCE`，其证据仍指向组成路径的静态事实。文字指令不等于执行事实，
静态调用也不等于已观察到行为。

## 4. 图构建

### 4.1 文件 fragment

每个文件独立生成 fragment：File 节点、语言事实节点和文件内关系。构建器复用 P11 专用解析器，
不把全部文件转成纯文本：

- Markdown：Instruction、安全约束、路径与端点；
- Python/JavaScript：Function、调用 Tool、READS/WRITES、Endpoint；
- YAML/JSON：Permission、Endpoint、Dependency Tool；
- References：内部 File→File 和外部 File→Endpoint。

Python 相对 import 和唯一函数名调用在全局组装阶段解析为 REFERENCES/CALLS。无法唯一解析的调用保持
INVOKES Tool，不强行连接任意函数。

### 4.2 增量复用

先按原始文件 SHA-256 比较版本：

- 字节未变文件：复用旧 fragment，并把证据快照侧转换为 NEW；
- 新增或修改文件：重新运行专用分析器；
- 删除文件：不进入新图；
- REFERENCES、CALLS 和跨文件 CONNECTS_TO：全局重建。

`IncrementalStats` 记录 changed、reused、recomputed 文件以及全局重建关系。测试要求增量新图与
独立全量重建的新图完全一致，不能用缓存命中牺牲正确性。

## 5. 对齐

节点分三层对齐：

1. `EXACT_SEMANTIC_KEY`：类型和稳定语义键完全相同；
2. `FILE_CONTENT_RENAME`：未匹配 File 的原始内容摘要唯一相同；
3. `FUNCTION_STRUCTURE`：未匹配 Function 的结构指纹唯一相同，允许函数/文件重命名。

歧义摘要或指纹不自动匹配。函数同名但函数体重构仍由稳定语义键对齐，属性变化可由后续 modified
分析扩展。关系对齐先映射旧端点，再要求关系相同；语义键相同优先，唯一候选次之。

`added_nodes/edges` 和 `removed_nodes/edges` 基于 Alignment，而不是裸 ID 集合差，因此重命名不会自动
被计作新能力。

## 6. 风险路径语义

当前四种版本化模板：

### 6.1 SENSITIVE_DATA_TO_ENDPOINT

一个 Function 或其静态 `CALLS` 闭包同时存在：

- `READS → Data[SENSITIVE_DATA]`；
- `CONNECTS_TO → Endpoint`。

闭包深度上限为 6，支持敏感数据读取和发送逻辑分布在不同文件。路径解释只称“可能读取并连接”，
不声称真实传输或恶意意图。

### 6.2 PROCESS_TOOL_INVOCATION

Function/File 通过 INVOKES 连接带 `PROCESS_EXECUTION` 标签的 Tool。标签来自 AST 调用名的静态事实
或可审计命名规则；不会执行命令。

### 6.3 INSTRUCTION_TO_RISK_CAPABILITY

Instruction 可沿 `INSTRUCTS → REFERENCES → CALLS` 搜索至风险相关 INVOKES、READS 或 CONNECTS_TO。
深度上限为 7，支持 `SKILL.md → references/usage.md → scripts/main.py → helper function`。

### 6.4 PERMISSION_ENABLES_RISK_CAPABILITY

配置 Permission 为 allow/true/enabled，并通过规则推断 GRANTS 到风险相关 Tool。deny 约束不会生成
GRANTS 路径。

每条路径必须至少包含一个对齐后确认的新增节点或新增边，否则不会作为“新增风险路径”输出。
这条条件与语义模板同时成立，集合差永远不能单独触发路径。

## 7. 对照方法

`skillupdate.behavior_graph.comparison` 提供：

| 方法 | 范围 | 限制 |
|---|---|---|
| Single-file Detection | 仅单文件拥有的新增边和非跨文件路径 | 看不到协同路径 |
| Multi-file Text Detection | 所有变化文本的关键词共现 | 无节点、边或数据流语义 |
| Dependency Graph | File/Function 与 REFERENCES/CALLS | 不输出风险路径 |
| Incremental Behavioral Graph | 完整节点、关系、对齐和语义路径 | P12 主方法 |

四种方法都不读取 Ground Truth。评价阶段把预测的 node/edge/path 语义键与独立标注集合比较。

## 8. 评价指标

- Node Precision / Recall：新增节点语义键的准确率和召回率；
- Edge Precision / Recall：新增关系语义键的准确率和召回率；
- Path Precision / Recall：新增风险路径语义键的准确率和召回率；
- False Positive Rate：错误风险路径数除以错误路径数加明确的负路径机会数。

空预测 Precision 定义为 0；Ground Truth 集合为空时 Recall 定义为 1。正式实验必须报告计数分母、
Alignment 失败、UNKNOWN、处理时间和缓存复用率，不能只报告 Path Recall。

## 9. 测试与限制

专项测试覆盖单文件风险、双文件协同、多文件协同、指令/脚本分离、References 间接引用、无关文件修改、
节点/文件重命名、函数重命名和函数体重构，并检查增量图等于全量重建。

P12 仍是静态研究原型。动态派发、反射、别名复杂调用、computed JavaScript property、配置模板展开和
高阶数据流可能无法解析。调用闭包和指令搜索有深度上限，函数名规则可能产生近似；这些限制需要在正式
实验中作为覆盖/UNKNOWN 报告。Pilot 数据只能验证受控行为，不能支持真实市场泛化结论。
