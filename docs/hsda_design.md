# Heterogeneous Semantic Differential Analysis（P11）

## 1. 目标与边界

HSDA 分析一个 Skill 的旧、新目录之间具有安全意义的异构语义变化。它分别处理 Markdown、
Python、JavaScript/TypeScript、YAML、JSON 和跨文件引用，不把所有文件先降级成统一纯文本。
公共入口为：

```python
from skillupdate.hsda import HSDAAnalyzer

report = HSDAAnalyzer().analyze(old_skill_directory, new_skill_directory)
```

可选 `output_dir` 会写入 `hsda_report.json` 和 `raw.diff`；目录必须尚不存在，避免覆盖审计结果。
HSDA 只静态解析，不 import Skill、不运行入口、不解释 shell、不联网，也不调用 LLM。

报告的六类主要输出是：结构变化、语义变化、权限变化、代码行为变化、引用关系变化和安全证据。
此外保留 `unknown_changes`、解析问题、逐文件原始 unified diff、快照摘要、处理时间以及零 token 计数。

## 2. 事实、变化和证据模型

语言分析器先产生 `SemanticFact`，再由引擎按 `(file, kind, key)` 对齐旧、新事实：

- 仅新侧存在：`ADDED`；
- 仅旧侧存在：`REMOVED`；
- 稳定键相同但值或属性变化：`MODIFIED`；
- 无法可靠解析或覆盖：`UNKNOWN`。

每个事实和变化至少绑定一个 `SourceLocation`：快照侧、相对文件、1-based 闭区间行号和原始摘录。
新增事实引用新侧，删除事实引用旧侧，修改事实同时引用两侧。Change 不允许存在无来源的自然语言总结。

证据基础值明确区分 `STATIC_MARKDOWN`、`STATIC_PYTHON_AST`、
`STATIC_JAVASCRIPT_AST`、`STATIC_YAML`、`STATIC_JSON`、`STATIC_REFERENCE` 和
`STATIC_FILE_METADATA`。P11 的 HSDA 输出只包含 `FACT` 或 `UNKNOWN`；
`LLM_INFERENCE` 仅供独立 LLM 对照使用，不能伪装成 AST/配置事实。

安全相关变化生成单独的 `SecurityEvidence`，引用原 Change、风险类型、断言和全部位置。
风险类型描述静态可见的能力或约束变化，例如 `FILE_OPERATION`、`NETWORK_OPERATION`、
`PROCESS_OPERATION`、`PERMISSION_CHANGE`、`ENDPOINT_CHANGE`、`SECURITY_CONSTRAINT`、
`INDIRECT_INSTRUCTION_CHANGE`。静态调用事实不等于该行为已在运行时发生。

## 3. 文件类型分析器

### 3.1 Markdown

使用 CommonMark token parser，分别保留标题、段落、列表、列表项、围栏代码块和 HTML 注释。
指令与安全约束是基于块的静态分类，保留所属标题上下文和原始行号。Markdown 链接分别标记为
内部或外部引用。指令事实不会因清理 Markdown 格式而丢失，代码块和注释也不会被删除。

指令/约束规则是可审计的 P11 初版启发式，不是自然语言意图的完备证明。无法确定是否构成恶意
指令时，只陈述文本事实或后续输出 UNKNOWN，不把关键词命中直接称为已执行攻击。

### 3.2 Python

使用标准库 `ast.parse(type_comments=True)`，提取函数定义及签名、imports、函数调用和字符串字面量；
使用 `tokenize` 独立保留注释。调用目标按静态名称分为文件、网络和进程相关操作，所有调用保留
原始表达式及 AST 行范围。分析器不 import 模块，也不执行 decorators、默认参数或任意表达式。

语法失败产生 `PYTHON_SYNTAX_ERROR`、`PARSE_UNKNOWN` 和 `UNPARSED_CODE`，不回退成“无风险”。

### 3.3 JavaScript/TypeScript

通过受限 Node 子进程调用项目锁定的 `@babel/parser`，解析 JS、MJS、CJS、JSX、TS 和 TSX。
Bridge 只读取 stdin 的源码 JSON 并遍历 AST，提取 imports、函数定义、函数调用、字符串/模板文本和注释；
它不加载或求值被分析代码。子进程限制为 5 秒、128 MiB Node heap、1 MiB 单文件输入，并使用最小环境。

解析失败、超时或 parser 缺失分别产生 UNKNOWN 问题。JS 静态调用同样只表示可能行为，不是动态观察。

### 3.4 YAML/JSON

YAML 使用 `SafeLoader` 的 compose tree，不构造任意 Python 对象；JSON 使用标准 parser。
分析器递归产生字段路径和原始行号，区分普通字段、权限字段、端点字段和依赖字段。
YAML 注释作为事实保留，字符串值不做脱敏式删除。非法配置产生 UNKNOWN，而不是空配置。

初版 JSON 行号通过源文件中解析后的 key 出现次序映射；重复键本身不应被接受为可信配置语义，
复杂重复键场景属于后续需要强化的覆盖限制。

### 3.5 References

Reference Analyzer 独立追踪 `scripts/`、`references/`、`config/`、`assets/` 路径和 URL/mock URI，
记录目标、来源行、内部目标是否存在以及外部属性。若一个未变化的引用源指向已变化目标，HSDA 生成
`INDIRECT_REFERENCE_CHANGE`，证据同时包含引用行和目标文件范围。

引用存在只表示静态关系，不授权联网、读取外部内容或执行目标。未解析内部目标作为安全相关事实保留。

### 3.6 不支持的文件

P11 未提供专用分析器的文件不会被忽略。其内容摘要以 `STATIC_FILE_METADATA` 记录，覆盖状态为
UNKNOWN；如果文件发生变化，报告包含 `UNSUPPORTED_FILE_TYPE`/`UNPARSED_CHANGED_FILE` 证据。

## 4. 原始 Diff 与审计

引擎对每个新增、删除或修改文件保存原始 unified diff，不使用 AST 或规范化文本替代它。
每项 `RawFileDiff` 包含相对文件、变化类型、完整 diff 和 SHA-256。落盘时还把所有 diff 合并为
`raw.diff`，报告内仍保留逐文件版本。原始 Diff 用于复核语义提取遗漏，不作为 HSDA 的唯一输入表示。

快照摘要按排序后的 `relative_path + NUL + file_sha256` 计算。输入拒绝 symlink，并限制文件数与总字节。

## 5. 四种对照方法

`skillupdate.hsda.comparison` 提供统一 `compare(old_directory, new_directory)`：

| 方法 | 输入表示 | 证据基础 | Token |
|---|---|---|---|
| Text Diff | 原始行级 SequenceMatcher | `TEXT_LINES` | 0 |
| AST Diff | 仅 Python/JavaScript AST facts | `PYTHON_AND_JAVASCRIPT_AST` | 0 |
| LLM Direct Comparison | 旧、新全部文件交给显式注入 client | `LLM_INFERENCE` | client usage |
| HSDA | 全部专用分析器、引用和 UNKNOWN | `STATIC_FACT_OR_UNKNOWN` | 0 |

LLM Direct 默认无 client，返回 `LLM_DISABLED_UNKNOWN` 和空预测，不进行网络调用。注入 client 后，
其 changes/evidence 仍标记为推断，不进入 HSDA 静态事实。四种方法必须使用同一版本对和同一 Ground
Truth；Ground Truth 只传给独立评价函数，绝不传入 `compare` 或 HSDA Analyzer。

## 6. 评价指标

`evaluate_comparison` 使用明确的 change key 和 evidence key 集合：

- Change Precision = 正确预测变化数 / 全部预测变化数；
- Change Recall = 正确预测变化数 / 全部人工变化数；
- Change F1 = Precision 与 Recall 的调和平均；
- Evidence Recall = 命中的人工证据位置数 / 全部人工证据位置数；
- Processing Time = 方法内部单调时钟毫秒；
- Token Cost = input tokens + output tokens；静态方法为 0。

空预测时 Precision 为 0；无 Ground Truth change/evidence 时相应 Recall 定义为 1。正式实验必须同时报告
分母、UNKNOWN、解析失败和覆盖，不能只报告 F1。若需要货币成本，应另用固定模型价格表从 token usage
派生，不能把 token 数直接称为美元成本。

## 7. 当前限制与后续输入

P11 是可测试的首版静态算法，不声称自然语言指令识别、跨语言调用解析或动态可达性已经完备。
函数/指令事实主要以稳定名称和顺序匹配；大规模重排可能表现为多条 added/removed。JavaScript 动态 import、
反射、computed property，Python 动态执行，以及配置模板展开可能产生 UNKNOWN 或静态近似。

正式对照实验还需要独立人工 change/evidence Ground Truth、冻结的 LLM direct provider/model/prompt/budget、
版本化实验 manifest 和明确的 UNKNOWN 计分策略。SkillUpdateBench 的 20-family Pilot 只能用于受控验证，
不能支持大规模真实市场性能结论。
