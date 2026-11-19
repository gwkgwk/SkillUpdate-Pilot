# P14：Risk-Guided Dynamic Verification

## 1. 范围

P14 根据 P12 新增语义风险路径选择动态验证对象，并在相同输入、任务摘要、权限摘要、镜像和资源策略下，
分别运行旧版本与新版本的受控 Mock scenario。当前实现只接受仓库内标记为 `CONTROLLED_MOCK` 的 fixture，
固定 harness 不 import 或执行 Skill 入口。公开市场下载的 Skill、真实恶意程序、安装脚本和 LLM 生成命令
仍被禁止。

动态结果是补充证据，不是安全证明。`NOT_OBSERVED` 仅表示本次有界 Mock 测试没有产生新事件，不能推出
Skill 安全。

## 2. 风险引导计划

`RiskGuidedPlanner` 消费 `BehavioralGraphDelta.new_risk_paths`：

| 风险级别 | 选择条件 | 行为 |
|---|---|---|
| LOW | 没有新增语义风险路径 | `execution_required=false`，verifier 禁止启动容器 |
| MEDIUM | 有新增路径但没有敏感数据、传输或进程高风险 | 只启用匹配的定向事件类别 |
| HIGH | 涉及敏感数据、数据传输或进程执行 | 启用全部六类有界 Mock 事件 |

计划包含 path IDs、risk types、事件类别、old/new fixture 内容 SHA-256、相同的 `ExecutionContext`、
完整 `SandboxPolicy` 和理由。执行前重新计算两个 fixture 摘要，防止签发 permit 后替换 scenario。
`ExecutionPermit.plan_sha256` 必须等于计划规范 JSON 的 SHA-256；修改任何镜像、预算、输入或类别都会使
permit 失效。

## 3. Docker 安全边界

`DockerSandboxRunner` 生成参数数组，不使用 shell，并强制：

- 本地镜像使用不可变且经过 P14 allowlist 审核的 `sha256:<image-id>`，`--pull never` 禁止隐式 pull；
- `--entrypoint python` 覆盖镜像声明的 ENTRYPOINT，只启动固定只读 harness；
- `--user 65532:65532`，禁止 root；
- `--network none`，容器内只出现 loopback；
- `--read-only`，harness 和 fixture 仅只读 bind mount；
- 唯一写空间为 `/tmp` 的 `noexec,nosuid,nodev` 限额 tmpfs；
- `--cap-drop ALL`、`no-new-privileges=true`、Docker builtin seccomp 和 AppArmor；
- CPU、memory、memory-swap、PID、nofile 和宿主墙钟超时限制；
- 只显式传入 `FAKE_API_TOKEN`、HOME 和 Python 确定性配置，不继承宿主环境；固定 harness 在读取
  fixture 前再次删除所有非白名单镜像环境变量；
- 不挂载 home、Docker socket、SSH、云凭据、API secret 或可写宿主目录；
- 超时后只对 CID 文件中校验为十六进制的本次容器执行强制清理。

容器内 attestation 记录真实 UID/GID、`CapEff`、`NoNewPrivs`、Seccomp mode、AppArmor profile、接口名、
环境变量名、只读根写入失败和 tmpfs 写入成功。任一强制条件不成立时，运行结果为 FAILED。

## 4. 固定 Mock harness

fixture 目录只能包含小于 64 KiB 的 `manifest.json` 和 `scenario.json`，不得包含 symlink，并且必须位于
显式 approved root。action 只有以下白名单：

| Action | 事件 | 安全语义 |
|---|---|---|
| `file_access` | FILE_ACCESS | 只读写容器 tmpfs 中的合成文件 |
| `process_creation` | PROCESS_CREATION | 仅记录 `spawned=false`，不调用 subprocess |
| `network_event` | NETWORK_EVENT | 仅接受 `mock://`，记录 `socket_opened=false` |
| `tool_invocation` | TOOL_INVOCATION | 仅记录 `mock-tool://` 工具 |
| `mock_data_access` | MOCK_DATA_ACCESS | 只读取 `FAKE_` 凭据，输出其摘要而非值 |
| `mock_transfer` | NETWORK_EVENT + MOCK_TRANSFER_EVENT | 内存 staging，`transmitted=false` |

target 必须使用 action 对应的 synthetic/mock scheme。fixture 文本不能更改 harness 逻辑，不能携带可执行
命令，也不能选择容器参数。

## 5. Old/New 对称执行与 Delta

旧、新版本使用同一 `ExecutionContext`、`SandboxPolicy` 和选中事件集合。事件规范键为：

```text
(category, operation, target, canonical(detail))
```

按 multiset count 计算 `new - old`，分别输出 ADDED、REMOVED、UNCHANGED。每个选中类别输出：

- `OBSERVED`：至少一个规范事件仅在新版本新增，并保留 new event IDs；
- `NOT_OBSERVED`：未观察到新增事件，不代表安全；
- `UNKNOWN`：任一匹配运行失败或证据无法验证。

原始事件保存 side、category、operation、synthetic target、detail、event ID 和
`CONTAINER_MOCK_HARNESS` evidence source。运行结果同时保存完整 Docker 参数、命令摘要、stdout/stderr
摘要、exit code、耗时和 attestation。

## 6. 测试

默认测试验证规划、permit 绑定、Docker 参数、非 root attestation、approved-root 拒绝、LOW 不调用 runner、
multiset delta 以及 OBSERVED/NOT_OBSERVED。真实 Docker 集成需显式启用：

```bash
SKILLUPDATE_RUN_DOCKER_TESTS=1 pytest -q tests/dynamic/test_docker_integration.py
```

集成 fixture 的旧版本只有 FILE_ACCESS/TOOL_INVOCATION；新版本新增 synthetic data、Mock transfer 和
Mock process request。预期四类新增事件为 OBSERVED，两个共有类别为 NOT_OBSERVED，且所有 process、socket、
transfer detail 均证明实际动作未发生。

## 7. 限制

- P14 验证的是安全 sandbox、差分管线和 Mock 行为可观测性，不是公开 Skill 的真实执行效果。
- Docker daemon 属于受信执行基础设施；生产实验还需固定 daemon、kernel、镜像 SBOM 与主机 attestation。
- 当前没有允许真实网络的模式；Mock endpoint 不监听 socket。
- NOT_OBSERVED、超时或 fixture 覆盖不足不能支持 BENIGN 结论。
