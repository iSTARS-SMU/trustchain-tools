# trustchain-contracts

所有外部契约的 **Pydantic + JSON Schema 单一真源**。发布为 pip 包 `trustchain-contracts`。

**在此定义的东西动了 = 所有 engine 可能要跟着动。按 semver 严格管理。**

## 里面放什么

| 文件 | 内容 |
|---|---|
| `domain.py` | TargetRef / Project / Task / Run / Finding / Artifact |
| `stages.py` | ReconOutput / Weakness / AttackPlan / ExploitResult / FindingCandidate / ReportInput |
| `events.py` | Event schema + EventKind 枚举 + 各 kind 的 payload 类型 |
| `engine.py` | EngineYamlSpec(engine.yaml 的顶层形状)+ RunContextEnvelope + EngineResult |
| `tools.py` | Tool client 的 request / response 接口 |
| `signatures.py` | `compute_signature(vuln_type, evidence)` — Finding location_signature 的统一算法 |

## 不在此放的

- 业务逻辑 / 算法(在 engine 各自仓)
- 核心实现(core 内部 module)
- SDK 辅助类(见 `../sdk/`)

## 版本规则
- semver。版本号在 `pyproject.toml`
- 加 Optional 字段:patch/minor
- 改字段语义 / 删字段:major(全员升级)
- 发布:`python -m build` + 推到私有 index

## 被谁依赖
- `trustchain-sdk` (pip 依赖)
- 每个 engine 的仓(pip 依赖)
- `trustchain/core/*`(本 monorepo 内部 editable install)
- `trustchain/tests/contract/*`

对应 spec:[§3.4 Stage I/O Contracts](../../doc/spec.md)、[§7 事件模型](../../doc/spec.md)、[engine-contract.md](../../doc/engine-contract.md)。
