# 智能合约审计与形式化验证流水线

## 用途

合约产物与 ABI 管理、静态规则与模式库、符号执行与模糊测试编排、不变式检查、缺陷归因与报告版本化。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `contractsentinel/`，命令入口位于 `cmd/contractsentinel/`。

```bash
go run ./cmd/contractsentinel demo
go run ./cmd/contractsentinel version
go test ./...
```

## audit 输入

`audit --input <file> --store <dir>` 接受 JSON：`artifact`、`rules`、`invariants`
（不变式布尔值）以及可选的 `checks`（导入的既有检查结果）。每条 check 记录：

```json
{
  "artifactHash": "本次产物的内容哈希",
  "ruleId": "已知规则编号",
  "ruleVersion": "规则当前版本",
  "status": "通过 | 发现缺陷 | 工具缺失 | 超时",
  "note": "缺陷证据/反例；工具缺失或超时说明哪个工具不可用或哪项检查未完成"
}
```

`发现缺陷`、`工具缺失`、`超时` 的 `note` 必须含非空白字符；`通过` 可为空。
只有 `发现缺陷` 生成发现记录并使用提交的证据；`工具缺失`/`超时` 不计入缺陷，
也不阻止其他规则产生结果。未知规则、重复记录、未知状态、必需说明为空、哈希或
版本不一致、同一规则同时给出 check 和不变式布尔值，都会拒绝整次提交且不写存档。

报告逐条展示状态与原始说明；报告编号绑定状态与说明，内容相同则编号相同，旧的
纯布尔输入报告编号保持不变，旧存档可直接读取与比较。`diff` 在规则定义相同的
前提下：只有 `通过`↔`发现缺陷` 计为新发现/已消除缺陷；`工具缺失`/`超时` 与其他
状态的切换计为检查状态变化；状态相同而说明不同计为检查说明变化并单独汇总。

## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
