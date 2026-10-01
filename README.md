# 智能合约审计与形式化验证流水线

## 用途

合约产物与 ABI 管理、静态规则与模式库、符号执行与模糊测试编排、不变式检查、缺陷归因与报告版本化。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `contractsentinel/`，命令入口位于 `cmd/contractsentinel/`。

```bash
go run ./cmd/contractsentinel demo
go run ./cmd/contractsentinel version
go test ./...
```

## 审计报告存档

`audit` 提交一次审计并保存报告，`report` 按标识读取已保存报告：

```bash
go run ./cmd/contractsentinel audit --input submission.json --store ./reports
go run ./cmd/contractsentinel report --store ./reports --id <报告标识>
```

提交文件是一个 JSON 对象：`artifact`（name/abi/bytecode/source）、`rules`（在现有规则字段上另带非空 `version`）、`invariants`（名称到布尔值的映射）。报告记录产物内容哈希（SHA-256，仅覆盖 ABI、字节码、源码的原始内容并区分字段边界）、每条规则的检查状态（未检查/通过/发现缺陷）以及绑定了产物哈希、规则标识、版本与证据的发现。报告标识由产物哈希、名称、完整规则定义和各规则实际使用的不变式值共同决定：同一输入重复提交得到同一标识和逐字节相同的报告，规则顺序与无关不变式键不影响结果。相同报告只保留一份；写入经临时文件原子提交，并发提交与中断重试均安全；内容被篡改（包括发现证据）的存档在读取和再次提交时都会报错且不被覆盖。

## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
