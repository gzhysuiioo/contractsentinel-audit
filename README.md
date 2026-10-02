# 智能合约审计与形式化验证流水线

## 用途

合约产物与 ABI 管理、静态规则与模式库、符号执行与模糊测试编排、不变式检查、缺陷归因与报告版本化。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `contractsentinel/`，命令入口位于 `cmd/contractsentinel/`。

```bash
go run ./cmd/contractsentinel demo
go run ./cmd/contractsentinel version
go run ./cmd/contractsentinel help
go run ./cmd/contractsentinel resolve <config.json> < request.json
go test ./...
```

`resolve` 从标准输入读取一个 JSON 请求（`method`、`target`），在离线状态下依据配置文件中的 `routes`（每条含 `id`、`methods`、`pathPrefix`、`upstream`）进行前缀匹配，并向标准输出输出命中的路由与上游地址：

```json
{"routeId":"orders","upstreamURL":"https://upstream.example.com/base/orders?x=1"}
```

失败时标准输出为空，标准错误输出含 `code`、`reason` 的 JSON 并以非零状态退出：`invalid_config`、`invalid_request`、`route_not_found`、`route_conflict`（冲突时另含按 id 排序的 `candidates`）。

## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
