# 智能合约审计与形式化验证流水线

## 用途

合约产物与 ABI 管理、静态规则与模式库、符号执行与模糊测试编排、不变式检查、缺陷归因与报告版本化。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `contractsentinel/`，命令入口位于 `cmd/contractsentinel/`。

```bash
go run ./cmd/contractsentinel demo
go run ./cmd/contractsentinel version
go test ./...
```

## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。

仓库自带同名可执行文件 `./cs`，下面的命令也可以把 `go run ./cmd/contractsentinel` 整体替换成 `./cs`，输出完全一致。

## 导入检查器已给出的逐规则检查结果

`audit` 除了接收 `invariants` 不变式布尔值，还可以通过提交里的 `checks` 数组**导入外部检查器已经得出的逐规则结论**，再用 `report` 按返回的报告标识读回。

请注意这条功能边界：`checks` 只负责**接收和归档检查器已经给出的结果**，提交本身不会启动任何符号执行或模糊测试，也不会重新判定规则。状态、说明和归属都以提交内容为准；工具是否真的运行过，由调用方负责。

### 一条 checks 记录的字段

| 字段 | 含义 |
| --- | --- |
| `artifactHash` | 该结论是针对哪一份合约产物得出的，必须等于本次提交产物算出的内容哈希 |
| `ruleId` | 结论所属规则的 `id`，必须能在本次 `rules` 中找到 |
| `version` | 结论所针对的规则版本，必须与该规则的 `version` 完全一致 |
| `status` | 检查器给出的结论，取值见下表 |
| `note` | 检查器的原始说明，逐字保留，不会被改写或套模板 |

可导入的 `status` 只有四种：

| status | 含义 | 是否需要非空白 `note` | 是否进入 `findings` |
| --- | --- | --- | --- |
| `通过` | 检查完成，未发现问题 | 否，可以不带说明 | 否 |
| `发现缺陷` | 检查完成并确认缺陷 | 是，通常写反例说明 | 是，逐字成为该缺陷的 `evidence` |
| `工具缺失` | 缺少执行检查所需的工具，检查没能完成 | 是 | 否，只保留在规则结果中 |
| `超时` | 检查超过截止时间，**同样属于未得到正常结论** | 是 | 否，只保留在规则结果中 |

说明：

- `通过`记录可以没有说明；其余三种可导入状态（`发现缺陷`、`工具缺失`、`超时`）都必须带**非空白**说明，纯空格也算缺失。
- 只有 `发现缺陷` 的规则会进入报告的 `findings`。`工具缺失`和`超时`只是检查没拿到正常结论，仍保留在该规则的结果里，它们的原始 `note` 不会被当成缺陷、也不会被搬进 `findings` 充当缺陷证据。缺陷记录的 `note` 会逐字复制为缺陷 `evidence`，不会被替换成自动生成的 `invariant ... does not hold` 模板。
- `未检查` **不是可导入的结论**，不能写进 `checks`；它表示某条规则既没有 checks 记录、也没有不变式布尔值时报告给出的默认状态。

### 完整示例输入

把下面内容存为 `audit.json`。其中产物、规则版本与 `checks` 里的哈希、版本是相互绑定的，可直接使用，不必手算或留空：

```json
{
  "artifact": {
    "name": "Vault",
    "abi": "[{\"name\":\"withdraw\",\"type\":\"function\"}]",
    "bytecode": "0x60806040",
    "source": "contract Vault {\n}\n"
  },
  "rules": [
    {"id": "reentrancy-guard", "kind": "static", "severity": "high", "invariant": "no-reentrant-withdraw", "requiresABI": false, "version": "2.0.1"},
    {"id": "symbolic-balance", "kind": "symbolic", "severity": "critical", "invariant": "balance-monotonic", "requiresABI": false, "version": "0.9.2"},
    {"id": "access-control", "kind": "static", "severity": "medium", "invariant": "owner-only-withdraw", "requiresABI": true, "version": "1.4.0"},
    {"id": "tx-origin", "kind": "static", "severity": "info", "invariant": "no-tx-origin", "requiresABI": false, "version": "3.1.0"},
    {"id": "unchecked-demo", "kind": "static", "severity": "low", "invariant": "unchecked-demo-inv", "requiresABI": false, "version": "1.0.0"}
  ],
  "invariants": {},
  "checks": [
    {"artifactHash": "f27a8fc31b5d7ce8fb7f52fcb714b84dd373d3080b89562d8b605ff382fb1894", "ruleId": "reentrancy-guard", "version": "2.0.1", "status": "发现缺陷", "note": "反例：攻击者利用 fallback 回调在 withdraw 执行完成前重入，重复通过余额检查并提空资金"},
    {"artifactHash": "f27a8fc31b5d7ce8fb7f52fcb714b84dd373d3080b89562d8b605ff382fb1894", "ruleId": "symbolic-balance", "version": "0.9.2", "status": "工具缺失", "note": "未找到符号执行引擎 mythril，可执行文件不在 PATH 中"},
    {"artifactHash": "f27a8fc31b5d7ce8fb7f52fcb714b84dd373d3080b89562d8b605ff382fb1894", "ruleId": "access-control", "version": "1.4.0", "status": "超时", "note": "检查超过 60s 截止时间，未得到正常结论"},
    {"artifactHash": "f27a8fc31b5d7ce8fb7f52fcb714b84dd373d3080b89562d8b605ff382fb1894", "ruleId": "tx-origin", "version": "3.1.0", "status": "通过"}
  ]
}
```

这份示例里：`reentrancy-guard` 是一条带反例说明的**发现缺陷**，`symbolic-balance` 是一条**工具缺失**；另有一条`超时`、一条不带说明的`通过`，以及一条没有任何记录的规则 `unchecked-demo`（在报告中为`未检查`）。

提交到本机某个报告目录（离线即可，不需要任何工具或网络）：

```bash
go run ./cmd/contractsentinel audit --input audit.json --store reports
```

成功时整份报告打印到标准输出，并落盘到 `reports/<reportId>.json`。上面这份固定输入会确定性地得到：

- `artifactHash` = `f27a8fc31b5d7ce8fb7f52fcb714b84dd373d3080b89562d8b605ff382fb1894`
- `reportId` = `e8555e7258f4bd56d351569453bb112ef477be3a65dfd87a013630730b23cfd6`

#### artifactHash 与 reportId 的区别

- **artifactHash** 只绑定 `abi`、`bytecode`、`source` 三个字段的**字符串内容**（按长度前缀后做 SHA-256）。合约的 `name` 不参与哈希，因此改名字不改变产物哈希，但改动 ABI、字节码或 source 中任何一个字符都会改变它。`source` 就是**提交进去的字符串值本身**——即使把它写成一个文件名，程序也不会据此去磁盘读取本地源码；上面示例里它就是 `contract Vault {`、空行、`}` 这几行文本。
- **reportId** 标识**整份报告**：除产物哈希外，还绑定合约名、全部规则定义、每条规则的状态/版本/说明以及 findings。它用于从指定的报告目录里定位这份报告。

报告中可重点确认：缺陷只来自 `reentrancy-guard`，`findings` 恰有一条，且证据就是提交的反例原文；`工具缺失`和`超时`不出现在 `findings` 中：

```json
{
  "rules": [
    {"id": "reentrancy-guard", "version": "2.0.1", "status": "发现缺陷", "note": "反例：攻击者利用 fallback 回调在 withdraw 执行完成前重入，重复通过余额检查并提空资金"},
    {"id": "symbolic-balance", "version": "0.9.2", "status": "工具缺失", "note": "未找到符号执行引擎 mythril，可执行文件不在 PATH 中"}
  ],
  "findings": [
    {
      "artifactHash": "f27a8fc31b5d7ce8fb7f52fcb714b84dd373d3080b89562d8b605ff382fb1894",
      "ruleId": "reentrancy-guard",
      "version": "2.0.1",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "evidence": "反例：攻击者利用 fallback 回调在 withdraw 执行完成前重入，重复通过余额检查并提空资金"
    }
  ]
}
```

### 按 reportId 读回报告

用成功输出里的 `reportId`（不是 `artifactHash`）从同一报告目录读回：

```bash
go run ./cmd/contractsentinel report \
  --store reports \
  --id e8555e7258f4bd56d351569453bb112ef477be3a65dfd87a013630730b23cfd6
```

读回不会重新解释结论，规则状态、版本和缺陷证据与提交成功时逐项一致。可以在输出中直接看到每条规则的 `status`、`version` 以及缺陷的 `evidence`，而不只是缺陷数量，例如：

```json
{
  "id": "reentrancy-guard",
  "version": "2.0.1",
  "status": "发现缺陷",
  "note": "反例：攻击者利用 fallback 回调在 withdraw 执行完成前重入，重复通过余额检查并提空资金"
}
```

```json
{
  "id": "symbolic-balance",
  "version": "0.9.2",
  "status": "工具缺失",
  "note": "未找到符号执行引擎 mythril，可执行文件不在 PATH 中"
}
```

### 提交失败的条件

下列情况都会使**整份提交失败**：命令以非零状态退出，原因写入标准错误，标准输出没有报告内容，也不会产生成功报告（连报告目录都不会被创建，已有的报告文件不受影响）。

- **产物哈希不匹配**：任一 checks 记录的 `artifactHash` 不等于本次产物实际算出的哈希。

  ```text
  audit failed: check for rule symbolic-balance: artifact hash mismatch
  ```

- **规则版本不匹配**：任一 checks 记录的 `version` 与同名规则当前的 `version` 不一致。

  ```text
  audit failed: check for rule reentrancy-guard: version mismatch
  ```

- **同一条规则同时走了两种结论通道**：某规则既有 checks 记录，又在 `invariants` 中收到了它所引用的那个不变式布尔值。这同样整份失败，系统**不会**在两种结论之间自动挑一个：

  ```text
  audit failed: rule reentrancy-guard: both a check record and an invariant value are provided
  ```

此外，checks 引用了未知规则、同一规则出现多条记录、写入了四种之外的状态（包括把`未检查`当作结论提交）、或三种要求说明的状态只给了空白说明，也都会整份拒绝。

### 与原有不变式布尔值用法的关系

此前只提交 `invariants` 布尔值（不提供 `checks`）的用法仍然完全有效：不变式为 `false` 的规则记为`发现缺陷`，其证据为自动生成的 `invariant <名称> does not hold`；为 `true` 记为`通过`。新增的 checks 导入**不改变**输入格式、报告内容或现有命令的行为——`demo`、`version`、`audit`、`report`、`diff` 均保持原样。

