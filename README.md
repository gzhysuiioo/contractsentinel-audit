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

## 导入外部检查器的逐规则结论

除了 `demo` 与 `version`，`audit` 命令还接受一条 **audit 提交**（一个 JSON 文件），把外部检查器**已经给出的**逐规则结论导入流水线并落盘成报告，随后可用 `report` 命令按报告标识读回。

请注意这条功能的边界：

- 提交内容是检查器**已经得出的结论**。`audit` 只做绑定校验、归因和报告版本化，**提交本身不会启动符号执行，也不会启动模糊测试**；工具缺失、超时等现场情况由提交者如实记录。
- 每条结论必须绑定**产物哈希**与**带版本的规则**，发现（finding）不可事后改写。
- 命令完全离线运行：`./cs audit ...` 与 `go run ./cmd/contractsentinel audit ...` 等价，报告写入 `--store` 指定的报告目录，文件名为 `<reportId>.json`。

### 提交 JSON 的结构

- `artifact`：合约产物，含 `name`、`abi`、`bytecode`、`source` 四个字符串字段。
- `rules`：本次适用的规则数组，每条规则必须有非空 `id` 与 `version`，`id` 在数组内唯一；`requiresABI` 为真时产物必须有非空 `abi`，`kind` 为 `symbolic` 时产物必须有非空 `bytecode`。
- `invariants`：不变式名到 JSON 布尔值的映射（既有用法，见文末）。
- `checks`：外部检查器给出的逐规则记录数组，每条记录含：
  - `artifactHash`：该结论所针对产物的哈希，必须与本次 `artifact` 实际算出的哈希一致；
  - `ruleId` / `version`：必须分别对应 `rules` 中已有的规则标识及其版本；
  - `status`：可导入的结论只有四种 —— `通过`、`发现缺陷`、`工具缺失`、`超时`；
  - `note`：检查器的原始说明。

结论与说明的规则：

- **`通过`** 可以没有说明（整个 `note` 字段可省略）。
- **`发现缺陷`、`工具缺失`、`超时`** 三种状态都必须带**非空白**说明；只有空格或换行的说明会使整份提交失败。
- **`超时` 同样属于检查未得到正常结论**，不是缺陷：它保留在规则结果里并必须附带截止时间等说明，但不会进入 `findings`。
- **`未检查` 不是可导入的结论**：把记录的 `status` 写成 `未检查` 会被当作未知状态拒绝。一条规则既没有 checks 记录、也没有不变式布尔值时，报告里才自然呈现 `未检查`。
- 只有 **`发现缺陷`** 记录进入报告的 `findings`；`工具缺失` 与 `超时` 只保留在规则结果中，绝不虚报成缺陷。
- 缺陷 finding 的证据（`evidence`）逐字采用该记录的原始 `note`（不修剪空格、不套模板改写）；原始 note 不会被改写成其他缺陷证据。

### 完整示例输入

把以下内容保存为 `audit-input.json`（`source` 是一个普通字符串值，里面的 `\n` 是 JSON 换行转义）：

```json
{
  "artifact": {
    "name": "Vault",
    "abi": "[{\"name\":\"withdraw\",\"type\":\"function\",\"stateMutability\":\"payable\"}]",
    "bytecode": "0x6080604052",
    "source": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Vault {\n    mapping(address => uint256) private balances;\n\n    function withdraw(uint256 amount) public {\n        (bool sent, ) = msg.sender.call{value: amount}(\"\");\n        require(sent, \"transfer failed\");\n        balances[msg.sender] -= amount;\n    }\n}\n"
  },
  "rules": [
    {
      "id": "reentrancy-guard",
      "kind": "static",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "requiresABI": false,
      "version": "1.4.2"
    },
    {
      "id": "owner-only-withdraw",
      "kind": "static",
      "severity": "medium",
      "invariant": "withdraw-owner-only",
      "requiresABI": true,
      "version": "2.1.0"
    },
    {
      "id": "solvency-symbolic",
      "kind": "symbolic",
      "severity": "critical",
      "invariant": "balances-cover-withdrawals",
      "requiresABI": false,
      "version": "0.9.3"
    }
  ],
  "invariants": {},
  "checks": [
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "status": "发现缺陷",
      "note": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "owner-only-withdraw",
      "version": "2.1.0",
      "status": "通过"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "solvency-symbolic",
      "version": "0.9.3",
      "status": "工具缺失",
      "note": "符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。"
    }
  ]
}
```

其中的关键绑定值相互对应、可直接使用，不是占位符：

- 三条 checks 记录里的 `artifactHash` 全部是
  `0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7`，
  它正是上面 `abi`、`bytecode`、`source` 三个字符串内容算出的产物哈希。
- 每条记录的 `version` 与同名规则的 `version` 一一对应（`1.4.2` / `2.1.0` / `0.9.3`）。
- `source` 就是**提交的字符串值本身**：即使把它写成一个文件名，程序也**不会**按文件名去磁盘读取本地源码，参与哈希的是字符串里的字符。产物的 `name`（`Vault`）**不参与**哈希计算。

### 提交并生成报告

```bash
mkdir -p reports
go run ./cmd/contractsentinel audit --input audit-input.json --store ./reports
```

在本机离线运行的成功输出（stdout）如下，报告同时落盘为
`./reports/a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34.json`：

```json
{
  "reportId": "a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34",
  "artifact": {
    "name": "Vault",
    "hash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7"
  },
  "rules": [
    {
      "id": "reentrancy-guard",
      "kind": "static",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "requiresABI": false,
      "version": "1.4.2",
      "status": "发现缺陷",
      "note": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    },
    {
      "id": "owner-only-withdraw",
      "kind": "static",
      "severity": "medium",
      "invariant": "withdraw-owner-only",
      "requiresABI": true,
      "version": "2.1.0",
      "status": "通过"
    },
    {
      "id": "solvency-symbolic",
      "kind": "symbolic",
      "severity": "critical",
      "invariant": "balances-cover-withdrawals",
      "requiresABI": false,
      "version": "0.9.3",
      "status": "工具缺失",
      "note": "符号执行引擎未安装：PATH 中未找到 mythril，无法求解 balances-cover-withdrawals。"
    }
  ],
  "findings": [
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "evidence": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    }
  ]
}
```

请分清输出中的两个标识：

- **`artifact.hash`（artifactHash）** 绑定 ABI、字节码和 source 字符串的**内容**，合约名称不参与。同一份产物内容无论出现在哪份报告里，这个哈希都相同；findings 中的 `artifactHash` 与它一致。
- **`reportId`** 是**整份报告**的内容寻址标识（产物哈希、名称、全部规则定义、每条规则的状态与版本、全部 findings 共同决定）。读回报告时用它，而不是用 artifactHash。

可以看到：`reentrancy-guard` 是带反例说明的唯一 `发现缺陷`，其证据就是提交时的原始 note；`solvency-symbolic` 仍是 `工具缺失`（版本 `0.9.3`，说明保留在规则结果中），不进 `findings`；`owner-only-withdraw` 为 `通过` 且无 note。

### 根据成功输出读回报告

用成功输出里的 `reportId`，从同一个报告目录读取：

```bash
go run ./cmd/contractsentinel report \
  --store ./reports \
  --id a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34
```

读回的是同一份完整报告 JSON（与提交成功时逐字段相同，不会被重新解释）。其中可以直接核对每条规则的**状态、版本**以及缺陷证据，例如：

- `reentrancy-guard`：`"version": "1.4.2"`、`"status": "发现缺陷"`，note 为反例原文；
- `owner-only-withdraw`：`"version": "2.1.0"`、`"status": "通过"`；
- `solvency-symbolic`：`"version": "0.9.3"`、`"status": "工具缺失"`，note 说明引擎缺失；
- `findings` 中只有一条，归属 `reentrancy-guard` / 版本 `1.4.2` / 产物哈希 `0cdb8997…3a8ca7`，`evidence` 是上面的完整反例说明——而不是仅仅一个缺陷计数。

### 提交失败条件（整份失败，不产生部分报告）

下列情况都会使**整份提交**被拒绝：命令以**非零状态退出**，原因写入**标准错误（stderr）**，stdout 没有任何报告片段，报告目录中**不会**出现成功报告（目录原本不存在时也不会被创建）。

1. **checks 记录的产物哈希不匹配。** 任一条记录的 `artifactHash` 不等于本次产物实际哈希即失败，即使其余记录都合法。例如把 `solvency-symbolic` 记录的哈希改成另一个 64 位十六进制串：

   ```text
   audit failed: check for rule solvency-symbolic: artifact hash mismatch
   ```

2. **checks 记录的规则版本不匹配。** 记录的 `version` 必须等于 `rules` 中该规则的版本；声称针对旧版本即失败：

   ```text
   audit failed: check for rule reentrancy-guard: version mismatch
   ```

3. **同一条规则既收到 checks 记录，又在 `invariants` 中收到它所引用的不变式布尔值。** 例如对 `reentrancy-guard` 既给 checks 记录、又给 `"invariants": {"no-reentrant-withdraw": false}`。这是冲突输入，会**整份失败**，不会被解释成“在两种结果之间自动选一个”：

   ```text
   audit failed: rule reentrancy-guard: both a check record and an invariant value are provided
   ```

此外，记录引用了 `rules` 中不存在的规则、同一规则出现多条 checks 记录、`status` 写成 `未检查` 等未知值（`unknown status …`）、或三种需要说明的状态给了空白说明（`note is required for status …`），同样整份拒绝。

## 仅提交不变式布尔值（既有用法，保持不变）

在 checks 导入能力之前就存在的用法仍然有效：提交只给 `invariants`（不变式名到布尔值的映射）而不给 `checks`。值为 `false` 的不变式使引用它的规则记为 `发现缺陷` 并生成 finding，证据为 `invariant <不变式名> does not hold`；值为 `true` 记为 `通过`；未出现的规则记为 `未检查`。

```json
{
  "artifact": {"name": "Vault", "abi": "[{\"name\":\"withdraw\"}]", "bytecode": "0x6080", "source": "Vault.sol"},
  "rules": [
    {"id": "reentrancy-guard", "kind": "static", "severity": "high", "invariant": "no-reentrant-withdraw", "requiresABI": false, "version": "1.0.0"}
  ],
  "invariants": {"no-reentrant-withdraw": false}
}
```

checks 导入的补充**不改变**输入格式、报告内容或现有命令的行为：上述提交的字段、生成的报告与报告标识都与以前一致。
