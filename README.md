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

- `artifact`：合约产物，含 `name`、`abi`、`bytecode`、`source` 四个字符串字段。字段可以省略（省略时按空字符串处理），但**一旦写出，值就必须是 JSON 字符串**：写成 `null`、布尔值、数字、对象或数组都会使整份提交失败，而不会被当成空字符串继续——见下文“产物字段不是字符串”。
- `rules`：本次适用的规则数组，每条规则必须有非空 `id` 与 `version`，`id` 在数组内唯一；`requiresABI` 为真时产物必须有非空 `abi`，`kind` 为 `symbolic` 时产物必须有非空 `bytecode`。`requiresABI` 可以省略（按 `false` 处理），但一旦写出就必须是 JSON 布尔值 `true` 或 `false`：`null`、字符串、数字、对象或数组都会使整份提交失败，而不会被当成 `false` 继续。规则的 `id`、`kind`、`severity`、`invariant`、`version` 五个文本成员同理：可以省略（省略时按空字符串并走既有必填/业务校验），但**一旦写出，值就必须是 JSON 字符串**，写成 `null`、布尔值、数字、对象或数组都会使整份提交失败，而不会被当成空字符串继续——见下文“规则定义的文本成员不是字符串”。
- `invariants`：不变式名到 JSON 布尔值的映射（既有用法，见文末）。
- `checks`：外部检查器给出的逐规则记录数组，每条记录含：
  - `artifactHash`：该结论所针对产物的哈希，必须与本次 `artifact` 实际算出的哈希一致；
  - `ruleId` / `version`：必须分别对应 `rules` 中已有的规则标识及其版本；
  - `status`：可导入的结论只有四种 —— `通过`、`发现缺陷`、`工具缺失`、`超时`；
  - `note`：检查器的原始说明。该成员可以省略，但**一旦写出，值就必须是 JSON 字符串**：写成 `null`、布尔值、数字、对象或数组都会使整份提交失败，而不会被当成空字符串继续——见下文“checks 记录的说明 `note` 不是字符串”。

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
- **`reportId`** 是**整份报告**的内容寻址标识：除产物哈希外还绑定产物**名称**、全部规则定义、每条规则的状态与版本、每条说明以及全部 findings。读回报告时用它，而不是用 artifactHash。规则与 findings 的**排列顺序不参与**标识计算（计算前按规则标识排序），所以仅调整排列的再次提交得到**同一个** `reportId`——见下文“仅调整排列后再次提交”。

可以看到：`reentrancy-guard` 是带反例说明的唯一 `发现缺陷`，其证据就是提交时的原始 note；`solvency-symbolic` 仍是 `工具缺失`（版本 `0.9.3`，说明保留在规则结果中），不进 `findings`；`owner-only-withdraw` 为 `通过` 且无 note。

### 根据成功输出读回报告

用成功输出里的 `reportId`，从同一个报告目录读取：

```bash
go run ./cmd/contractsentinel report \
  --store ./reports \
  --id a6fa091bc2bb94a56453b3d58a190ff2c17c7023b7d2fd0600ffccccb3b13b34
```

读回的是归档保存的同一份完整报告 JSON，不会被重新解释：它与**首次写入该标识归档的那次提交**的成功输出逐字段相同。这一保证的适用边界是“同一份归档内容”——如果之后只把规则或 checks 记录换个排列再次提交，新提交仍算出**同一个** `reportId`，其成功输出的排列跟随新提交的规则顺序，而读回仍保持首次归档的排列。这是正常行为，不是归档被覆盖，也不是结论改变；下一节给出可以照着运行的完整示例。其中可以直接核对每条规则的**状态、版本**以及缺陷证据，例如：

- `reentrancy-guard`：`"version": "1.4.2"`、`"status": "发现缺陷"`，note 为反例原文；
- `owner-only-withdraw`：`"version": "2.1.0"`、`"status": "通过"`；
- `solvency-symbolic`：`"version": "0.9.3"`、`"status": "工具缺失"`，note 说明引擎缺失；
- `findings` 中只有一条，归属 `reentrancy-guard` / 版本 `1.4.2` / 产物哈希 `0cdb8997…3a8ca7`，`evidence` 是上面的完整反例说明——而不是仅仅一个缺陷计数。

### 完整离线示例：仅调整排列后再次提交（报告标识不变）

同一份审计结论可能因收集渠道不同而以不同的规则排列、checks 排列反复提交。这是正常用法：**报告标识不受排列影响**，仅调整排列的各次提交都得到同一个 `reportId`；但 `audit` 成功输出里的规则与缺陷排列跟随**本次提交**的规则顺序，而 `report` 读回保持**首次归档**的排列。看到这两处排列不同，不等于归档被后来的提交覆盖，也不等于任何一条检查结论改变。下面用两份完整输入演示，全部离线运行。

两份提交审计**同一产物**（`abi`、`bytecode`、`source` 与上文相同，产物哈希仍是 `0cdb8997…3a8ca7`），使用**同样的三条带版本规则**：`reentrancy-guard` `1.4.2` 与 `owner-only-withdraw` `2.1.0` 发现缺陷，`solvency-symbolic` `0.9.3` 通过并带一条说明。两份输入除排列外内容逐字一致：

- `order-a.json`：规则顺序 reentrancy-guard、owner-only-withdraw、solvency-symbolic；checks 顺序 solvency-symbolic、owner-only-withdraw、reentrancy-guard（与规则顺序不同）。
- `order-b.json`：规则顺序 solvency-symbolic、owner-only-withdraw、reentrancy-guard；checks 顺序 reentrancy-guard、solvency-symbolic、owner-only-withdraw（同样与自己的规则顺序不同）。

`order-a.json` 的完整内容：

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
      "ruleId": "solvency-symbolic",
      "version": "0.9.3",
      "status": "通过",
      "note": "符号执行遍历了 withdraw 的全部可达状态，balances-cover-withdrawals 在每条路径上都成立。"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "owner-only-withdraw",
      "version": "2.1.0",
      "status": "发现缺陷",
      "note": "反例：withdraw 没有任何调用者校验，非 owner 地址直接调用 withdraw 即可转走自己的余额，owner-only 约束不成立。"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "status": "发现缺陷",
      "note": "反例：攻击者先存入 1 ether 后调用 withdraw；call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    }
  ]
}
```

`order-b.json` 的完整内容（与 `order-a.json` 逐字段相同，仅 `rules` 与 `checks` 的排列不同）：

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
      "id": "solvency-symbolic",
      "kind": "symbolic",
      "severity": "critical",
      "invariant": "balances-cover-withdrawals",
      "requiresABI": false,
      "version": "0.9.3"
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
      "id": "reentrancy-guard",
      "kind": "static",
      "severity": "high",
      "invariant": "no-reentrant-withdraw",
      "requiresABI": false,
      "version": "1.4.2"
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
      "ruleId": "solvency-symbolic",
      "version": "0.9.3",
      "status": "通过",
      "note": "符号执行遍历了 withdraw 的全部可达状态，balances-cover-withdrawals 在每条路径上都成立。"
    },
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "owner-only-withdraw",
      "version": "2.1.0",
      "status": "发现缺陷",
      "note": "反例：withdraw 没有任何调用者校验，非 owner 地址直接调用 withdraw 即可转走自己的余额，owner-only 约束不成立。"
    }
  ]
}
```

绑定值都是确定的、可直接使用：六条 checks 记录里的 `artifactHash` 都是
`0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7`，由上面 `abi`、`bytecode`、`source` 三个字符串内容实际算出（名称 `Vault` 不参与），不是占位符；每条记录的 `version` 与同名规则的版本一一对应。

依次提交到**同一个报告目录**：

```bash
mkdir -p reports
go run ./cmd/contractsentinel audit --input order-a.json --store ./reports
go run ./cmd/contractsentinel audit --input order-b.json --store ./reports
```

两次都以退出状态 0 成功，stdout 各输出一份完整报告 JSON。两次成功输出的**报告标识相同**：

```text
reportId: 587afafd421dcd722b4a8909546e723062c8df0768780479f9bbafa48c28eb52
```

但两份成功输出中的规则排列与缺陷排列各自跟随本次提交的规则顺序：

| 成功输出来源 | `rules` 排列 | `findings` 排列 |
| --- | --- | --- |
| 第一次（order-a.json） | reentrancy-guard → owner-only-withdraw → solvency-symbolic | reentrancy-guard → owner-only-withdraw |
| 第二次（order-b.json） | solvency-symbolic → owner-only-withdraw → reentrancy-guard | owner-only-withdraw → reentrancy-guard |

要点：

- `audit` 输出的 `rules` 按**本次提交的规则数组顺序**排列；`findings` 只包含**发现缺陷**的规则，按本次规则顺序排列，**不按 checks 记录的顺序**——两份输入的 checks 排列都与各自输出的 findings 排列不同。
- 缺陷始终归属各自的规则及版本，说明与证据一一对应：`reentrancy-guard` 的 finding 版本为 `1.4.2`、证据是重入反例原文；`owner-only-withdraw` 的 finding 版本为 `2.1.0`、证据是 owner 校验反例原文。记录在 checks 或 findings 中的位置变化不会把两条说明与证据互换。
- 第二次提交时目录中已存在 `587afafd….json`：同标识内容再次提交**不会替换首次归档**，报告目录中始终只有这一份文件，字节与首次写入相同。

用共同标识读回：

```bash
go run ./cmd/contractsentinel report \
  --store ./reports \
  --id 587afafd421dcd722b4a8909546e723062c8df0768780479f9bbafa48c28eb52
```

读回保持**首次归档**（order-a.json）的排列：`rules` 为 reentrancy-guard → owner-only-withdraw → solvency-symbolic，`findings` 为 reentrancy-guard → owner-only-withdraw。这与第二次成功输出的排列不同，但每条规则的状态、版本、说明和每条缺陷的证据逐字段一致——排列差异来自“读回保留归档顺序”，不是归档被第二次提交覆盖，也不是检查结论改变。

也可以用 `diff` 核对：把同一标识同时作为基准与新报告（等价于比较两份仅排列不同的提交）：

```bash
go run ./cmd/contractsentinel diff \
  --store ./reports \
  --before 587afafd421dcd722b4a8909546e723062c8df0768780479f9bbafa48c28eb52 \
  --after  587afafd421dcd722b4a8909546e723062c8df0768780479f9bbafa48c28eb52
```

`results` 三条全部是 `无变化`，`summary.noChange` 为 3，`beforeDefects` 与 `afterDefects` 都是 2。注意 `results` 始终**按规则标识排序**（owner-only-withdraw、reentrancy-guard、solvency-symbolic），这是比较结果自己的排列，与任一侧报告里规则或缺陷的保存顺序无关——只换排列仍显示无变化，但不能把比较结果的排序套用到完整报告上。

#### 排列变化与内容变化的界限

排列不影响报告标识，**任何文本内容变化**都会影响——哪怕只是一个尾随空格。把 `order-a.json` 中通过规则 `solvency-symbolic` 的说明末尾加一个空格（改为 `"…在每条路径上都成立。 "`），其余逐字不变，保存为 `order-c.json` 再提交：

```bash
go run ./cmd/contractsentinel audit --input order-c.json --store ./reports
# reportId: 6ec4f89789d2c16e0108c0e6a476165b6febe74337b96eb02406f65a997f1198
```

得到的是**另一个报告标识**，报告目录中新增 `6ec4f897….json`，旧归档 `587afafd….json` 原样保留。两个标识分别读回时各自保留说明原文：旧报告的说明以 `成立。` 结尾（无尾随空格），新报告的说明以 `成立。 ` 结尾（有尾随空格），互不覆盖。对这两份报告做 `diff`，`solvency-symbolic` 一条为 `检查说明变化`，其余两条为 `无变化`。

再次提醒本节的边界：`audit`、`report`、`diff` 只保存、读回和比较**已经得出的**检查结论；提交或比较本身不会启动符号执行、模糊测试或任何合约检查器。

### 读回失败条件（归档损坏，非零退出，不动归档）

`report` 读取时报告标识必须是**恰好 64 位小写十六进制字符串**，且归档字节必须完整合法。下列情况命令都以**非零状态退出**，原因写入 **stderr**，stdout 不出现任何报告片段（不会输出部分规则或部分字段），原归档保持原样（不删除、不自动修补、不留临时文件）：

- 标识格式不合法（`invalid report id …`）；
- 目录中没有该标识的归档，或报告目录本身不存在（`report … not found`）；
- 归档损坏或内容与标识不符：JSON 语法错误、任何对象重复成员名、成员名称或字符串值含非法 UTF-8 / 错误代理转义、`reportId` 与重算内容不符、规则与缺陷的一一绑定被破坏等；
- **规则的 `requiresABI` 不是布尔值。** 正式 `requiresABI` 成员（约定拼写，含 Unicode 转义写法）一旦在归档中出现，值必须是 `true` 或 `false`；写成 `null`、字符串、数字、对象或数组时**整份归档判为损坏**。`null` 在解码时会被静默当成 Go 零值 `false`：即使把归档里原本的 `false` 换成 `null` 后，报告标识、规则状态与缺陷绑定仍能全部吻合，读出的规则定义也显示 `false`，但这掩盖了归档内容不合法的事实，因此照样拒绝。这条规则适用于报告中的**每条规则**，与该规则是否已经检查、是否发现缺陷无关；一条规则不合法时不会只跳过它返回其余规则。错误会点名报告标识与出错规则：

  ```text
  report failed: report a6fa091b…3b34 archive is corrupt: rule reentrancy-guard: requiresABI must be a boolean
  ```

  省略该成员仍按 `false` 读回；合法 `true` / `false` 按原值读回，报告标识、规则状态与原始证据不变。`RequiresABI`、`" requiresABI "` 这类大小写变体或带空格的名称仍只作为扩展信息忽略，其中的 `null` 不导致本错误，也不能替代正式成员；正式成员非法时，旁边的变体即使写了合法布尔值（无论位于它之前还是之后）都不能使读取成功。

- **规则的文本成员不是字符串。** 每条规则已写出的正式 `id`、`kind`、`severity`、`invariant`、`version`、`status`、`note` 成员（约定拼写，含 Unicode 转义写法），值必须是 JSON 字符串；写成 `null`、布尔值、数字、对象或数组时**整份归档判为损坏**。`null` 在解码时会被静默当成 Go 零值 `""`：给一条没有说明的“通过”规则加入 `"note":null`，报告标识、规则状态与缺陷绑定仍能全部吻合，读出的说明也是空字符串，但归档并没有按格式保存文本，因此照样拒绝。这条规则适用于报告中的**每条规则**与所有检查状态，也适用于没有任何 finding 的报告；一条规则不合法时不会只跳过它返回其余规则。错误会点名报告标识、出错字段与规则在 `rules` 数组中的位置，规则有合法非空 `id` 时同时点名该规则：

  ```text
  report failed: report a6fa091b…3b34 archive is corrupt: rules[1] (rule owner-only-withdraw): note must be a string
  ```

  省略成员仍沿用既有默认值与必填校验，显式空字符串仍按既有业务规则判断（例如空 `version` 仍报 `has an empty version`），不会一律要求所有文本非空；通过或未检查的规则可以没有说明。`Note`、`" note "` 这类大小写变体或带空格的名称仍只作为扩展信息忽略，其中的 `null` 不导致本错误，也不能替代或挽救非法的正式成员。合法报告读回后的标识、结论、说明与缺陷证据保持原值，中文、换行和前后空格不被修剪或改写。

- **缺陷记录（findings）的文本成员不是字符串。** `findings` 中每条记录已写出的正式 `artifactHash`、`ruleId`、`version`、`severity`、`invariant`、`evidence` 成员（约定拼写，含 Unicode 转义写法），值必须是 JSON 字符串；任一成员写成 `null`、布尔值、数字、对象或数组时**整份归档判为损坏**——即使产物哈希、报告标识以及规则与缺陷的对应关系仍然全部吻合，也不会返回报告。`null` 在解码时会被静默当成 Go 零值 `""`：当一份规则与缺陷记录都把 `severity` 保存为空字符串的合法报告，只把 findings 中对应记录的 `severity` 改成 `null` 后，重算的报告标识不变、绑定也仍吻合，读出的严重级别同样是空字符串，归档没有保存合法文本却被当成合法空文本接受，之后的比较还可能显示“无变化”，因此照样拒绝；`invariant` 原本为空字符串时存在同样问题。一条记录不合法时不会只跳过它返回其余记录。错误会点名请求的报告标识、出错记录在 `findings` 数组中从零开始的位置和成员名，明确该成员必须是字符串；记录的 `ruleId` 本身是合法非空字符串时，还要指出所属规则：

  ```text
  report failed: report a6fa091b…3b34 archive is corrupt: findings[0] (rule r-empty): severity must be a string
  ```

  成员省略或显式写成空字符串时，继续按原有的必填和绑定要求判断，不新增所有文本必须非空的限制：省略的成员仍按空字符串读回，合法的空 `severity` / `invariant` 文本照常接受。`Severity`、`" invariant "` 这类大小写变体或带空格的名称仍只作为扩展信息忽略，其中的 `null` 不导致本错误，也不能替代缺失字段或挽救非法正式值。合法报告读回后的标识、缺陷归属与证据原文保持不变，中文、换行和前后空格不被修剪或改写。

- **“发现缺陷”规则的说明只有空白。** 缺陷规则的 `note` 是非空字符串、却完全由空格、制表符或换行等空白组成时（空白范围与提交侧的判断一致），**整份归档判为损坏**——即使对应 finding 的 `evidence` 保存同一段空白、产物哈希与规则版本等其余绑定全部吻合、报告标识与重算内容一致，也不会返回报告；同一份报告中的其他合法规则与缺陷也不会略过坏记录后部分返回。错误会点名请求的报告标识、所属规则，并指出缺陷说明为空白：

  ```text
  report failed: report a6fa091b…3b34 rule reentrancy-guard status 发现缺陷 has a blank note
  ```

  布尔不变式报告的证据形式不受影响：只提交不变式值 `false` 时缺陷规则没有 `note`，证据为 `invariant <不变式名> does not hold`，这种报告仍正常读回；省略 `note` 与显式空字符串继续按既有规则处理，不会一律要求缺陷规则带外部说明。含非空白内容的合法说明（中文、换行、前后空格）仍逐字保留。

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

4. **提交内容含非法字符。** 出于正确性，程序**不会**删除或替换坏字符后继续处理：

   - JSON 字符串（成员名称或任何字符串值，即使只出现在不参与报告的未知扩展成员及其嵌套内容里）含有**非法 UTF-8 字节**；
   - JSON 的 `\uXXXX` Unicode 转义里出现**未配对的高/低代理项**，或**配对顺序错误**（低代理项在前）。

   否则这两类字节都会被解码器静默改写成 U+FFFD：缺陷 `note` 的证据会变成与提交原文不符的文字，`source` 等字段被改写还会改变参与产物哈希计算的内容。命中时整份拒绝，stderr 说明是字符编码还是 Unicode 转义问题并给出字节偏移、行列与 JSON 路径，方便修正原始内容：

   ```text
   audit failed: invalid Unicode escape: unpaired high surrogate escape \uD800 in JSON string value at .checks[0].note (byte offset 535, line 24, column 19)
   audit failed: invalid character encoding: invalid UTF-8 byte 0xff in JSON string value at .artifact.source (byte offset 135, line 6, column 31)
   ```

   合法字符不受影响：中文、换行、前后空格、正确成对的代理转义（如 `😀`）与直接书写的同一字符都可使用，`note`/证据保留解码后的原文，两种写法的产物哈希与报告标识一致；原文中本就存在的 U+FFFD 只是普通字符，`"\\uD800"`（转义反斜线后跟 `uD800`）也只是普通文本，不会被误判。

5. **规则的 `requiresABI` 不是布尔值。** 正式 `requiresABI` 成员（约定拼写，含 Unicode 转义写法）一旦写出，值必须是 `true` 或 `false`；写成 `null`、字符串、数字、对象或数组时整份失败，不会被当成 `false` 继续，即使产物已有 ABI、规则没有收到任何检查结论也一样。错误会点名出错的规则：

   ```text
   audit failed: rule reentrancy-guard: requiresABI must be a boolean
   ```

   省略该成员仍按 `false` 处理；`RequiresABI`、`" requiresABI "` 这类大小写变体或带空格的名称只是扩展信息，其中的 `null` 不触发本错误，也不能替代或挽救正式成员的非法值。

6. **产物字段不是字符串。** 正式 `name`、`abi`、`bytecode`、`source` 成员（约定拼写，含 Unicode 转义写法）一旦在 `artifact` 中写出，值必须是 JSON 字符串；写成 `null`、布尔值、数字、对象或数组时**整份失败**。`null` 在解码时会被静默当成 Go 零值 `""`：产物名称合法、规则数组为空、`source` 写成 `null` 这样的提交会与用户明确提交 `"source": ""` 算出**相同的产物哈希**并照常拿到成功报告，格式错误的内容因此与合法空文本混在一起，无法区分，所以照样拒绝。这条检查只看 JSON 类型，与有没有规则、有没有 checks 记录、规则是否引用该字段无关——没有规则、没有检查记录时也一样执行；它属于**提交格式错误**，不会被记成缺陷、工具缺失或超时。错误会点名具体字段：

   ```text
   audit failed: artifact.source must be a string
   ```

   省略成员仍沿用既有默认值（按空字符串处理），显式空字符串也保留原来的业务判断：缺少或为空的名称仍不能生成报告（`artifact name is required`），`requiresABI` 为真的规则仍要求非空 `abi`，符号规则仍要求非空 `bytecode`；没有这些要求时，合法空文本可以正常使用，且省略与显式 `""` 的产物哈希、报告标识一致。`Name`、`" source "` 这类大小写变体或带空格的名称仍只作为扩展信息忽略，其中的任何值都不能补上缺失的正式字段，也不能挽救正式字段的非法值（无论位于其前还是其后）。合法字符串逐字保留中文、换行与前后空格，`source` 始终是提交的文本内容，不按文件名读取；合法提交的产物哈希、报告标识、规则结论与缺陷证据保持原有结果。

7. **规则定义的文本成员不是字符串。** `rules` 中每条规则已写出的正式 `id`、`kind`、`severity`、`invariant`、`version` 成员（约定拼写，含 Unicode 转义写法），值必须是 JSON 字符串；写成 `null`、布尔值、数字、对象或数组时**整份失败**。`null` 在解码时会被静默当成 Go 零值 `""`：一条 `id` 与 `version` 合法的规则即使把 `kind`、`severity` 或 `invariant` 写成 `null`，也可能通过全部业务检查并生成报告，空掉的定义与用户明确提交空字符串得到的规则定义、报告标识和缺陷绑定完全相同，格式错误因此被洗成了合法提交，所以照样拒绝。这条检查适用于 `rules` 中的**每条规则**，与该规则是否被检查、是否产生缺陷无关；其他规则与 checks 记录合法也不能使提交成功。它属于**规则定义的提交格式错误**，不会被记成缺陷、工具缺失或超时。错误会点名规则在 `rules` 数组中从零开始的位置与出错字段；规则有合法非空 `id` 时同时点名，`id` 自身非法时仍可凭位置定位：

   ```text
   audit failed: rules[1] (rule owner-only-withdraw): severity must be a string
   ```

   省略成员仍沿用既有默认值与必填校验（省略或为空的 `id` 仍报 `rule id is required`，空 `version` 仍报 `version is required`），显式空字符串仍按既有业务规则判断，不会一律要求五个文本非空或限制取值范围；省略与显式 `""` 的报告标识一致。`Kind`、`" invariant "` 这类大小写变体或带空格的名称及未知成员仍只作为扩展信息忽略，其中的 `null` 不触发本错误，合法字符串也不能补上缺失字段或挽救非法正式字段（无论位于其前还是其后）。合法字符串逐字保留中文、换行与前后空格；已有合法提交的产物哈希、报告标识、规则结论与缺陷证据保持原有结果。失败时尚不存在的报告目录不被创建，已有归档保持原样。

8. **checks 记录的说明 `note` 不是字符串。** `checks` 中每条记录的正式 `note` 成员（约定拼写，含 Unicode 转义写法）一旦写出，值必须是 JSON 字符串；写成 `null`、布尔值、数字、对象或数组时**整份失败**。`null` 在解码时会被静默当成 Go 零值 `""`：在产物哈希、规则与检查记录绑定都合法时，一条状态为“通过”的记录即使写了 `"note":null`，也会成功生成报告，并与**省略**说明的提交得到同一份报告（同一报告标识）——提交因此无法区分“没写说明”和“写了非文本值”，格式错误被洗成了合法提交，所以照样拒绝。这条规则对 **“通过”“发现缺陷”“工具缺失”“超时”四种状态都有效**，与该记录的其他字段是否合法无关；其他记录合法也不能使提交成功或输出、保存部分报告。它属于**提交格式错误**，不会被记成合约缺陷、工具缺失、超时或任何检查状态。错误会点名记录在 `checks` 数组中从零开始的位置与出错成员；记录带合法非空 `ruleId` 时同时点名该规则，`ruleId` 缺失或自身非法时仍可凭位置定位：

   ```text
   audit failed: checks[1] (rule owner-only-withdraw): note must be a string
   ```

   省略 `note` 仍按当前状态走既有判断：**“通过”允许没有说明**，也允许显式空字符串或只有空白的字符串；**其余三种状态仍要求非空白说明**，缺少或给出空白文字时沿用原有失败（`note is required for status …`），不是本类型错误。`Note`、`" note "` 这类大小写变体或带空格的名称及未知成员仍只作为扩展信息忽略：其中的 `null` 或其他非字符串值不触发本错误，合法字符串也不能补上缺失的正式说明、或挽救正式 `note` 的非法值（无论位于其前还是其后）。合法说明逐字保留中文、换行与前后空格；缺陷证据继续采用提交的说明原文，工具缺失与超时仍不进入 `findings`；已有合法提交的产物哈希、报告标识、规则结论与说明保持不变。失败时尚不存在的报告目录不被创建，已有归档保持原样。

此外，记录引用了 `rules` 中不存在的规则、同一规则出现多条 checks 记录、`status` 写成 `未检查` 等未知值（`unknown status …`）、或三种需要说明的状态给了空白说明（`note is required for status …`），同样整份拒绝。

## 比较两份已保存的报告（diff）

`diff` 从**同一个报告目录**中读取两份已经落盘的报告，逐规则比较并输出确定性的比较 JSON（无时间戳，重复比较同一对报告结果逐字节一致）。

```bash
go run ./cmd/contractsentinel diff \
  --store ./reports \
  --before <基准报告 reportId> \
  --after <新报告 reportId>
```

`./cs diff ...` 与上面的 `go run ./cmd/contractsentinel diff ...` 等价，全程离线。

三个参数各选什么：

- **`--store`**：两份报告共同所在的报告目录，与 `audit`、`report` 用的是同一个目录参数。
- **`--before`**：基准报告（当作对照的较早一次审计）；**`--after`**：新报告。
- **比较方向只由两个标识所在的参数位置决定**：工具不按文件时间或归档顺序猜测方向。交换两个参数，所有“新发现/已消除”的方向随之反转。
- 两个参数填的都必须是各自 **`audit` 成功输出（stdout）里的 `reportId`**（随后也可用 `report` 读回确认），**不是产物哈希**。产物哈希相同只说明两份报告审计的产物内容相同，不能拿它当报告标识。
- `diff` 只**读取已保存的结论**做比较：不会重新检查合约，不启动符号执行或模糊测试，不重新解释证据，也不写入或修改报告目录。

### 完整离线示例：缺陷总数从 1 变成 0，却没有“已消除缺陷”

下面两份提交审计**完全相同的产物内容**（同样的 `abi`、`bytecode`、`source`），使用**同一条带版本的规则** `reentrancy-guard` `1.4.2`：基准报告记录“发现缺陷”并附具体反例，新报告记录“超时”并附具体超时说明。

第一份提交保存为 `baseline.json`：

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
    }
  ],
  "invariants": {},
  "checks": [
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "status": "发现缺陷",
      "note": "反例：攻击者先存入 1 ether 后调用 withdraw；外部 call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
    }
  ]
}
```

第二份提交保存为 `rerun.json`（产物三个字符串字段与规则定义逐字相同，仅检查状态与说明不同）：

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
    }
  ],
  "invariants": {},
  "checks": [
    {
      "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
      "ruleId": "reentrancy-guard",
      "version": "1.4.2",
      "status": "超时",
      "note": "符号执行在 300s 截止时间到达时仍未遍历完 withdraw 的重入状态空间，作业被调度器中止，本次未得出通过或缺陷结论。"
    }
  ]
}
```

绑定值都是确定的、无需读者补齐：两份提交 checks 里的 `artifactHash` 都是
`0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7`
（由相同的 `abi`、`bytecode`、`source` 内容算出，名称 `Vault` 不参与），`version` 都与规则的 `1.4.2` 相符。

依次提交，从成功输出中取用两个 `reportId`：

```bash
mkdir -p reports
go run ./cmd/contractsentinel audit --input baseline.json --store ./reports
# reportId: fd2b18fc0819786bc466a3bc8f5a60ffbf24d44e86d0b9b2bd09495bb80383dc
go run ./cmd/contractsentinel audit --input rerun.json    --store ./reports
# reportId: 738004a606559b08a2beb04382ea1ef2c9ec81869081c27e7dd153e840d0e4e0
```

把基准标识放在 `--before`、新标识放在 `--after`：

```bash
go run ./cmd/contractsentinel diff \
  --store ./reports \
  --before fd2b18fc0819786bc466a3bc8f5a60ffbf24d44e86d0b9b2bd09495bb80383dc \
  --after  738004a606559b08a2beb04382ea1ef2c9ec81869081c27e7dd153e840d0e4e0
```

本机离线输出（与仓库中 `contractsentinel` 的比较分类和报告格式一致）：

```json
{
  "before": {
    "reportId": "fd2b18fc0819786bc466a3bc8f5a60ffbf24d44e86d0b9b2bd09495bb80383dc",
    "artifact": {
      "name": "Vault",
      "hash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7"
    }
  },
  "after": {
    "reportId": "738004a606559b08a2beb04382ea1ef2c9ec81869081c27e7dd153e840d0e4e0",
    "artifact": {
      "name": "Vault",
      "hash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7"
    }
  },
  "artifactNameChanged": false,
  "artifactHashChanged": false,
  "results": [
    {
      "ruleId": "reentrancy-guard",
      "change": "检查状态变化",
      "before": {
        "rule": {
          "id": "reentrancy-guard",
          "kind": "static",
          "severity": "high",
          "invariant": "no-reentrant-withdraw",
          "requiresABI": false,
          "version": "1.4.2",
          "status": "发现缺陷",
          "note": "反例：攻击者先存入 1 ether 后调用 withdraw；外部 call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
        },
        "finding": {
          "artifactHash": "0cdb899734304f7aac91e746f5332c248c94bf0877ae37d0848409bd0b3a8ca7",
          "ruleId": "reentrancy-guard",
          "version": "1.4.2",
          "severity": "high",
          "invariant": "no-reentrant-withdraw",
          "evidence": "反例：攻击者先存入 1 ether 后调用 withdraw；外部 call 在 balances 扣减前把控制权交给攻击合约的 receive，receive 重入 withdraw，此时 balances[msg.sender] 仍是旧值，同一笔余额被第二次转出。"
        }
      },
      "after": {
        "rule": {
          "id": "reentrancy-guard",
          "kind": "static",
          "severity": "high",
          "invariant": "no-reentrant-withdraw",
          "requiresABI": false,
          "version": "1.4.2",
          "status": "超时",
          "note": "符号执行在 300s 截止时间到达时仍未遍历完 withdraw 的重入状态空间，作业被调度器中止，本次未得出通过或缺陷结论。"
        },
        "finding": null
      }
    }
  ],
  "summary": {
    "newDefects": 0,
    "resolvedDefects": 0,
    "statusChanges": 1,
    "noteChanges": 0,
    "noChange": 0,
    "addedRules": 0,
    "removedRules": 0,
    "changedRules": 0,
    "beforeDefects": 1,
    "afterDefects": 0
  }
}
```

如何读这份结果：

- 这条规则的 `change` 是 **“检查状态变化”**，**不是“已消除缺陷”**。基准侧（`before`）原样保留 `发现缺陷` 状态和 finding，finding 的 `evidence` 就是提交时的反例原文；新侧（`after`）只有 `超时` 状态和超时说明，`finding` 为 `null`。两侧结论与原始证据都能在这一个结果条目里直接找到，需要完整报告时再用 `report --id <reportId>` 读回。
- **缺陷总数与变化分类是两类不同字段。** `summary.beforeDefects = 1`、`afterDefects = 0` 只数两侧各自归档的真实 finding 条数（超时、工具缺失不产生 finding）；`newDefects` / `resolvedDefects` 则是对“发生了什么变化”的归类。本例两者都是 0：新报告缺陷数变少，仅仅是因为这次检查**超时、没有得出结论**，并没有一条 `发现缺陷 → 通过` 的迁移。
- **超时不代表检查通过，也不能据此推断缺陷已修复或已消除。** 手头唯一的具体证据仍是基准侧那条重入反例；新侧说明只证明“这次没查完”。`工具缺失`、`未检查` 同理：凡是涉及这几种非正常结论的状态迁移，一律归为“检查状态变化”。
- **只有规则定义完全一致时才比较检查状态**：同一 `ruleId` 的 `version`、`kind`、`severity`、`invariant`、`requiresABI` 全部相同，才可能出现 **`通过 → 发现缺陷` 计为“新发现缺陷”（`newDefects`）**、反向 **`发现缺陷 → 通过` 计为“已消除缺陷”（`resolvedDefects`）**。
- **规则版本或其他定义不同则归为“规则变化”（`changedRules`）**，两侧仍各自保留状态与证据，但不能据此推断修复或新增缺陷。例如把新提交的规则版本改成 `1.4.3`（checks 中的版本同步改为 `1.4.3`），输出就是 `"change": "规则变化"`、`"changedRules": 1`，而 `newDefects` 与 `resolvedDefects` 仍为 0——即使 `beforeDefects` 为 1、`afterDefects` 为 0。

### 比较结果的分类与字段

每个在任一侧出现过的规则标识恰好产生一个 `results` 条目，按 `ruleId` 排序；该侧没有这条规则时对应一侧为 `null`。`change` 沿用既有八类：

| change | 含义 |
| --- | --- |
| `新发现缺陷` | 定义完全一致，且状态 `通过 → 发现缺陷` |
| `已消除缺陷` | 定义完全一致，且状态 `发现缺陷 → 通过` |
| `检查状态变化` | 定义一致，但状态迁移不属于上面两种（涉及 `超时`、`工具缺失`、`未检查` 等） |
| `检查说明变化` | 状态相同，仅 note 不同 |
| `无变化` | 状态与说明都相同 |
| `新增规则` / `移除规则` | 规则标识只在新侧 / 基准侧出现 |
| `规则变化` | 同名规则的版本或其他定义字段不同，不比较检查状态 |

`before` / `after` 两侧的 `rule` 是该侧完整规则（含 `version`、`status`、`note`）；`finding` 仅在该侧该规则为 `发现缺陷` 时出现，携带当侧归档的 `artifactHash`、`version` 与逐字证据。顶层 `artifactNameChanged` / `artifactHashChanged` 标明两侧产物是否同名同内容。`summary` 中八类计数与逐条 `change` 一一对应且零值也总是出现，`beforeDefects` / `afterDefects` 是两侧缺陷总数。

### diff 失败条件（非零退出，无部分结果，不动归档）

报告标识必须是**恰好 64 位小写十六进制字符串**。下列情况命令都以**非零状态退出**，原因写入 **stderr**，stdout 没有任何比较片段（即使第一份报告已成功读取也不会输出部分结果），报告目录与已有归档保持原样（不创建目录、不修复或改写损坏文件、不留临时文件）：

- 标识格式不合法：

  ```text
  diff failed: invalid report id xyz: want 64 lowercase hex characters
  ```

- 任一报告在目录中不存在（含报告目录本身不存在）：

  ```text
  diff failed: report 0000…0000 not found
  ```

- 任一归档损坏或内容与标识不符：

  ```text
  diff failed: invalid JSON in report 738004a6…0e4e0: invalid character 'b' looking for beginning of object key string
  ```

- 任一归档的规则定义里，正式 `requiresABI` 成员写成了 `null`、字符串、数字、对象或数组等非布尔值：

  ```text
  diff failed: report a6fa091b…3b34 archive is corrupt: rule reentrancy-guard: requiresABI must be a boolean
  ```

  `null` 会被解码静默当成 `false`，损坏归档因此可能与合法归档同标识，甚至被误判为“无变化”；比较前的类型校验会先拒绝整份归档，**任一侧**命中都直接失败，不输出任何比较结果，也不会把被默认成 `false` 的规则拿去判断“规则变化”或“无变化”。省略 `requiresABI` 仍按 `false`，合法 `true` / `false` 的既有比较行为不变。

- 任一归档的规则文本成员（正式的 `id`、`kind`、`severity`、`invariant`、`version`、`status`、`note`）写成了 `null`、布尔值、数字、对象或数组等非字符串值：

  ```text
  diff failed: report a6fa091b…3b34 archive is corrupt: rules[0] (rule owner-only-withdraw): note must be a string
  ```

  `null` 会被解码静默当成空字符串，损坏归档因此可能与合法归档同标识，甚至被误判为“无变化”；比较前的类型校验会先拒绝整份归档，**任一侧**命中都直接失败，不输出任何比较结果，也不会把被默认成空字符串的内容拿去判断“无变化”。省略成员仍按既有默认值处理，已有合法报告的比较分类与统计保持不变。

- 任一归档 `findings` 中某条缺陷记录的文本成员（正式的 `artifactHash`、`ruleId`、`version`、`severity`、`invariant`、`evidence`）写成了 `null`、布尔值、数字、对象或数组等非字符串值：

  ```text
  diff failed: report a6fa091b…3b34 archive is corrupt: findings[0] (rule r-empty): severity must be a string
  ```

  `null` 会被解码静默当成空字符串：规则与缺陷记录都保存空文本的合法报告，把记录里的 `severity` 或 `invariant` 改成 `null` 后标识不变、绑定仍吻合，甚至会被误判为“无变化”。比较前的类型校验会先拒绝整份归档，**任一侧**命中都直接失败，不输出任何比较结果，也不会依据被当成空字符串的错误值计算分类或统计。成员省略或显式写成空字符串仍按既有必填与绑定要求处理，已有合法报告的比较分类与统计保持不变。

- 任一归档中某条“发现缺陷”规则的 `note` 是非空字符串却完全由空白组成（对应 finding 的 `evidence` 保存同一段空白、报告标识与内容一致也不例外）：

  ```text
  diff failed: report a6fa091b…3b34 rule reentrancy-guard status 发现缺陷 has a blank note
  ```

  比较前的校验会先拒绝整份归档，**任一侧**命中都直接失败，不输出任何比较分类或统计。只提交不变式布尔值生成的无说明缺陷报告（证据为 `invariant <不变式名> does not hold`）不受影响，已有合法报告的比较结果保持不变。

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
