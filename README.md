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

4. **提交内容含非法字符。** 出于正确性，程序**不会**删除或替换坏字符后继续处理：

   - JSON 字符串（成员名称或任何字符串值，即使只出现在不参与报告的未知扩展成员及其嵌套内容里）含有**非法 UTF-8 字节**；
   - JSON 的 `\uXXXX` Unicode 转义里出现**未配对的高/低代理项**，或**配对顺序错误**（低代理项在前）。

   否则这两类字节都会被解码器静默改写成 U+FFFD：缺陷 `note` 的证据会变成与提交原文不符的文字，`source` 等字段被改写还会改变参与产物哈希计算的内容。命中时整份拒绝，stderr 说明是字符编码还是 Unicode 转义问题并给出字节偏移、行列与 JSON 路径，方便修正原始内容：

   ```text
   audit failed: invalid Unicode escape: unpaired high surrogate escape \uD800 in JSON string value at .checks[0].note (byte offset 535, line 24, column 19)
   audit failed: invalid character encoding: invalid UTF-8 byte 0xff in JSON string value at .artifact.source (byte offset 135, line 6, column 31)
   ```

   合法字符不受影响：中文、换行、前后空格、正确成对的代理转义（如 `😀`）与直接书写的同一字符都可使用，`note`/证据保留解码后的原文，两种写法的产物哈希与报告标识一致；原文中本就存在的 U+FFFD 只是普通字符，`"\\uD800"`（转义反斜线后跟 `uD800`）也只是普通文本，不会被误判。

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
