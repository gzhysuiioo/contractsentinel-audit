# 智能合约审计与形式化验证流水线

## 用途

合约产物与 ABI 管理、静态规则与模式库、符号执行与模糊测试编排、不变式检查、缺陷归因与报告版本化。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `contractsentinel/`，命令入口位于 `cmd/contractsentinel/`。

```bash
go run ./cmd/contractsentinel demo
go run ./cmd/contractsentinel version
go run ./cmd/contractsentinel resolve <config-file> < request.json
go test ./...
```

## 离线路由解析（resolve）

`resolve` 从配置文件读取路由，从标准输入读取一个 JSON 请求，在本机离线
完成匹配并输出命中的路由与上游地址，全程不建立网络连接。

配置文件：

```json
{
  "routes": [
    {"id": "api",  "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1"},
    {"id": "root", "methods": ["*"],  "pathPrefix": "/",    "upstream": "https://fallback.internal/base/"}
  ]
}
```

请求（`target` 为带可选查询串的路径）：

```json
{"method": "GET", "target": "/api/orders/7?a=1&a="}
```

成功时标准输出：

```json
{"routeId":"api","upstreamURL":"http://api.internal/v1/orders/7?a=1&a="}
```

带查询串改写的配置（命中后 `set` 名称 `a` 值空字符串、`remove` 名称 `flag`）：

```json
{
  "routes": [
    {"id": "api", "methods": ["GET"], "pathPrefix": "/api", "upstream": "http://api.internal/v1",
     "queryTransforms": [
       {"op": "set",    "name": "a",    "value": ""},
       {"op": "remove", "name": "flag"}
     ]}
  ]
}
```

请求 `/api/orders?x=%2f&a=1&%61=2&flag` 的输出为：

```json
{"routeId":"api","upstreamURL":"http://api.internal/v1/orders?x=%2f&a="}
```

匹配规则：

- `methods` 为非空数组，元素是区分大小写的具体 HTTP 方法名或 `*`（匹配任意合法方法）。
- `pathPrefix` 以 `/` 开头，除根前缀 `/` 外不能以 `/` 结尾，不含查询串或片段。
- 前缀按原始编码与请求路径匹配，并必须落在路径段边界上：`/api` 匹配
  `/api` 与 `/api/orders`，不匹配 `/apiv2`；`%2F` 不视为分隔符。
- 查询串不参与匹配。多条命中时最长前缀优先；前缀相同则具体方法优先于 `*`；
  仍有多条候选时返回 `route_conflict`，候选 `id` 按字典序排列；无候选返回
  `route_not_found`。
- 命中后去掉请求路径前缀，剩余路径接到 upstream 基础路径之后，连接处恰好
  保留一个 `/`（剩余路径为空也保留）；根前缀 `/` 保留其后全部路径。连接处
  以外的路径、百分号编码与原始查询串（含重复参数、空值与顺序）逐字节保留。

查询串改写（`queryTransforms`）：

- 每条路由可新增 `queryTransforms` 数组，规则按数组顺序执行，作用于路由
  选定后的查询串，不改变匹配、冲突判定与路径拼接。
- 每条规则含 `op`（仅支持 `set`、`remove`）与 `name`（非空字符串，按字面
  值使用）；`set` 必须提供字符串 `value`（允许空字符串），`remove` 不接受
  `value`。
- 省略或为空数组时逐字节保留原查询串；`null`、规则为 `null`、字段类型错误、
  未知操作、空名称、缺少必要字段或 `remove` 带 `value` 均使整个配置返回
  `invalid_config`（即使出错路由未被命中），reason 定位到路由，规则错误给出
  从 1 开始的序号。
- 查询串只以 `&` 分隔参数，第一个 `=` 分开名称与值，没有 `=` 的参数也可按
  名称命中；空查询串视为没有片段，其余空片段保留且不作为参数。比较参数名
  称时解码百分号转义、把 `+` 视为空格、区分大小写，不做其他归一化。
- `remove` 删除该名称的全部参数；`set` 将该名称的全部参数合并成一个，放在
  首次命中的位置，原来没有时追加到末尾。新增或替换的参数写成编码后的
  `name=value`：仅 ASCII 字母、数字及 `-._~` 原样出现，其他 UTF-8 字节使用
  大写百分号转义，空格写为 `%20`。未被修改的参数与空片段保持原始内容及相对
  顺序，后续规则基于前一步结果执行。
- 没有查询串时 `remove` 不产生问号、`set` 创建查询串；原先空查询串的问号在
  没有实际修改时保留；删除命中参数后若参数与空片段均已清空则去掉问号。
  非法百分号转义返回 `invalid_request`。

示例：查询串 `x=%2f&a=1&%61=2&flag`，依次 `set` 名称 `a` 值空字符串、
`remove` 名称 `flag`，结果为 `x=%2f&a=`。

失败时标准错误输出含 `code`、`reason` 的 JSON（`route_conflict` 另含
`candidates`），退出状态非零，标准输出不留下结果：

- `invalid_config`：配置不可读、JSON 无效或任一路由不合法（能定位时指出第几条路由及 id）。
- `invalid_request`：请求 JSON 无效、方法缺失或不合法、`target` 不以 `/` 开头、含片段或非法百分号转义。
- `route_conflict` / `route_not_found`：见上。


## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
