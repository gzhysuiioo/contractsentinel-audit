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

### queryTransforms 查询串改写

每条路由可新增 `queryTransforms` 数组，在路由选定之后、路径拼接完成后按
数组顺序改写查询串；匹配、冲突判定与路径拼接均不受其影响。省略该字段或给
空数组时，原始查询串逐字节保留。规则形如：

```json
"queryTransforms": [
  {"op": "set",    "name": "a",    "value": ""},
  {"op": "remove", "name": "flag"},
  {"op": "rename", "name": "old",  "to": "new"}
]
```

- `op` 仅支持 `set`、`remove`、`rename`；`name` 为非空字符串，按字面值使用。
- `set` 必须提供字符串 `value`（允许空字符串）；`remove` 不接受 `value`。
- `rename` 必须提供非空字符串 `to`，不接受 `value`；`name` 与 `to` 按
  字面值使用。命中的参数在原位置改名，各自的值、数量与相对顺序保留；
  已经叫目标名的参数继续保留，不合并也不覆盖。无等号的参数改名后仍无
  等号，空值保留等号；只重新编码被改动参数的名称（编码方式与 `set`
  相同），等号及其后的内容逐字节保留，值中的 `+`、百分号转义、额外等号
  与大小写都不改写。例如 `old=1&new=9&%6Fld=%2f+&old&x=` 把 `old`
  改名为 `new` 后得到 `new=1&new=9&new=%2f+&new&x=`。没有来源参数时
  查询串完全不变；`name` 与 `to` 相同时也不改写已有的名称编码。
- 查询串只以 `&` 分隔，第一个 `=` 分开名称和值；没有 `=` 的片段也能按名称
  命中。空查询串（`?` 后为空）视为没有片段，其余空片段（如 `?a=1&` 末尾）
  保留且不作为参数。
- 比较参数名称时解码百分号转义、把 `+` 视为空格、区分大小写，不做其他
  归一化；未命中名称的参数与其原始内容、顺序保持不变。
- `remove` 删除该名称的全部参数。`set` 把该名称的全部参数合并为一个，
  放在首次命中的位置；原查询中不存在时追加到末尾。没有查询串时 `remove`
  不产生问号，`set` 会创建查询串；原先的空问号在没有实际修改时保留，
  删除命中参数后若参数与空片段均已清空则去掉问号。
- 新增或替换的参数写成编码后的 `name=value`：仅 ASCII 字母、数字及
  `-._~` 原样出现，其他 UTF-8 字节使用大写百分号转义，空格写为 `%20`。
- 后一条规则基于前一条规则的结果执行。例如查询串
  `x=%2f&a=1&%61=2&flag` 先 `set a=""` 再 `remove flag`，结果为
  `x=%2f&a=`。`rename` 同样按数组次序串接：后续对目标名的 `set`
  仍合并所有同名参数，`remove` 仍删除全部同名参数。

数组或规则为 `null`、字段类型错误、未知操作、空名称、缺少必要字段、
`remove` 带 `value` 或 `rename` 缺少/带非法 `to` 或带 `value`，都使
整个配置返回 `invalid_config`（即使出错路由不会被命中）；reason 定位到
路由，规则错误另给出从 1 开始的规则序号。

失败时标准错误输出含 `code`、`reason` 的 JSON（`route_conflict` 另含
`candidates`），退出状态非零，标准输出不留下结果：

- `invalid_config`：配置不可读、JSON 无效或任一路由不合法（含非法
  queryTransforms；能定位时指出第几条路由及 id，规则错误指出规则序号）。
  合法 JSON 但结构不符与语法损坏严格区分：最外层必须是 JSON 对象，
  数组、字符串、数字、布尔值和 null 都被拒绝，reason 说明配置必须是
  对象并指出实际收到的类型，不猜测路由序号；对象中只要提供 `routes`
  就必须是数组，其他类型（含 null）报 `routes` 类型错误，不能当成没有
  路由；没有 `routes` 键的对象与 `"routes": []` 仍是合法空路由配置，
  合法请求对其解析得到 `route_not_found`。`routes` 数组的每个元素必须
  是对象，null 也按元素类型错误处理（不报缺少 id），reason 指出从 1
  开始的路由序号、要求的对象类型和实际收到的类型，且即使请求只会命中
  较早的合法路由，后面的非对象元素也会使整份配置被拒绝。
  合法 JSON 中某条路由的 `id`、`methods`、`pathPrefix`、`upstream`
  字段类型本身不符（如 `methods` 写成字符串、数组元素不是字符串）时，
  reason 直接指出从 1 开始的路由序号与字段，而非把整份配置说成无效
  JSON；该路由同时提供了合法非空字符串 `id` 时附带该 id（即使它写在
  出错字段之后），但 `id` 自身类型错误时只报位置与字段。只有 JSON
  语法损坏才报解析失败（即使开头包含 `routes` 或完整的第一条路由），
  且不猜测出错字段或路由位置；配置结构错误与请求错误同时存在时先报告
  `invalid_config`。
- `invalid_request`：方法缺失或不合法、`target` 不以 `/` 开头、含片段或非法百分号转义。
  只有 JSON 语法损坏才报解析失败，且不猜测哪个字段出错；合法 JSON 但最外层是
  数组、数字、字符串、布尔值或 null 时，reason 说明请求必须是 JSON 对象；合法
  对象中 `method` 或 `target` 写成数字、布尔值、对象、数组或 null 时，reason
  指出该字段必须是字符串并说明收到的类型（null 算类型错误，不是字段未填写），
  两个字段都出错时先报告 `method`，与字段书写顺序无关；空字符串仍是内容问题
  （方法必填、目标路径必须以 `/` 开头），不归为类型错误。
- `route_conflict` / `route_not_found`：见上。


## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
