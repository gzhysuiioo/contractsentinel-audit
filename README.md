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
- 除百分号编码外，前缀中不得直接出现 ASCII 空格（U+0020）、U+0000 至
  U+001F 控制字符或 U+007F：请求 target 本身也禁止直接携带这些字符，
  因此含这种字符的前缀不可能被任何合法请求命中，配置在读取时即返回
  `invalid_config`。判定基于 JSON 解码后的字符串，直接写空格与写
  反斜杠 `u0020` 转义失败方式相同，`\n`、`\t` 等转义也不能绕过；reason 指出
  pathPrefix、从 1 开始的路由位置、该路由合法的非空 id 与前缀中最先
  出现的违规字符（U+XXXX）。不删除字符、不修剪前缀、也不替用户补上
  百分号编码。`%20`、`%09`、`%00` 等合法百分号编码不是直接出现的字符，
  继续按原始文本处理，不先解码再检查或匹配：以 `/a%20b` 为前缀的路由
  仍能匹配 `/a%20b/items`。
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
  {"op": "rename", "name": "old",  "to": "new"},
  {"op": "copy",   "name": "old",  "to": "backup"}
]
```

- `op` 仅支持 `set`、`remove`、`rename`、`copy`；`name` 为非空字符串，按字面值使用。
- `set` 必须提供字符串 `value`（允许空字符串）；`remove` 不接受 `value`。
- `rename` 必须提供非空字符串 `to`，不接受 `value`；`name` 与 `to` 按
  字面值使用。命中的参数在原位置改名，各自的值、数量与相对顺序保留；
  已经叫目标名的参数继续保留，不合并也不覆盖。无等号的参数改名后仍无
  等号，空值保留等号；只重新编码被改动参数的名称（编码方式与 `set`
  相同），等号及其后的内容逐字节保留，值中的 `+`、百分号转义、额外等号
  与大小写都不改写。例如 `old=1&new=9&%6Fld=%2f+&old&x=` 把 `old`
  改名为 `new` 后得到 `new=1&new=9&new=%2f+&new&x=`。没有来源参数时
  查询串完全不变；`name` 与 `to` 相同时也不改写已有的名称编码。
- `copy` 必须提供非空字符串 `to`，不接受 `value`；`name` 与 `to` 按
  字面值使用。`copy` 复制所有名称匹配的参数：原参数留在原位置，每个
  副本紧跟其原参数；已经叫目标名的参数继续保留，不合并也不覆盖。无
  等号的参数产生无等号的副本，空值保留等号；副本只按 `set` 的方式编码
  新名称，第一个等号及其后的内容（值中的 `+`、百分号转义、额外等号与
  大小写）逐字节复制。例如 `old=%2f+&new=9&old` 把 `old` 复制为 `new`
  后得到 `old=%2f+&new=%2f+&new=9&old&new`。没有来源参数时查询串完全
  不变；`name` 与 `to` 相同时不生成副本，也不重新编码已有的名称。
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
  仍合并所有同名参数，`remove` 仍删除全部同名参数。`copy` 产生的副本
  也能被后续规则处理：例如先 `copy` 再 `remove` 来源名称，副本保留。

数组或规则为 `null`、字段类型错误、未知操作、空名称、缺少必要字段、
`remove` 带 `value`、`rename` 或 `copy` 缺少/带非法 `to` 或带 `value`，都使
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
  `invalid_config`。此外，`upstream` 用方括号包围主机时，括号内必须是合法
  IPv6 地址（完整写法、压缩写法、含 IPv4 尾段均可），允许带端口、用户信息
  与区域标识（`%25eth0`）；空括号、括号内为普通名称或 IPv4 地址（如
  `[not-an-ip]`、`[127.0.0.1]`）及格式错误的 IPv6 地址都使整份配置返回
  `invalid_config`，reason 指出从 1 开始的路由序号、id 与 `upstream` 字段，
  说明括号中的主机不是合法 IPv6 地址，而不是把配置 JSON 说成语法损坏；普通
  域名与不带方括号的 IPv4 主机不受影响。反过来，IPv6 字面量主机必须完整放
  在一对方括号内，端口写在括号之外（如 `http://[2001:db8::1]:8080/base`）：
  完整写法、压缩写法、含 IPv4 尾段及带 `%25eth0` 区域标识的地址，不加括号都
  被拒绝，`http://2001:db8::1/base`、`http://::1:8080/base` 与
  `http://::ffff:192.0.2.1/base` 均属此类，末尾是数字也不能使其成为合法配置
  （主机与端口边界有歧义时不猜测端口，也不自动补括号），带端口或用户信息的
  写法同样拒绝；reason 指出从 1 开始的路由序号、该路由 id 与 `upstream` 字段，
  说明 IPv6 主机缺少方括号，这是地址内容错误而非配置 JSON 语法损坏，且只检查
  主机段——用户信息或基础路径中出现冒号不影响判定。此外，每个上游都必须真正
  填写非空主机：`http://:8080/base`、`https://:8443`、`http://:/base` 都使
  整份配置返回 `invalid_config`，即使主机位置前带有用户名或密码（如
  `https://user:p%40ss@:8443/v1`）也相同——用户信息、端口和基础路径都不能
  补足缺失的主机，也不会补上任何默认地址；判断的是主机有没有填写，端口格式
  仍沿用现有规则，所以有主机的 `http://api.internal:/base`（空端口）继续按
  现有行为接受。reason 指出从 1 开始的路由序号、该路由 id 与 `upstream`
  字段，并说明上游缺少主机，既不能说成配置 JSON 解析失败，也不能说成 IPv6
  缺少方括号；配置中只要有一条路由存在此问题，即使当前请求只会命中较早的
  合法路由，整份配置也在读取时被拒绝。
  同样在读取时被拒绝的还有 pathPrefix 中直接出现的空格或控制字符：只要
  原本满足前缀格式要求的 pathPrefix 在 JSON 解码后的字符串里直接含有
  U+0020、U+0000 至 U+001F 中任意字符或 U+007F，整份配置就返回
  `invalid_config`，不返回可供继续解析的配置（直接写入空格与用反斜杠
  `u0020` 表示空格失败方式相同，`\n`、`\t` 等转义也不能绕过检查）；
  reason 指出 pathPrefix、从 1 开始的路由位置、该路由合法的非空 id 以及
  前缀中最先出现的违规字符（U+XXXX），且不删除字符、不修剪前缀、不替
  用户补上百分号编码。该检查与查询串改写规则同属内容层面，沿用现有的
  错误选择顺序：JSON 语法、结构及基础字段类型、查询串改写规则中的错误
  仍优先报告；同属路由内容错误时按路由数组位置决定先报告哪条，即使
  违规路由排在可正常命中的路由之后或与当前请求无关也拒绝整份配置。
  百分号编码的字符不属于直接出现的违规字符：`/a%20b` 前缀仍能匹配
  `/a%20b/items`，`%09`、`%00` 等合法编码继续按原始文本处理，不先
  解码再检查或匹配，编码大小写、路径段边界与上游拼接方式保持不变，
  中文等未被本规则禁止的字符不扩大拒绝范围。
- `invalid_request`：方法缺失或不合法、`target` 不以 `/` 开头、含片段、非法百分号转义，
  或直接出现不允许的字符（ASCII 空格、U+0000 至 U+001F 控制字符、U+007F，无论位于路径、
  参数名称还是参数值）。该字符检查在路由选择与查询串改写之前进行：没有路由命中、路由冲突，
  或 `remove`、`set` 会删除/覆盖携带该字符的参数时，仍返回 `invalid_request`；reason 指出
  target 含有不允许直接出现的字符，并以 U+XXXX 形式说明最先出现的那个字符（JSON 中的
  `\n`、`\t`、`\u0000` 等转义解码后按此规则处理）。百分号编码与直接字符严格区分：
  `/api/orders%20next` 与 `/api/orders?note=%0A%09` 继续按现有规则解析，路径中的编码不先
  解码再匹配，未改写的编码、参数顺序与空格写法保持原样，不删除控制字符后继续解析；中文等
  未涉及该规则的内容保持现有行为。
  只有 JSON 语法损坏才报解析失败，且不猜测哪个字段出错；合法 JSON 但最外层是
  数组、数字、字符串、布尔值或 null 时，reason 说明请求必须是 JSON 对象；合法
  对象中 `method` 或 `target` 写成数字、布尔值、对象、数组或 null 时，reason
  指出该字段必须是字符串并说明收到的类型（null 算类型错误，不是字段未填写），
  两个字段都出错时先报告 `method`，与字段书写顺序无关；空字符串仍是内容问题
  （方法必填、目标路径必须以 `/` 开头），不归为类型错误。
- `route_conflict` / `route_not_found`：见上。

### 上游地址带用户名或密码：失败诊断如何隐藏凭据

`upstream` 可以携带用户信息，形如 `scheme://用户名:密码@主机/基础路径`
（密码可省略；`resolve` 全程离线，主机不需要真实存在，也不会发起连接）。
当某条路由的 upstream 不合法、整份配置返回 `invalid_config` 时，标准错误
JSON 的 `reason` 会引用这个地址，引用时遵守一条固定的隐藏规则：

- authority 中 `@` 之前的整段用户信息——用户名和可选密码，连同其中的
  冒号、百分号编码——**整体替换为 `***`**，既不解码也不部分保留；
- 分隔用的 `@` 以及后面的主机、端口、基础路径原样保留；
- reason 的其他文字也不会再次引用用户名、密码或其中的出错片段。

因此诊断可以安全保存或转交。区分“凭据本身错误”与“地址其他部分错误”，
看 reason 给出的实际原因，而不是地址中有没有 `%`：

- **凭据里的非法百分号转义**使用专用原因（“invalid percent escape in
  its userinfo”），只说明 `@` 之前的用户名或密码存在没有跟上两位十六
  进制数字的 `%`，绝不会把出错片段再写一遍；
- **主机或基础路径的错误**保留各自原有的具体原因：主机错误说主机
  （缺少主机、IPv6 括号问题等），路径中的非法转义以通用 URL 解析错误
  报告并保留 `invalid URL escape "%zz"` 这样的片段——这个 `%zz` 位于
  主机或路径中，不是密码的一部分，不能据此判断为凭据错误；
- 用户信息的边界是 authority（`://` 之后到第一个路径 `/` 之间）中
  **最后一个 `@`**：基础路径里单独出现的 `@` 属于路径内容，不作为
  用户名或密码的分隔位置。

#### 情况一：密码中的百分号转义不完整

以下配置共两条路由；请求只会命中第一条合法路由，第二条路由的 upstream
为 `https://reader:pw%4@api.internal/v1`，密码片段 `pw%4` 中的 `%4`
不是完整的百分号转义（`%` 后必须紧跟两位十六进制数字）。

配置文件：

```json
{
  "routes": [
    {"id": "api",    "methods": ["GET"], "pathPrefix": "/api",    "upstream": "http://api.internal/v1"},
    {"id": "reader", "methods": ["GET"], "pathPrefix": "/reader", "upstream": "https://reader:pw%4@api.internal/v1"}
  ]
}
```

请求：

```json
{"method":"GET","target":"/api/items/9?a=1&a="}
```

运行结果（退出状态为 1，标准输出为空，标准错误为一行 JSON）：

```json
{"code":"invalid_config","reason":"route 2 (id \"reader\"): upstream \"https://***@api.internal/v1\" contains an invalid percent escape in its userinfo: the username or password before the '@' carries a '%' that is not followed by two hexadecimal digits, so the address cannot be parsed; write a literal percent as %25 and percent-encode every other byte as two hex digits. The configured username and password are not repeated — shown together as \"***\" — while the '@', host, port and base path stay unchanged"}
```

要点：

- reason 定位到从 1 开始的路由位置（`route 2`）、路由 id（`"reader"`）
  与 `upstream` 字段，并说明问题是凭据中存在非法百分号转义；
- 地址展示为 `https://***@api.internal/v1`：用户名 `reader` 与密码
  整体被 `***` 替换，`@`、主机与基础路径 `/v1` 保留；整段 reason 中
  不会再次出现 `pw%4`、`%4` 或用户名的任何字节；
- 即使出错路由不会被当前请求选中，只要配置中存在一条这样的路由，
  `ParseConfig` 就在读取时拒绝**整份配置**、不返回可用对象——配置
  在读取 stdin 之前即校验完毕，与请求命中哪条路由无关。

修正方法是把字面百分号写成 `%25`（密码 `pw%4` 按字面写应作
`pw%254`），或补全/更正转义。

#### 情况二：凭据合法，基础路径含非法转义

把密码换成合法的百分号编码（`p%40ss` 解码后是 `p@ss`），非法转义
改放到基础路径中：upstream 为
`https://reader:p%40ss@api.internal/%zz`。

配置文件：

```json
{
  "routes": [
    {"id": "reader", "methods": ["GET"], "pathPrefix": "/reader", "upstream": "https://reader:p%40ss@api.internal/%zz"}
  ]
}
```

请求：

```json
{"method":"GET","target":"/reader/books/7?a=1&a="}
```

运行结果（退出状态为 1，标准输出为空）：

```json
{"code":"invalid_config","reason":"route 1 (id \"reader\"): upstream is not a valid URL: parse \"https://***@api.internal/%zz\": invalid URL escape \"%zz\""}
```

这里仍然隐藏凭据（reason 中找不到 `reader` 或 `p%40ss`），但保留了
路径转义错误的真实原因：`%zz` 位于基础路径，诊断中的
`invalid URL escape "%zz"` 指向的是路径，**不能把它解释为密码错误**。
主机部分的错误同理，按主机自身的原因报告，例如把非法转义放到主机中
（upstream `https://reader:p%40ss@ho%zzst.internal/`）时，reason 为
`route 1 (id "reader"): upstream is not a valid URL: parse "https://***@ho%zzst.internal/": invalid URL escape "%zz"`——
片段 `%zz` 属于主机；又如 `https://reader:p%40ss@:8443/v1` 缺少主机
时，reason 引用的地址为 `https://***@:8443/v1`，原因明确是
“is missing a host”，而不是 JSON 解析失败或 IPv6 括号问题。

基础路径中的 `@` 是普通路径字符：upstream
`https://reader:p%40ss@api.internal/v1@x%zz` 报错时展示为
`parse "https://***@api.internal/v1@x%zz": invalid URL escape "%zz"`，
`/v1@x%zz` 整段保留，其中的 `@` 不会被当作凭据分隔符，凭据仍只隐藏
authority 中最后一个 `@` 之前的部分。

#### 修正地址后的成功结果

把基础路径改为合法的 `/v1`（凭据 `reader:p%40ss` 保持不变）：

```json
{
  "routes": [
    {"id": "reader", "methods": ["GET"], "pathPrefix": "/reader", "upstream": "https://reader:p%40ss@api.internal/v1"}
  ]
}
```

对同一个请求 `{"method":"GET","target":"/reader/books/7?a=1&a="}`，
退出状态为 0、标准错误为空，标准输出为：

```json
{"routeId":"reader","upstreamURL":"https://reader:p%40ss@api.internal/v1/books/7?a=1&a="}
```

隐藏只作用于**失败诊断**：配置合法时，解析结果中的 `upstreamURL`
仍逐字节保留原始用户名、密码及其百分号编码（`p%40ss` 不会被解码成
`p@ss`），并照现有规则拼接——去掉 `/reader` 前缀后的剩余路径接到
基础路径 `/v1` 之后，连接处恰好保留一个 `/`，原始查询串（重复参数、
空值与顺序）逐字节保留；路由若配置了 `queryTransforms`，仍按前述
规则改写查询串。情况一修正后的 `https://reader:pw%254@api.internal/v1`
同样解析成功，`upstreamURL` 中保留的就是 `reader:pw%254`。通过校验
的配置用 `encoding/json` 保存时，upstream 中的用户名、密码与百分号
编码也原样写回，重新读取后解析结果不变（见下一节）。

### 保存配置为 JSON 并重新读取

前面介绍的 `ParseConfig` 是读取配置的完整校验入口；同一份通过校验的
`*Config` 可以用标准库 `encoding/json` 直接保存回 JSON，保存结果可以
再次交给 `ParseConfig` 读取，并用重新得到的配置按原规则解析请求：

```go
cfg, f := contractsentinel.ParseConfig(data)
if f != nil {
    // 展示 f.Code 与 f.Reason；读取失败的配置没有可用对象，停止使用。
}
saved, err := json.Marshal(cfg) // Config、Route、QueryTransform 实现了 MarshalJSON
```

保存后的 JSON 不必与原文件逐字节相同：缩进、空白与 JSON 字符串转义
（如 `&` 写作 `\u0026`）可以变化；以下内容会保留，因此重新读取后解析
同一请求得到的 routeId 与 upstreamURL 与保存前一致：

- 路由在 `routes` 数组中的顺序、方法名的大小写、`pathPrefix` 的原始
  文本（含百分号编码）与 `upstream` 的原始地址；
- `queryTransforms` 规则的执行顺序，以及规则中 `name`、`value`、`to`
  的字面字符串——它们按原样写入配置，只做 JSON 字符串转义，不会先按
  查询参数编码（例如名称 `a b` 保存后仍是 `"a b"`，不是 `a%20b`），
  所以重新读取后命中的仍是同一批参数、应用的仍是同一份字面值。

保存时几个容易误解的结果：

- `set` 的空字符串 `value` 仍会写出（`"value":""`）：空字符串是合法值，
  读取时只有缺少 `value` 字段才报错；
- `remove` 不写 `value` 或 `to`，`rename` 与 `copy` 保留 `to` 且不写
  `value`——多写的字段正是读取时会拒绝的形状；
- 未提供 `queryTransforms` 与显式 `"queryTransforms": []` 都保存为省略
  该字段（不会写成 `null`）：两种写法本就等价，重新读取后原查询串
  逐字节保留，不会被改写；
- 空路由配置保存为 `"routes": []` 而不是 `"routes": null`（`null` 在
  读取时是 routes 类型错误）；重新读取仍是合法配置，合法请求对其解析
  得到 `route_not_found`。

读取配置应始终通过完整校验入口 `ParseConfig`：它执行全部四层检查
（JSON 语法、结构与字段类型、改写规则、字段内容）。仅把 JSON 解码成
配置对象（`json.Unmarshal` 到 `Config`）只覆盖前三层，id 为空或重复、
方法非法、pathPrefix 或 upstream 内容非法等问题不会被发现，得到的
对象不能当作可用配置。保存成功同样不能代替合法性检查：`json.Marshal`
只负责把内存中的配置写出来，不重新校验内容。凡是 `ParseConfig` 返回
`Failure` 的配置都不要继续使用——此时没有可供解析的配置。

保存是库层面的能力；`resolve` 命令的输入、输出与错误约定（标准输出
的结果 JSON、标准错误的 code/reason、非零退出状态）保持不变。

#### 完整示例

`examples/saveconfig/main.go` 演示读取、保存、重新读取及解析同一个
请求的完整过程，可在本机离线运行：

```bash
go run ./examples/saveconfig
```

示例配置带一条改名后再设置同名参数的连续改写链（先把 `old` 改名为
`new`，再把 `new` 设为空字符串）：

```json
{
  "routes": [
    {
      "id": "api",
      "methods": ["GET"],
      "pathPrefix": "/api",
      "upstream": "http://api.internal/v1",
      "queryTransforms": [
        {"op": "rename", "name": "old", "to": "new"},
        {"op": "set", "name": "new", "value": ""}
      ]
    }
  ]
}
```

请求含重复参数、空值与原始百分号编码：

```json
{"method":"GET","target":"/api/orders/7?old=1&old=&keep=%2f%41&flag"}
```

运行输出（可逐行核对）：

```
saved config: {"routes":[{"id":"api","methods":["GET"],"pathPrefix":"/api","upstream":"http://api.internal/v1","queryTransforms":[{"op":"rename","name":"old","to":"new"},{"op":"set","name":"new","value":""}]}]}
before save: routeId=api upstreamURL=http://api.internal/v1/orders/7?new=&keep=%2f%41&flag
after save : routeId=api upstreamURL=http://api.internal/v1/orders/7?new=&keep=%2f%41&flag
saved empty config: {"routes":[]}
empty config resolve: code=route_not_found reason=no route matches GET /api/orders/7
```

保存后的配置里，路由顺序、方法大小写、`/api` 前缀、上游地址与两条
规则的执行顺序都原样保留；`rename` 带 `to` 不带 `value`，`set` 的空
字符串 `value` 仍然写出。重新读取后 routeId 与 upstreamURL 与保存前
一致，是因为保存保留了匹配与拼接所需的全部原始文本（前缀、方法、
上游、规则及顺序），规则中的名称与值按字面字符串写回，重新解析得到
的是语义相同的配置。

对请求查询串 `old=1&old=&keep=%2f%41&flag`，改写链的效果是：

- `rename old→new`：两个 `old` 参数在原位置改名，各自的值、数量与
  相对顺序保留，得到 `new=1&new=&keep=%2f%41&flag`；
- `set new=""`：合并所有 `new` 参数为一个，放在首次命中的位置，得到
  `new=`；
- 未命中任何规则的内容逐字节保留：`keep=%2f%41` 的原始百分号编码不
  解码也不重编码，无等号的 `flag` 原样保留。

最后的空路由配置演示：保存为 `"routes":[]` 而非 `null`，重新读取
合法，合法请求得到 `route_not_found`，错误以 code 与 reason 展示。

## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
