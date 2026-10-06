# 智能合约审计与形式化验证流水线

## 用途

合约产物与 ABI 管理、静态规则与模式库、符号执行与模糊测试编排、不变式检查、缺陷归因与报告版本化。

本仓库是可持续演进的自托管 Go 应用。领域核心位于 `contractsentinel/`，命令入口位于 `cmd/contractsentinel/`。

```bash
go run ./cmd/contractsentinel demo
go run ./cmd/contractsentinel version
go run ./cmd/contractsentinel resolve <config-file> < request.json
go run ./examples/saveconfig examples/saveconfig/routes.json   # 读取、保存、重新读取并解析同一请求
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

### 作为 Go 库读取、保存与重新读取配置

离线路由能力也通过 `contractsentinel` 包的公开入口提供，全程不建立网络连接：

- `ParseConfig(data []byte) (*Config, *Failure)`：读取并**完整校验**配置，是读取任何
  配置（包括刚保存的文件）的入口；
- 标准库 `encoding/json`（`json.Marshal(cfg)` 或 `json.Encoder`）：把 `*Config`
  保存为 JSON，`Config`、`Route`、`QueryTransform` 已实现各自的 `MarshalJSON`，
  调用方不需要自己挑选字段；
- `ParseRequest` 与 `Resolve`：保存前后按同一套规则解析请求。

下面这段程序可在本机离线运行：读入 `routes.json`，保存为 `routes.saved.json`，
重新读取保存结果，再用保存前后两份配置解析同一个请求。任何一步失败都打印
`code` 与 `reason` 并停止；读取失败的配置不会被继续使用。可直接运行的版本在
[`examples/saveconfig`](examples/saveconfig)（`cd examples/saveconfig &&
go run . routes.json routes.saved.json`），其中还包含本小节后面的几种边界情形。

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

func main() {
	// ParseConfig 是完整校验入口；读取失败时返回的 cfg 为 nil。
	raw, err := os.ReadFile("routes.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg, f := contractsentinel.ParseConfig(raw)
	if f != nil {
		// 只展示 code 与 reason，并停止使用这份配置。
		fmt.Fprintf(os.Stderr, "code=%s\nreason=%s\n", f.Code, f.Reason)
		os.Exit(1)
	}

	// 保存为 JSON；缩进与 HTML 转义开关按需选择，语义不受影响。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("routes.saved.json", buf.Bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 保存结果重新走同一个完整校验入口，而不是只把 JSON 解码进结构体。
	saved, f := contractsentinel.ParseConfig(buf.Bytes())
	if f != nil {
		fmt.Fprintf(os.Stderr, "code=%s\nreason=%s\n", f.Code, f.Reason)
		os.Exit(1)
	}

	// 按原规则解析请求；保存前后两份配置得到相同的 routeId 与 upstreamURL。
	request := []byte(`{"method":"get","target":"/api/orders/7?old=1&old=2&flag&keep=%2f%41&e=&old=3&z"}`)
	req, f := contractsentinel.ParseRequest(request)
	if f != nil {
		fmt.Fprintf(os.Stderr, "code=%s\nreason=%s\n", f.Code, f.Reason)
		os.Exit(1)
	}
	for _, c := range []*contractsentinel.Config{cfg, saved} {
		res, f := contractsentinel.Resolve(c, req)
		if f != nil {
			fmt.Fprintf(os.Stderr, "code=%s\nreason=%s\n", f.Code, f.Reason)
			os.Exit(1)
		}
		fmt.Printf("routeId=%s\nupstreamURL=%s\n", res.RouteID, res.UpstreamURL)
	}
}
```

用于该示例的配置（`examples/saveconfig/routes.json`）带有查询串改写规则，
其中包含“先改名、再对同名参数 set”的连续改写，规则名称与值都是普通字面
字符串（含空格、中文、`+`、`%`），不是查询参数编码：

```json
{
  "routes": [
    {
      "id": "api",
      "methods": ["get"],
      "pathPrefix": "/api",
      "upstream": "http://api.internal/v1/",
      "queryTransforms": [
        {"op": "rename", "name": "old", "to": "new"},
        {"op": "set", "name": "new", "value": ""},
        {"op": "set", "name": "a b", "value": "中+%"},
        {"op": "remove", "name": "flag"}
      ]
    },
    {
      "id": "root",
      "methods": ["*"],
      "pathPrefix": "/",
      "upstream": "https://fallback.internal/base/"
    }
  ]
}
```

被解析的请求是
`GET /api/orders/7?old=1&old=2&flag&keep=%2f%41&e=&old=3&z`（示例 JSON 中方法名
写作小写 `"get"`，与配置里的 `"get"` 按字面、区分大小写地匹配）：它同时含
重复参数（`old` 出现三次）、无等号参数（`flag`、`z`）、空值（`e=`）与原始
百分号编码（`%2f%41`）。

保存得到的 JSON 不必与原文件逐字节相同：键按固定次序写出、缩进可能不同、
字符串转义形式也可能不同（例如默认编码器可能把 `&` 写成 `\u0026` 这样的
Unicode 转义，而示例用 `SetEscapeHTML(false)` 直接写出 `&`），但语义完全
等价。紧凑写法如下（示例程序写的是两空格缩进版）：

```json
{"routes":[{"id":"api","methods":["get"],"pathPrefix":"/api","upstream":"http://api.internal/v1/","queryTransforms":[{"op":"rename","name":"old","to":"new"},{"op":"set","name":"new","value":""},{"op":"set","name":"a b","value":"中+%"},{"op":"remove","name":"flag"}]},{"id":"root","methods":["*"],"pathPrefix":"/","upstream":"https://fallback.internal/base/"}]}
```

保存前与保存后重新读取，解析同一请求的输出逐字相同：

```text
routeId=api
upstreamURL=http://api.internal/v1/orders/7?new=&keep=%2f%41&e=&z&a%20b=%E4%B8%AD%2B%25
```

之所以 `routeId` 与 `upstreamURL` 一致，是因为保存逐项保留了决定匹配与拼接的
全部内容：`routes` 数组顺序、`methods` 的大小写（小写 `get` 不会被改成 `GET`）、
`pathPrefix` 的原始字符串（`/api` 仍按原始编码与路径段边界匹配）、`upstream`
原文（`http://api.internal/v1/` 的主机与基础路径不变，连接仍折叠为恰好一个
`/`），以及 `queryTransforms` 的规则顺序与每条规则的字面字符串；重新读取后
匹配、拼接与改写规则没有任何变化。

查询串的改写按规则数组顺序逐条发生，可逐步核对：

1. `rename old → new`：三个 `old` 在各自原位置改名为 `new`，值、数量与相对
   顺序保留，得到
   `new=1&new=2&flag&keep=%2f%41&e=&new=3&z`；
2. `set new=""`：把全部同名参数合并为一个，放在首次命中的位置，得到
   `new=&flag&keep=%2f%41&e=&z`；
3. `set "a b"="中+%"`：查询中没有该名称，追加到末尾；编码只在这一步作用于
   新参数本身，写成 `a%20b=%E4%B8%AD%2B%25`（空格为 `%20`，`+` 为 `%2B`，
   `%` 为 `%25`）；
4. `remove flag`：删除无等号参数 `flag`。

最终查询串为 `new=&keep=%2f%41&e=&z&a%20b=%E4%B8%AD%2B%25`。被改写的是三个
`old`（先改名再被空值合并）、被删除的 `flag`，以及末尾新增的 `a b`；以下
原始内容继续逐字节保留：`keep=%2f%41` 的百分号编码（不解码、不改写大小写）、
`e=` 的空值与等号、无等号参数 `z`，以及各参数的相对顺序。

#### 保存时几个容易误解的结果

- `set` 的空字符串仍然写出：`{"op":"set","name":"a","value":""}` 中的
  `"value":""` 不能省略，空字符串是有效取值。
- `remove` 只写 `op` 与 `name`，不写 `value` 或 `to`：
  `{"op":"remove","name":"flag"}`。
- `rename` 保留 `to` 且不写 `value`：
  `{"op":"rename","name":"old","to":"new"}`。
- 规则中的 `name`、`value`、`to` 一律按**字面字符串**保存：空格、中文、`+`、
  `%` 原样进入 JSON 字符串，保存时不会先按查询参数做百分号编码；编码只在以后
  解析请求、规则实际改写查询串时发生。
- 一条路由未提供 `queryTransforms` 与显式写成 `"queryTransforms": []`，保存时
  都省略该字段（绝不会写成 `null`）；重新读取后两种写法等价，原查询串都不被
  改写。
- 空路由配置（`{}` 或 `{"routes":[]}`）保存为 `{"routes":[]}`，而不是会被读取
  拒绝的 `"routes": null`；再次读取仍是合法配置，合法请求对其解析得到
  `route_not_found`，例如
  `code=route_not_found`、`reason=no route matches get /api/orders/7`。

#### 读取请走完整校验入口：解码不等于配置可用

读取配置应始终使用 `ParseConfig`。它依次执行四层检查：JSON 语法、文档结构与
基础字段类型、`queryTransforms` 规则形状、字段内容（非空且唯一的 id、合法
methods、以 `/` 开头的 pathPrefix、合法的 upstream 等）。仅把 JSON 解码进
配置对象不等于确认配置可用：`json.Unmarshal(data, &cfg)`（或
`Config.UnmarshalJSON`）只覆盖前三层，例如一份 pathPrefix 不以 `/` 开头、
id 重复或 upstream 缺少主机的文档可以解码成功，却只有 `ParseConfig` 会以
`invalid_config` 拒绝（reason 仍定位到具体路由与字段）。同样，用代码手工
拼出的 `*Config` 即使字段不合法也能 `json.Marshal` 成功——**保存成功不能代替
合法性检查**；保存得到的 JSON 在再次使用前仍应交给 `ParseConfig`。
`ParseConfig` 失败时不返回配置对象，调用方应展示返回的 `code` 与 `reason`
并停止使用那份输入，例如：

```text
code=invalid_config
reason=route 1 (id "r"), queryTransforms rule 1: remove must not include a value
```

#### `resolve` 命令的约定不变

本小节只补充 Go 库用法，`resolve` 命令的输入输出与错误约定保持不变：仍从
配置文件参数与标准输入读取，成功时向标准输出 `routeId`/`upstreamURL`，
失败时向标准错误输出含 `code`、`reason`（`route_conflict` 另含 `candidates`）
的 JSON 并以非零状态退出。用上述方式保存出的 JSON 文件可以直接作为
`contractsentinel resolve <config-file>` 的配置参数，结果与保存前一致。


## 技术方向

smart-contract-audit, formal-verification, symbolic-execution, fuzzing, security, exploit-analysis, reentrancy

## 运行要求

Go 1.26，仅使用标准库，全部行为可在本机 CPU 上离线复现。
