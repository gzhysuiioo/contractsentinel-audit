// saveconfig 示例（本机离线即可运行，仅依赖标准库与本仓库包）：
//
//	cd examples/saveconfig
//	go run . routes.json routes.saved.json
//
// 它展示一个完整过程：通过完整校验入口 ParseConfig 读入路由配置，用标准
// 库 encoding/json 把配置保存为 JSON，重新读取保存结果，再用保存前后两份
// 配置按原规则解析同一个请求。全程不建立网络连接。
//
// 用法：
//
//	saveconfig <config-file> [saved-file]
//
// 给出 saved-file 时，保存的 JSON 同时写入该文件。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: saveconfig <config-file> [saved-file]")
		os.Exit(2)
	}

	// 1) 读取配置。ParseConfig 是完整校验入口：JSON 语法、文档结构与基础
	//    字段类型、queryTransforms 规则、字段内容（id、methods、pathPrefix、
	//    upstream）四层检查全部通过后才返回 *Config。失败时返回 nil 与
	//    *Failure，调用方只能展示 code/reason 并停止使用这份配置。
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %q: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	cfg, ok := load(raw, os.Args[1])
	if !ok {
		os.Exit(1)
	}

	// 2) 保存为 JSON。规则中的 name、value、to 按字面值写出（空格、中文、
	//    '+'、'%' 原样保留在 JSON 字符串里），不做任何查询串百分号编码；
	//    编码只在后续真正改写请求查询串时按规则发生。
	saved, err := saveJSON(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot marshal config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("=== saved JSON ===")
	fmt.Println(string(saved))
	if len(os.Args) == 3 {
		if err := os.WriteFile(os.Args[2], saved, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write %q: %v\n", os.Args[2], err)
			os.Exit(1)
		}
	}

	// 3) 重新读取保存结果。保存后的文件必须走同一个完整校验入口，而不是
	//    只把 JSON 解码进结构体：能解析成对象不等于配置可用。
	reloaded, ok := load(saved, "saved config")
	if !ok {
		os.Exit(1)
	}

	// 4) 用保存前、保存后的配置解析同一个请求。该请求含连续同名参数、
	//    无等号参数、空值与原始百分号编码。
	request := []byte(`{"method":"get","target":"/api/orders/7?old=1&old=2&flag&keep=%2f%41&e=&old=3&z"}`)
	req, f := contractsentinel.ParseRequest(request)
	if f != nil {
		printFailure(f)
		os.Exit(1)
	}
	before, f := contractsentinel.Resolve(cfg, req)
	if f != nil {
		printFailure(f)
		os.Exit(1)
	}
	after, f := contractsentinel.Resolve(reloaded, req)
	if f != nil {
		printFailure(f)
		os.Exit(1)
	}
	fmt.Println("=== resolve before save ===")
	printResolution(before)
	fmt.Println("=== resolve after save/reload ===")
	printResolution(after)

	// 5) 未提供改写规则与显式空数组，保存时都省略 queryTransforms 字段
	//    （不写 null）；重新读取后原查询串逐字节保留。
	ruleless := []byte(`{"routes":[
	  {"id":"absent","methods":["*"],"pathPrefix":"/a","upstream":"http://h"},
	  {"id":"empty","methods":["*"],"pathPrefix":"/b","upstream":"http://h","queryTransforms":[]}
	]}`)
	rl, ok := load(ruleless, "ruleless config")
	if !ok {
		os.Exit(1)
	}
	out, err := saveJSON(rl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot marshal ruleless config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("=== ruleless routes saved (field omitted, never null) ===")
	fmt.Println(string(out))

	// 6) 空路由配置（连 routes 键都没有）保存为 routes 空数组而不是 null，
	//    再次读取仍合法；合法请求对其解析得到 route_not_found。
	empty, ok := load([]byte(`{}`), "empty config")
	if !ok {
		os.Exit(1)
	}
	out, err = json.Marshal(empty)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot marshal empty config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("=== empty routes saved: %s ===\n", string(out))
	reloadedEmpty, ok := load(out, "saved empty config")
	if !ok {
		os.Exit(1)
	}
	_, f = contractsentinel.Resolve(reloadedEmpty, req)
	fmt.Println("=== resolve against saved empty routes ===")
	if f == nil {
		fmt.Fprintln(os.Stderr, "expected route_not_found")
		os.Exit(1)
	}
	printFailure(f)

	// 7) 读取失败的配置：ParseConfig 返回 nil，示例只展示 code 与 reason，
	//    并且不再使用这份配置（remove 不允许带 value）。
	bad := []byte(`{"routes":[{"id":"r","methods":["*"],"pathPrefix":"/","upstream":"http://h",
	  "queryTransforms":[{"op":"remove","name":"x","value":"1"}]}]}`)
	fmt.Println("=== reading an invalid config ===")
	if _, ok := load(bad, "invalid config"); !ok {
		fmt.Println("(ParseConfig returned no config; it is never used)")
	}
}

// load 通过完整校验入口读取配置；失败时打印 code 与 reason 并返回
// ok=false，调用方不得继续使用那份配置。
func load(data []byte, label string) (*contractsentinel.Config, bool) {
	cfg, f := contractsentinel.ParseConfig(data)
	if f != nil {
		fmt.Fprintf(os.Stderr, "cannot use %s:\n", label)
		printFailure(f)
		return nil, false
	}
	return cfg, true
}

// saveJSON 用标准库保存配置。SetEscapeHTML(false) 让字符串里的 '&' 等字符
// 直接出现；缩进与转义形式可以与原文件不同，重新读取仍然等价。
func saveJSON(cfg *contractsentinel.Config) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func printFailure(f *contractsentinel.Failure) {
	fmt.Printf("code:   %s\n", f.Code)
	fmt.Printf("reason: %s\n", f.Reason)
}

func printResolution(r *contractsentinel.Resolution) {
	fmt.Printf("routeId:     %s\n", r.RouteID)
	fmt.Printf("upstreamURL: %s\n", r.UpstreamURL)
}
