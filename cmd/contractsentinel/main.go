// Command contractsentinel is the 智能合约审计与形式化验证流水线 entry point.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gzhysuiioo/contractsentinel-audit/contractsentinel"
)

func main() {
	command := "demo"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "demo":
		runDemo()
	case "version":
		fmt.Println("contractsentinel 0.1.0")
	case "help", "-h", "--help":
		usage()
	case "resolve":
		runResolve(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: contractsentinel [demo|version|help|resolve <config-file>]")
}

// runResolve implements `resolve <config-file>`: it reads a routing request
// from standard input, performs no network I/O, and prints the matched route
// with its upstream URL as JSON. Failures are reported on standard error.
func runResolve(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: contractsentinel resolve <config-file>")
		os.Exit(2)
	}

	// Check the whole configuration before touching the request.
	routes, err := contractsentinel.LoadRoutes(args[0])
	if err != nil {
		var cfgErr *contractsentinel.ConfigError
		if errors.As(err, &cfgErr) {
			emitFailure("invalid_config", cfgErr.Reason, nil)
		}
		emitFailure("invalid_config", err.Error(), nil)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		emitFailure("invalid_request", "无法读取标准输入: "+err.Error(), nil)
	}
	req, err := contractsentinel.ParseRequest(data)
	if err != nil {
		var reqErr *contractsentinel.RequestError
		if errors.As(err, &reqErr) {
			emitFailure("invalid_request", reqErr.Reason, nil)
		}
		emitFailure("invalid_request", err.Error(), nil)
	}

	res, err := contractsentinel.Resolve(routes, req)
	if err != nil {
		var resErr *contractsentinel.ResolutionError
		if errors.As(err, &resErr) {
			emitFailure(resErr.Code, resErr.Reason, resErr.Candidates)
		}
		emitFailure("route_not_found", err.Error(), nil)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "写出结果失败: %v\n", err)
		os.Exit(1)
	}
}

// emitFailure writes a JSON failure document to standard error and exits
// non-zero, leaving standard output empty.
func emitFailure(code, reason string, candidates []string) {
	doc := map[string]any{"code": code, "reason": reason}
	if len(candidates) > 0 {
		doc["candidates"] = candidates
	}
	enc := json.NewEncoder(os.Stderr)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "{\"code\":%q,\"reason\":%q}\n", code, reason)
	}
	os.Exit(1)
}

func runDemo() {
	artifact := contractsentinel.Artifact{Name: "Vault", ABI: "[{\"name\":\"withdraw\"}]", Bytecode: "0x6080", Source: "Vault.sol"}
	rules := []contractsentinel.Rule{
		{ID: "reentrancy-guard", Kind: "static", Severity: "high", Invariant: "no-reentrant-withdraw"},
		{ID: "access-control", Kind: "static", Severity: "medium", Invariant: "owner-only-withdraw", RequiresABI: true},
		{ID: "invariant-preserved", Kind: "symbolic", Severity: "critical", Invariant: "balance-monotonic"},
	}
	invariants := map[string]bool{"no-reentrant-withdraw": false, "owner-only-withdraw": true, "balance-monotonic": false}
	findings, err := contractsentinel.Run(artifact, rules, invariants)
	if err != nil {
		fmt.Println("audit refused:", err)
		return
	}
	for _, finding := range findings {
		fmt.Printf("rule=%s severity=%s invariant=%s evidence=%s\n", finding.Rule, finding.Severity, finding.Invariant, finding.Evidence)
	}
	fmt.Printf("artifact=%s rules=%d findings=%d\n", artifact.Name, len(rules), len(findings))
}
