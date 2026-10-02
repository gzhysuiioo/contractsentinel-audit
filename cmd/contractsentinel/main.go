// Command contractsentinel is the 智能合约审计与形式化验证流水线 entry point.
package main

import (
	"encoding/json"
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
	fmt.Println("usage: contractsentinel <command> [arguments]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  demo                        run the built-in audit demo")
	fmt.Println("  resolve <config-file>       resolve one JSON request (read from stdin)")
	fmt.Println("                              against offline routes; no network connections")
	fmt.Println("  version                     print the version")
	fmt.Println("  help                        show this help")
}

func runResolve(args []string) {
	if len(args) != 1 {
		fail(contractsentinel.Failure{Code: "invalid_usage",
			Reason: "usage: contractsentinel resolve <config-file>"})
	}

	configData, err := os.ReadFile(args[0])
	if err != nil {
		fail(contractsentinel.Failure{Code: "invalid_config",
			Reason: fmt.Sprintf("cannot read config file %q: %v", args[0], err)})
	}
	requestData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(contractsentinel.Failure{Code: "invalid_request",
			Reason: fmt.Sprintf("cannot read request from stdin: %v", err)})
	}

	cfg, f := contractsentinel.ParseConfig(configData)
	if f != nil {
		fail(*f)
	}
	req, f := contractsentinel.ParseRequest(requestData)
	if f != nil {
		fail(*f)
	}
	resolution, f := contractsentinel.Resolve(cfg, req)
	if f != nil {
		fail(*f)
	}

	// HTML escaping is disabled so a raw query such as "a=1&b=2" is emitted
	// byte for byte instead of "&".
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resolution); err != nil {
		fail(contractsentinel.Failure{Code: "internal_error", Reason: err.Error()})
	}
}

// fail prints the error as JSON to stderr and exits non-zero; stdout is left
// untouched so no partial result is observable on failure.
func fail(f contractsentinel.Failure) {
	enc := json.NewEncoder(os.Stderr)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(f)
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
