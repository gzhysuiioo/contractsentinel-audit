// Command contractsentinel is the 智能合约审计与形式化验证流水线 entry point.
package main

import (
	"fmt"
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: contractsentinel [demo|version|help]")
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
