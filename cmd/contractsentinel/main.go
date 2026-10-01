// Command contractsentinel is the 智能合约审计与形式化验证流水线 entry point.
package main

import (
	"flag"
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
	case "audit":
		runAudit(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
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
	fmt.Println("       contractsentinel audit --input <file> --store <dir>")
	fmt.Println("       contractsentinel report --store <dir> --id <report-id>")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "audit submission JSON file")
	store := fs.String("store", "", "report store directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *input == "" || *store == "" {
		fmt.Fprintln(os.Stderr, "audit: --input and --store are required")
		os.Exit(2)
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		fail(fmt.Errorf("read input: %w", err))
	}
	report, raw, err := contractsentinel.Audit(data, *store)
	if err != nil {
		fail(err)
	}
	fmt.Printf("report %s\n", report.ID)
	os.Stdout.Write(raw)
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	store := fs.String("store", "", "report store directory")
	id := fs.String("id", "", "report id")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *store == "" || *id == "" {
		fmt.Fprintln(os.Stderr, "report: --store and --id are required")
		os.Exit(2)
	}
	_, raw, err := contractsentinel.LoadReport(*store, *id)
	if err != nil {
		fail(err)
	}
	os.Stdout.Write(raw)
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
