// Command contractsentinel is the 智能合约审计与形式化验证流水线 entry point.
package main

import (
	"encoding/json"
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
	case "diff":
		runDiff(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: contractsentinel [demo|version|audit|report|diff|help]")
}

// runAudit parses an audit submission, builds the report and saves it.
func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	inputPath := fs.String("input", "", "path to the audit input JSON file")
	store := fs.String("store", "", "report store directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *inputPath == "" || *store == "" {
		fmt.Fprintln(os.Stderr, "usage: contractsentinel audit --input <file> --store <dir>")
		os.Exit(2)
	}
	data, err := os.ReadFile(*inputPath)
	if err != nil {
		fail("audit", err)
	}
	artifact, rules, invariants, err := contractsentinel.ParseAuditInput(data)
	if err != nil {
		fail("audit", err)
	}
	report, err := contractsentinel.BuildReport(artifact, rules, invariants)
	if err != nil {
		fail("audit", err)
	}
	if err := contractsentinel.SaveReport(*store, report); err != nil {
		fail("audit", err)
	}
	printReport("audit", report)
}

// runReport reads a saved report by id and prints it.
func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	store := fs.String("store", "", "report store directory")
	id := fs.String("id", "", "report id")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *store == "" || *id == "" {
		fmt.Fprintln(os.Stderr, "usage: contractsentinel report --store <dir> --id <id>")
		os.Exit(2)
	}
	report, err := contractsentinel.LoadReport(*store, *id)
	if err != nil {
		fail("report", err)
	}
	printReport("report", report)
}

// runDiff compares two stored reports and prints the diff JSON.
func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	store := fs.String("store", "", "report store directory")
	before := fs.String("before", "", "baseline report id")
	after := fs.String("after", "", "new report id")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *store == "" || *before == "" || *after == "" {
		fmt.Fprintln(os.Stderr, "usage: contractsentinel diff --store <dir> --before <id> --after <id>")
		os.Exit(2)
	}
	diff, err := contractsentinel.DiffStore(*store, *before, *after)
	if err != nil {
		fail("diff", err)
	}
	out, err := json.MarshalIndent(diff, "", "  ")
	if err != nil {
		fail("diff", err)
	}
	fmt.Println(string(out))
}

// fail prints an error to stderr and exits with a non-zero status.
func fail(command string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %s\n", command, err)
	os.Exit(1)
}

// printReport writes the full report JSON to stdout.
func printReport(command string, report contractsentinel.Report) {
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail(command, err)
	}
	fmt.Println(string(out))
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
