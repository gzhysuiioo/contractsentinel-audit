package contractsentinel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rawReportWithID builds a hand-authored report and stamps the id computed from
// its own bytes-equivalent content, bypassing BuildReport. It models a caller
// who recomputed the id for an otherwise invalid report.
func rawReportWithID(r Report) Report {
	r.ReportID = ReportID(r)
	return r
}

// writeReportFile writes a report's JSON directly into the store under its id.
func writeReportFile(t *testing.T, dir string, r Report) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, r.ReportID+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func validManualReport() Report {
	return Report{
		Artifact: ReportArtifact{Name: "Vault", Hash: ArtifactHash(sampleArtifact())},
		Rules: []ReportRule{
			{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv-1", Version: "1", Status: StatusPass},
			{ID: "r2", Kind: "static", Severity: "low", Invariant: "inv-2", Version: "2", Status: StatusToolMissing, Note: "tool absent"},
		},
		Findings: []ReportFinding{},
	}
}

// --- Save validates the submission, independent of the archive ---

func TestSaveRejectsIDContentMismatch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	report := rawReportWithID(validManualReport())
	// Tamper with a rule but keep the original id.
	report.Rules[0].Severity = "critical"
	err := SaveReport(dir, report)
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T %v", err, err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatal("invalid submission must not create the store")
	}
}

func TestSaveRejectsRecomputedInvalidReport(t *testing.T) {
	// Even with a correctly recomputed id the invalid rules must be refused.
	cases := map[string]Report{
		"empty artifact name": func() Report {
			r := validManualReport()
			r.Artifact.Name = ""
			return r
		}(),
		"bad artifact hash": func() Report {
			r := validManualReport()
			r.Artifact.Hash = "xyz"
			return r
		}(),
		"empty rule id": func() Report {
			r := validManualReport()
			r.Rules[0].ID = ""
			return r
		}(),
		"empty rule version": func() Report {
			r := validManualReport()
			r.Rules[0].Version = ""
			return r
		}(),
		"unknown status": func() Report {
			r := validManualReport()
			r.Rules[0].Status = "跳过"
			return r
		}(),
		"tool missing without note": func() Report {
			r := validManualReport()
			r.Rules[0].Status = StatusToolMissing
			r.Rules[0].Note = "   "
			return r
		}(),
		"timeout without note": func() Report {
			r := validManualReport()
			r.Rules[0].Status = StatusTimeout
			return r
		}(),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			err := SaveReport(dir, rawReportWithID(r))
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("expected errInvalid, got %T %v", err, err)
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Fatal("invalid submission must not create the store")
			}
		})
	}
}

func TestSaveRejectsDuplicateRuleID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	r := validManualReport()
	r.Rules = append(r.Rules, ReportRule{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv-1", Version: "1", Status: StatusPass})
	err := SaveReport(dir, rawReportWithID(r))
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid, got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "duplicate rule id r1") {
		t.Fatalf("error must name the rule: %v", err)
	}
}

func TestSaveRejectsFindingMismatch(t *testing.T) {
	hash := ArtifactHash(sampleArtifact())
	base := func() Report {
		return Report{
			Artifact: ReportArtifact{Name: "Vault", Hash: hash},
			Rules: []ReportRule{
				{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv-1", Version: "1", Status: StatusDefect},
			},
			Findings: []ReportFinding{
				{ArtifactHash: hash, RuleID: "r1", Version: "1", Severity: "high", Invariant: "inv-1", Evidence: "invariant inv-1 does not hold"},
			},
		}
	}
	mutations := map[string]func(*Report){
		"artifact hash":   func(r *Report) { r.Findings[0].ArtifactHash = strings.Repeat("a", 64) },
		"version":         func(r *Report) { r.Findings[0].Version = "9" },
		"severity":        func(r *Report) { r.Findings[0].Severity = "low" },
		"invariant":       func(r *Report) { r.Findings[0].Invariant = "other" },
		"evidence":        func(r *Report) { r.Findings[0].Evidence = "rewritten" },
		"missing finding": func(r *Report) { r.Findings = nil },
		"finding without rule": func(r *Report) {
			r.Rules[0].Status = StatusPass
		},
		"duplicate finding": func(r *Report) {
			r.Findings = append(r.Findings, r.Findings[0])
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			r := base()
			mutate(&r)
			err := SaveReport(dir, rawReportWithID(r))
			var ei errInvalid
			if !errors.As(err, &ei) {
				t.Fatalf("expected errInvalid, got %T %v", err, err)
			}
		})
	}
}

func TestSaveInvalidSubmissionKeepsArchiveIntact(t *testing.T) {
	dir := t.TempDir()
	good, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, good); err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(dir, good.ReportID+".json")
	goodBytes, _ := os.ReadFile(goodPath)

	// A different id slot already holds a fine report; an invalid submission
	// for another slot must neither add files nor touch the archive.
	bad := rawReportWithID(validManualReport())
	bad.Rules[0].Version = ""
	if err := SaveReport(dir, bad); err == nil {
		t.Fatal("expected invalid submission to fail")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 1 {
		t.Fatalf("invalid submission changed the store: %v", matches)
	}
	kept, _ := os.ReadFile(goodPath)
	if string(kept) != string(goodBytes) {
		t.Fatal("invalid submission modified the existing archive")
	}
}

// --- The id is checked against the submitted content ---

func TestSaveModifiedRuleKeepsOriginalID(t *testing.T) {
	dir := t.TempDir()
	original, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants(), nil)
	if err := SaveReport(dir, original); err != nil {
		t.Fatal(err)
	}
	// Change a rule but reuse the original id: must fail even though the
	// original archive on disk is perfectly intact.
	modified := original
	modified.Rules = append([]ReportRule(nil), original.Rules...)
	modified.Rules[0].Severity = "critical"
	err := SaveReport(dir, modified)
	var ei errInvalid
	if !errors.As(err, &ei) {
		t.Fatalf("expected errInvalid for stale id, got %T %v", err, err)
	}
	loaded, err := LoadReport(dir, original.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Rules[0].ID == modified.Rules[0].ID && loaded.Rules[0].Severity == "critical" {
		t.Fatal("the archive was modified by the rejected submission")
	}
}

// --- Byte preservation for logical duplicates ---

func TestSaveDuplicatePermutationKeepsFirstBytes(t *testing.T) {
	dir := t.TempDir()
	first, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants(), nil)
	rules := sampleRules()
	reversed, _ := BuildReport(sampleArtifact(), []Rule{rules[2], rules[1], rules[0]}, sampleInvariants(), nil)
	if first.ReportID != reversed.ReportID {
		t.Fatal("permutation must keep the same id")
	}
	firstBytes, _ := json.Marshal(first)
	secondBytes, _ := json.Marshal(reversed)
	if string(firstBytes) == string(secondBytes) {
		t.Fatal("test setup: permutation must serialize differently")
	}
	if err := SaveReport(dir, first); err != nil {
		t.Fatal(err)
	}
	// Submit the reordered duplicate: it must succeed and leave the first
	// archiver's bytes in place.
	if err := SaveReport(dir, reversed); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(filepath.Join(dir, first.ReportID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(firstBytes) {
		t.Fatal("duplicate resubmission replaced the original bytes")
	}
}

// --- Concurrency: one complete file, all duplicates succeed ---

func TestSaveConcurrentPermutations(t *testing.T) {
	dir := t.TempDir()
	base := sampleRules()
	perms := [][]Rule{
		base,
		{base[2], base[1], base[0]},
		{base[1], base[0], base[2]},
		{base[2], base[0], base[1]},
	}
	reports := make([]Report, len(perms))
	encoded := make([][]byte, len(perms))
	for i, p := range perms {
		r, err := BuildReport(sampleArtifact(), p, sampleInvariants(), nil)
		if err != nil {
			t.Fatal(err)
		}
		reports[i] = r
		encoded[i], _ = json.Marshal(r)
	}
	id := reports[0].ReportID

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	stop := make(chan struct{})
	// Concurrent readers must only ever see "missing" or a complete report.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				if r, err := LoadReport(dir, id); err == nil {
					if r.ReportID != id {
						errs <- errInvalid("reader saw wrong id")
						return
					}
				} else {
					var nf errNotFound
					if !errors.As(err, &nf) {
						errs <- err
						return
					}
				}
			}
		}
	}()
	for rep := 0; rep < 4; rep++ {
		for _, r := range reports {
			wg.Add(1)
			go func(r Report) {
				defer wg.Done()
				errs <- SaveReport(dir, r)
			}(r)
		}
	}
	wg.Wait()
	close(stop)
	<-readerDone
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent save/load failed: %v", err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 1 {
		t.Fatalf("expected exactly one report, got %d: %v", len(matches), matches)
	}
	kept, _ := os.ReadFile(matches[0])
	matched := false
	for _, b := range encoded {
		if string(kept) == string(b) {
			matched = true
		}
	}
	if !matched {
		t.Fatal("archived bytes match none of the complete submissions")
	}
}

// --- Corrupt slot: never repaired or overwritten ---

func TestSaveCorruptSlotCreatedDuringSaveIsKept(t *testing.T) {
	dir := t.TempDir()
	report, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants(), nil)
	path := filepath.Join(dir, report.ReportID+".json")

	// Another process plants a corrupt file while saves are in flight.
	var wg sync.WaitGroup
	plantOnce := sync.Once{}
	plant := func() {
		plantOnce.Do(func() { _ = os.WriteFile(path, []byte(`{broken`), 0o644) })
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond)
		plant()
	}()
	sawCorrupt := false
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = SaveReport(dir, report)
		}()
	}
	// Deterministic follow-up: once the corrupt file sits at the slot, a save
	// must report corruption and leave it.
	plant()
	wg.Wait()
	for i := 0; i < 8; i++ {
		err := SaveReport(dir, report)
		var ec errCorrupt
		if errors.As(err, &ec) {
			sawCorrupt = true
		} else if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if !sawCorrupt {
		t.Fatal("expected an archive-corruption error against the corrupt slot")
	}
	kept, _ := os.ReadFile(path)
	if string(kept) != `{broken` {
		t.Fatalf("the valid submission repaired/overwrote the corrupt file: %q", kept)
	}
}

// --- Load/Diff reject invalid archives even with a self-consistent id ---

func TestLoadRejectsRecomputedInvalidArchive(t *testing.T) {
	dir := t.TempDir()
	r := validManualReport()
	r.Rules = append(r.Rules, r.Rules[0]) // duplicate rule id
	r = rawReportWithID(r)
	writeReportFile(t, dir, r)
	_, err := LoadReport(dir, r.ReportID)
	var ec errCorrupt
	if !errors.As(err, &ec) {
		t.Fatalf("expected errCorrupt, got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "duplicate rule id r1") {
		t.Fatalf("error must name the rule: %v", err)
	}
}

func TestDiffRejectsRecomputedInvalidArchive(t *testing.T) {
	dir := t.TempDir()
	good := saveDiffReport(t, dir, sampleArtifact(), sampleRules(), sampleInvariants())
	r := validManualReport()
	r.Rules[0].Status = StatusTimeout // no note
	r = rawReportWithID(r)
	writeReportFile(t, dir, r)
	if _, err := DiffStore(dir, good.ReportID, r.ReportID); err == nil {
		t.Fatal("expected diff to reject invalid archive")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("expected errCorrupt, got %T %v", err, err)
		}
	}
	// Failed diff must leave the store untouched.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 2 {
		t.Fatalf("failed diff modified the store: %v", matches)
	}
}

// --- Error classification ---

func TestErrorClassification(t *testing.T) {
	dir := t.TempDir()
	good, _ := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants(), nil)
	if err := SaveReport(dir, good); err != nil {
		t.Fatal(err)
	}
	// Input invalid.
	if err := SaveReport(dir, func() Report {
		r := good
		r.ReportID = "too-short"
		return r
	}()); err == nil {
		t.Fatal("expected error for malformed id")
	} else {
		var ei errInvalid
		if !errors.As(err, &ei) {
			t.Fatalf("want errInvalid, got %T", err)
		}
	}
	// Not found.
	if _, err := LoadReport(dir, strings.Repeat("0", 64)); err == nil {
		t.Fatal("expected not found")
	} else {
		var nf errNotFound
		if !errors.As(err, &nf) {
			t.Fatalf("want errNotFound, got %T %v", err, err)
		}
	}
	// Corrupt.
	path := filepath.Join(dir, good.ReportID+".json")
	original, _ := os.ReadFile(path)
	_ = os.WriteFile(path, []byte(`{broken`), 0o644)
	if _, err := LoadReport(dir, good.ReportID); err == nil {
		t.Fatal("expected corrupt")
	} else {
		var ec errCorrupt
		if !errors.As(err, &ec) {
			t.Fatalf("want errCorrupt, got %T %v", err, err)
		}
	}
	_ = os.WriteFile(path, original, 0o644)
}

// --- Evidence text is preserved verbatim ---

func TestSavePreservesNoteEvidenceVerbatim(t *testing.T) {
	dir := t.TempDir()
	hash := ArtifactHash(sampleArtifact())
	rules := []Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}}
	checks := []CheckRecord{
		{ArtifactHash: hash, RuleID: "r1", Version: "1", Status: StatusDefect, Note: "  counterexample:\n\tspaced  "},
	}
	report, err := BuildReport(sampleArtifact(), rules, nil, checks)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Findings[0].Evidence; got != "  counterexample:\n\tspaced  " {
		t.Fatalf("evidence was rewritten: %q", got)
	}
}

func TestSaveOldStyleBooleanEvidence(t *testing.T) {
	dir := t.TempDir()
	report, err := BuildReport(sampleArtifact(),
		[]Rule{{ID: "r1", Kind: "static", Severity: "high", Invariant: "inv", Version: "1"}},
		map[string]bool{"inv": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveReport(dir, report); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReport(dir, report.ReportID)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Findings[0].Evidence; got != "invariant inv does not hold" {
		t.Fatalf("old-style evidence changed: %q", got)
	}
}
