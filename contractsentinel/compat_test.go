package contractsentinel

import (
	"os"
	"path/filepath"
	"testing"
)

// Old-format boolean-only reports (no checks, no note field) must load
// unchanged and keep the exact report ids produced by the previous code.
func TestBackwardCompatOldArchives(t *testing.T) {
	cases := []struct {
		path string
		id   string
	}{
		{"testdata/old-full.json", "8f6b21baff121b19a8d0391a81f6515fa106d1574a384b4cd7d8afc198a03882"},
		{"testdata/old-onepass.json", "00af33dc11fae0978423148b06d13675df1d540d5f183c4b0f0fb9649da02a78"},
	}
	dir := t.TempDir()
	for _, c := range cases {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, c.id+".json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		r, err := LoadReport(dir, c.id)
		if err != nil {
			t.Fatalf("old archive %s failed to load: %v", c.path, err)
		}
		if r.ReportID != c.id {
			t.Errorf("old archive %s id = %q, want %q", c.path, r.ReportID, c.id)
		}
		if _, err := LoadReportForDiff(dir, c.id); err != nil {
			t.Errorf("old archive %s not diff-loadable: %v", c.path, err)
		}
	}
	// Rebuilding the boolean-only report must reproduce the frozen id.
	rebuilt, err := BuildReport(sampleArtifact(), sampleRules(), sampleInvariants())
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.ReportID != cases[0].id {
		t.Errorf("rebuilt id = %q, want frozen %q", rebuilt.ReportID, cases[0].id)
	}
}
