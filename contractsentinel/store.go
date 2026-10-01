package contractsentinel

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

var reportIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Audit parses a submission, builds the report and stores it. It returns the
// report and its canonical bytes. Nothing is stored when the input is invalid
// or the artifact is insufficient for the requested rules.
func Audit(input []byte, storeDir string) (*Report, []byte, error) {
	artifact, rules, invariants, err := ParseAuditInput(input)
	if err != nil {
		return nil, nil, err
	}
	report, err := BuildReport(artifact, rules, invariants)
	if err != nil {
		return nil, nil, err
	}
	raw := report.Marshal()
	if err := SaveReport(storeDir, report.ID, raw); err != nil {
		return nil, nil, err
	}
	return report, raw, nil
}

// SaveReport stores raw under <dir>/<id>.json. Identical reports are kept
// once and every submission succeeds; a corrupted archive under the same id
// fails the submission and is left untouched. Writes go through a temporary
// file and an atomic rename so concurrent submitters and readers never see a
// partial report, and an interrupted write can simply be retried.
func SaveReport(dir, id string, raw []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}
	path := filepath.Join(dir, id+".json")
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if _, verr := VerifyReport(existing, id); verr != nil {
			return fmt.Errorf("refusing to overwrite archive %s: %w", id, verr)
		}
		return nil
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("read existing archive %s: %w", id, err)
	}

	tmp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return fmt.Errorf("create temporary report file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write report %s: %w", id, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync report %s: %w", id, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close report %s: %w", id, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("commit report %s: %w", id, err)
	}
	return nil
}

// LoadReport reads and verifies the report stored under id.
func LoadReport(dir, id string) (*Report, []byte, error) {
	if !reportIDPattern.MatchString(id) {
		return nil, nil, errInvalid("invalid report id " + id)
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("report %s not found", id)
		}
		return nil, nil, fmt.Errorf("read report %s: %w", id, err)
	}
	report, err := VerifyReport(data, id)
	if err != nil {
		return nil, nil, err
	}
	return report, data, nil
}
