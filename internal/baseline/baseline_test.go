package baseline

import (
	"path/filepath"
	"testing"

	"github.com/ulisespignatelli/secretguard/internal/finding"
)

func TestRoundTrip(t *testing.T) {
	fs := []finding.Finding{{Fingerprint: "a", RuleID: "r", File: "x"}, {Fingerprint: "b", RuleID: "r", File: "y"}}
	path := filepath.Join(t.TempDir(), "bl.json")
	if err := FromFindings(fs[:1]).Save(path); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	left, skipped := b.Filter(fs)
	if skipped != 1 || len(left) != 1 || left[0].Fingerprint != "b" {
		t.Fatalf("filtro incorrecto: %+v %d", left, skipped)
	}
	if empty, err := Load(filepath.Join(t.TempDir(), "no-existe.json")); err != nil || len(empty.Entries) != 0 {
		t.Fatal("una línea base inexistente debería estar vacía")
	}
}
