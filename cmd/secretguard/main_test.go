package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/ulisespignatelli/secretguard/internal/testutil"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExitCodesAndBaseline(t *testing.T) {
	root := t.TempDir()
	if code, _, _ := runCLI("scan", root); code != 0 {
		t.Fatalf("carpeta vacía debería salir con 0, salió %d", code)
	}
	tok := J("gh", "p_", Rand(36, Alnum, 1))
	if err := os.WriteFile(filepath.Join(root, "deploy.sh"), []byte("TOKEN="+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI("scan", root)
	if code != 1 || !strings.Contains(out, "Token de GitHub") || strings.Contains(out, tok) {
		t.Fatalf("esperaba hallazgo enmascarado y salida 1 (%d):\n%s", code, out)
	}
	if code, _, _ := runCLI("scan", root, "--fail-on", "critica", "--min-score", "99"); code != 0 {
		t.Fatalf("--min-score debería ocultarlo, salió %d", code)
	}
	bl := filepath.Join(root, "bl.json")
	if code, _, e := runCLI("baseline", root, "--baseline", bl); code != 0 {
		t.Fatal(e)
	}
	if code, out, _ := runCLI("scan", root, "--baseline", bl, "--format", "json"); code != 0 {
		t.Fatalf("con línea base debería salir 0, salió %d: %s", code, out)
	} else {
		var doc struct {
			Summary  struct{ Baselined int } `json:"summary"`
			Findings []any                   `json:"findings"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Summary.Baselined != 1 || len(doc.Findings) != 0 {
			t.Fatalf("JSON inesperado: %s", out)
		}
	}
}

func TestBadArgs(t *testing.T) {
	for _, args := range [][]string{{}, {"nada"}, {"scan", "--format", "xml"}, {"scan", "--fail-on", "x"}} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%v debería salir con 2, salió %d", args, code)
		}
	}
}
