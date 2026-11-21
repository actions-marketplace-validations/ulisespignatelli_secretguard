package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulisespignatelli/secretguard/internal/remote"
	. "github.com/ulisespignatelli/secretguard/internal/testutil"
)

// fakeRepo crea un repo local con un secreto que entro y luego se borro.
func fakeRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git no está instalado")
	}
	dir := t.TempDir()
	g := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	g("init", "-q")
	_ = os.WriteFile(filepath.Join(dir, "deploy.sh"), []byte("T="+J("gh", "p_", Rand(36, Alnum, 40))+"\n"), 0o600)
	g("add", ".")
	g("commit", "-qm", "a")
	_ = os.WriteFile(filepath.Join(dir, "deploy.sh"), []byte("T=${TOKEN}\n"), 0o600)
	g("commit", "-qam", "b")
	return dir
}

func TestGithubCommandWithFakeClone(t *testing.T) {
	src := fakeRepo(t)
	old := cloneFunc
	defer func() { cloneFunc = old }()
	cloneFunc = func(_ context.Context, r remote.Repo, _ string) (string, func(), error) {
		if r.FullName() != "acme/app" {
			t.Fatalf("repo inesperado %s", r.FullName())
		}
		return src, func() {}, nil
	}
	code, out, _ := runCLI("scan", "https://github.com/acme/app", "--format", "json")
	if code != 1 {
		t.Fatalf("esperaba hallazgos (1), salió %d: %s", code, out)
	}
	var doc struct {
		Findings []struct {
			Repo, URL   string
			HistoryOnly bool `json:"history_only"`
			Reasons     []string
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Findings) != 1 {
		t.Fatalf("%v %s", err, out)
	}
	f := doc.Findings[0]
	if f.Repo != "acme/app" || !f.HistoryOnly || !strings.HasPrefix(f.URL, "https://github.com/acme/app/blob/") ||
		!strings.Contains(strings.Join(f.Reasons, ";"), "público") {
		t.Fatalf("hallazgo remoto inesperado: %+v", f)
	}
}

func TestGithubBadTarget(t *testing.T) {
	if code, _, _ := runCLI("github", "no es un repo"); code != 2 {
		t.Fatal("debería rechazar un destino inválido")
	}
	if code, _, _ := runCLI("github"); code != 2 {
		t.Fatal("sin destino debería salir con 2")
	}
}
