package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulisespignatelli/secretguard/internal/detect"
	. "github.com/ulisespignatelli/secretguard/internal/testutil"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stripe(seed int) string { return J("sk", "_live_", Rand(28, Alnum, seed)) }

func TestScanFilesSkipsNoise(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/app.js", "const k = '"+stripe(1)+"'\n")
	write(t, root, "node_modules/lib/index.js", "const k = '"+stripe(2)+"'\n")
	write(t, root, "docs/guide.md", "clave: "+stripe(3)+"\n")
	write(t, root, "image.bin", "\x00\x01"+stripe(4))
	fs, n, err := ScanFiles(root, detect.New(nil), Options{Exclude: []string{"docs/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].File != "src/app.js" || fs[0].Line != 1 {
		t.Fatalf("esperaba solo src/app.js, obtuve %+v", fs)
	}
	if n != 1 { // image.bin se lee pero se descarta como binario; docs/ y node_modules/ ni se abren
		t.Fatalf("archivos revisados: %d", n)
	}
}

func TestScanSingleFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.env", "TOKEN="+J("gh", "p_", Rand(36, Alnum, 5))+"\n")
	fs, _, err := ScanFiles(filepath.Join(root, "a.env"), detect.New(nil), Options{})
	if err != nil || len(fs) != 1 || fs[0].File != "a.env" {
		t.Fatalf("archivo suelto: %v %+v", err, fs)
	}
}

func TestParseDiffLineNumbers(t *testing.T) {
	diff := strings.Join([]string{
		commitMark + "abcdef1234567890 2026-11-20T10:00:00-03:00",
		"diff --git a/cfg.yml b/cfg.yml",
		"--- a/cfg.yml", "+++ b/cfg.yml",
		"@@ -10,0 +11,2 @@",
		"+name: app",
		"+key: " + stripe(6),
		"--- a/old.txt", "+++ /dev/null",
		"@@ -1 +0,0 @@", "-borrado",
	}, "\n")
	fs := ParseDiff(strings.NewReader(diff), detect.New(nil), nil)
	if len(fs) != 1 || fs[0].Line != 12 || fs[0].File != "cfg.yml" || fs[0].Commit != "abcdef123456" {
		t.Fatalf("diff mal interpretado: %+v", fs)
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
		"-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestHistoryFindsRemovedSecrets(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git no está instalado")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	old, current := stripe(7), J("gh", "p_", Rand(36, Alnum, 8))
	write(t, root, "config.js", "const k = '"+old+"'\n")
	gitRun(t, root, "add", ".")
	gitRun(t, root, "commit", "-qm", "primero")
	write(t, root, "config.js", "const k = process.env.KEY\nconst t = '"+current+"'\n")
	gitRun(t, root, "commit", "-qam", "segundo")

	det := detect.New(nil)
	cur, _, err := ScanFiles(root, det, Options{})
	if err != nil {
		t.Fatal(err)
	}
	hist, err := ScanHistory(root, det, nil)
	if err != nil {
		t.Fatal(err)
	}
	all := MergeHistory(cur, hist)
	if len(all) != 2 {
		t.Fatalf("esperaba 2 hallazgos, obtuve %+v", all)
	}
	var onlyHist, inCode int
	for _, f := range all {
		if f.HistoryOnly && f.RuleID == "stripe-secret-key" {
			onlyHist++
		}
		if !f.HistoryOnly && f.RuleID == "github-token" && f.Commit != "" {
			inCode++
		}
	}
	if onlyHist != 1 || inCode != 1 {
		t.Fatalf("clasificación de historial incorrecta: %+v", all)
	}

	// Area de preparacion: solo lo nuevo
	write(t, root, "new.txt", "x = '"+stripe(9)+"'\n")
	gitRun(t, root, "add", "new.txt")
	staged, n, err := ScanStaged(root, det, nil)
	if err != nil || len(staged) != 1 || staged[0].File != "new.txt" || n != 1 {
		t.Fatalf("staged: %v %d %+v", err, n, staged)
	}
}

func TestExcluded(t *testing.T) {
	cases := map[string]bool{"docs/a.md": true, "src/x.min.js": true, "src/x.js": false}
	for p, want := range cases {
		if got := Excluded(p, []string{"docs/**", "*.min.js"}); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}
