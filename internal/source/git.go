package source

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ulisespignatelli/secretguard/internal/detect"
	"github.com/ulisespignatelli/secretguard/internal/finding"
)

const commitMark = "\x00SG-COMMIT "

// git ejecuta git sin shell y con una configuracion que no depende del repo escaneado.
func git(root string, args ...string) *exec.Cmd {
	base := []string{"-C", root, "-c", "core.quotePath=false", "-c", "diff.noprefix=false", "-c", "color.ui=false"}
	return exec.Command("git", append(base, args...)...) // #nosec G204: argumentos fijos, sin shell
}

// ScanHistory revisa las lineas AGREGADAS en todos los commits de todas las ramas. Si un secreto
// aparece en varios commits, se informa el mas antiguo (el que lo introdujo).
func ScanHistory(root string, det *detect.Detector, exclude []string) ([]finding.Finding, error) {
	cmd := git(root, "log", "-p", "--all", "--unified=0", "--no-ext-diff", "--no-textconv", "--format=%x00SG-COMMIT %H %cI") // git escribe el NUL; no puede ir en el argumento
	return runDiff(cmd, det, exclude, true)
}

// ScanStaged revisa lo que esta en el area de preparacion (para el hook pre-commit). Devuelve tambien
// cuantos archivos cambiados se revisaron.
func ScanStaged(root string, det *detect.Detector, exclude []string) ([]finding.Finding, int, error) {
	files, err := git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR").Output()
	if err != nil {
		return nil, 0, fmt.Errorf("no se pudo leer el área de preparación de git: %w", err)
	}
	n := len(strings.Fields(string(files)))
	cmd := git(root, "diff", "--cached", "--unified=0", "--no-ext-diff", "--no-textconv")
	fs, err := runDiff(cmd, det, exclude, false)
	return fs, n, err
}

func runDiff(cmd *exec.Cmd, det *detect.Detector, exclude []string, oldest bool) ([]finding.Finding, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("no se pudo ejecutar git: %w", err)
	}
	fs := ParseDiff(out, det, exclude)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git falló: %s", strings.TrimSpace(stderr.String()))
	}
	return dedupe(fs, oldest), nil
}

// ParseDiff lee la salida de git log -p / git diff y escanea solo las lineas agregadas.
func ParseDiff(r io.Reader, det *detect.Detector, exclude []string) []finding.Finding {
	var out []finding.Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var commit, date, file string
	newLine := 0
	skip := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, commitMark):
			parts := strings.Fields(strings.TrimPrefix(line, commitMark))
			commit, date, file = "", "", ""
			if len(parts) > 0 {
				commit = parts[0]
			}
			if len(parts) > 1 {
				date = parts[1]
			}
		case strings.HasPrefix(line, "+++ "):
			file = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
			skip = file == "/dev/null" || Excluded(file, exclude) || skipExt[strings.ToLower(extOf(file))]
		case strings.HasPrefix(line, "@@"):
			newLine = hunkStart(line)
		case strings.HasPrefix(line, "+") && !skip && file != "":
			text := line[1:]
			if len(text) <= detect.MaxLineLen {
				for _, f := range det.ScanLine(text, file, newLine) {
					if commit != "" {
						f.Commit, f.CommitDate = commit[:min(12, len(commit))], date
					}
					out = append(out, f)
				}
			}
			newLine++
		}
	}
	return out
}

func extOf(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && !strings.ContainsRune(p[i:], '/') {
		return p[i:]
	}
	return ""
}

// hunkStart lee "@@ -a,b +c,d @@" y devuelve c (primera linea nueva).
func hunkStart(h string) int {
	i := strings.Index(h, "+")
	if i < 0 {
		return 1
	}
	rest := h[i+1:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 1
	}
	return n
}

func dedupe(fs []finding.Finding, keepLast bool) []finding.Finding {
	idx := map[string]int{}
	var out []finding.Finding
	for _, f := range fs {
		if i, ok := idx[f.Fingerprint]; ok {
			if keepLast {
				out[i] = f // git log va del mas nuevo al mas viejo: el ultimo es el que lo introdujo
			}
			continue
		}
		idx[f.Fingerprint] = len(out)
		out = append(out, f)
	}
	return out
}

// MergeHistory combina el escaneo del codigo actual con el del historial: lo que ya esta en el codigo
// actual no se repite; lo que solo esta en el historial se marca como tal.
func MergeHistory(current, history []finding.Finding) []finding.Finding {
	hist := map[string]finding.Finding{}
	for _, f := range history {
		hist[f.Fingerprint] = f
	}
	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(current)+len(history))
	for _, f := range current {
		seen[f.Fingerprint] = true
		if h, ok := hist[f.Fingerprint]; ok { // en que commit entro el secreto
			f.Commit, f.CommitDate = h.Commit, h.CommitDate
		}
		out = append(out, f)
	}
	for _, f := range history {
		if seen[f.Fingerprint] {
			continue
		}
		f.HistoryOnly = true
		out = append(out, f)
	}
	return out
}
