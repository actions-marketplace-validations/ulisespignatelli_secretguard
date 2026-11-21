// secretguard busca secretos (claves de API, tokens, contrasenas, claves privadas) en archivos y en el
// historial de git, los ordena por riesgo real y explica como revocarlos. Solo usa la biblioteca estandar.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ulisespignatelli/secretguard/internal/baseline"
	"github.com/ulisespignatelli/secretguard/internal/detect"
	"github.com/ulisespignatelli/secretguard/internal/finding"
	"github.com/ulisespignatelli/secretguard/internal/report"
	"github.com/ulisespignatelli/secretguard/internal/rules"
	"github.com/ulisespignatelli/secretguard/internal/source"
)

// version se completa al compilar: -ldflags "-X main.version=v0.1.0"
var version = "dev"

const usage = `secretguard: encuentra secretos en tu código antes que otros.

Uso:
  secretguard scan [ruta]        Escanea archivos (por defecto, la carpeta actual)
  secretguard baseline [ruta]    Acepta los hallazgos actuales en un archivo de línea base
  secretguard hook install       Instala el hook pre-commit en el repo actual
  secretguard rules              Lista los tipos de secreto que detecta
  secretguard version

Opciones de scan y baseline:
  --history            también revisa todo el historial de git (todas las ramas)
  --staged             solo los cambios preparados para commit (lo usa el hook)
  --format FORMATO     text (por defecto), json o sarif
  --output ARCHIVO     escribe el informe en un archivo
  --baseline ARCHIVO   omite los hallazgos aceptados (por defecto .secretguard-baseline.json si existe)
  --fail-on GRAVEDAD   sale con código 1 desde esta gravedad: baja, media, alta, critica (por defecto baja)
  --min-score N        oculta hallazgos con riesgo menor a N (0-100)
  --exclude PATRONES   globs separados por coma, p. ej. "docs/**,*.min.js"
  --workers N          archivos en paralelo (por defecto 8)

Códigos de salida: 0 sin hallazgos, 1 con hallazgos, 2 error.
`

const defaultBaseline = ".secretguard-baseline.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return scan(args[1:], stdout, stderr, false)
	case "baseline":
		return scan(args[1:], stdout, stderr, true)
	case "hook":
		return hook(args[1:], stdout, stderr)
	case "rules":
		for _, r := range rules.All() {
			fmt.Fprintf(stdout, "%-26s %-8s %s\n", r.ID, r.Severity, r.Name)
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "secretguard", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "comando desconocido: %q\n\n%s", args[0], usage)
	return 2
}

type scanOpts struct {
	history, staged          bool
	format, output, baseline string
	failOn                   string
	minScore, workers        int
	exclude                  string
}

// parseInterspersed permite opciones antes o despues de la ruta ("scan . --history" o "scan --history .").
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func scan(args []string, stdout, stderr io.Writer, makeBaseline bool) int {
	var o scanOpts
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&o.history, "history", false, "")
	fs.BoolVar(&o.staged, "staged", false, "")
	fs.StringVar(&o.format, "format", "text", "")
	fs.StringVar(&o.output, "output", "", "")
	fs.StringVar(&o.baseline, "baseline", "", "")
	fs.StringVar(&o.failOn, "fail-on", "baja", "")
	fs.IntVar(&o.minScore, "min-score", 0, "")
	fs.IntVar(&o.workers, "workers", 8, "")
	fs.StringVar(&o.exclude, "exclude", "", "")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	root := "."
	if len(pos) > 0 {
		root = pos[0]
	}
	failOn, ok := finding.ParseSeverity(o.failOn)
	if !ok {
		fmt.Fprintf(stderr, "gravedad inválida en --fail-on: %q\n", o.failOn)
		return 2
	}
	if o.format != "text" && o.format != "json" && o.format != "sarif" {
		fmt.Fprintf(stderr, "formato inválido: %q (text, json o sarif)\n", o.format)
		return 2
	}
	exclude := splitList(o.exclude)
	det := detect.New(nil)
	sum := report.Summary{Target: root, History: o.history, Staged: o.staged, Version: version}

	var found []finding.Finding
	switch {
	case o.staged && !isGitRepo(root):
		err = errors.New("--staged necesita un repositorio de git")
	case o.staged:
		found, sum.Files, err = source.ScanStaged(gitTop(root), det, exclude)
	default:
		found, sum.Files, err = source.ScanFiles(root, det, source.Options{Exclude: exclude, Workers: o.workers})
		if err == nil && o.history && !isGitRepo(root) {
			fmt.Fprintln(stderr, "aviso: no es un repositorio de git; se escanean solo los archivos actuales")
			sum.History = false
		} else if err == nil && o.history {
			var hist []finding.Finding
			gitRoot := root
			if fi, statErr := os.Stat(root); statErr == nil && !fi.IsDir() {
				gitRoot = filepath.Dir(root)
			}
			hist, err = source.ScanHistory(gitRoot, det, exclude)
			found = source.MergeHistory(found, hist)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for i := range found {
		detect.Score(&found[i])
	}

	blPath := o.baseline
	if blPath == "" {
		blPath = filepath.Join(gitTop(root), defaultBaseline)
	}
	if makeBaseline {
		if o.baseline == "" {
			blPath = defaultBaseline
		}
		if err := baseline.FromFindings(found).Save(blPath); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		fmt.Fprintf(stdout, "Línea base guardada en %s con %d hallazgo(s). Revisalos: aceptar no es lo mismo que rotar.\n", blPath, len(found))
		return 0
	}
	bl, err := baseline.Load(blPath)
	if err != nil {
		fmt.Fprintln(stderr, "error leyendo la línea base:", err)
		return 2
	}
	found, sum.Baselined = bl.Filter(found)

	var shown []finding.Finding
	for _, f := range found {
		if f.Score >= o.minScore {
			shown = append(shown, f)
		}
	}
	sort.SliceStable(shown, func(i, j int) bool { return shown[i].Score > shown[j].Score })

	w := stdout
	if o.output != "" {
		file, err := os.OpenFile(o.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		defer file.Close()
		w = file
	}
	switch o.format {
	case "json":
		err = report.JSON(w, shown, sum)
	case "sarif":
		err = report.SARIF(w, shown, sum)
	default:
		report.Text(w, shown, sum, w == stdout && isTerminal(stdout))
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, f := range shown {
		if f.Severity >= failOn {
			return 1
		}
	}
	return 0
}

const hookScript = `#!/bin/sh
# Instalado por secretguard: frena el commit si los cambios preparados contienen secretos.
# Para saltearlo una vez (no recomendado): git commit --no-verify
exec secretguard scan --staged --fail-on media .
`

func hook(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "install" {
		fmt.Fprintln(stderr, "uso: secretguard hook install [ruta-del-repo]")
		return 2
	}
	root := "."
	if len(args) > 1 {
		root = args[1]
	}
	dir := filepath.Join(gitTop(root), ".git", "hooks")
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		fmt.Fprintln(stderr, "error: no parece un repositorio de git (falta .git/hooks)")
		return 2
	}
	path := filepath.Join(dir, "pre-commit")
	if data, err := os.ReadFile(path); err == nil && !strings.Contains(string(data), "secretguard") {
		fmt.Fprintf(stderr, "error: ya existe un hook pre-commit en %s; agregá esta línea a mano:\n  secretguard scan --staged --fail-on media .\n", path)
		return 2
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := os.WriteFile(path, []byte(hookScript), 0o755); err != nil { // #nosec G306: el hook debe ser ejecutable
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(stdout, "Hook instalado en %s. Desde ahora cada commit se revisa antes de guardarse.\n", path)
	return 0
}

// gitTop busca hacia arriba la carpeta que contiene .git (o devuelve la ruta tal cual).
func gitTop(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
		abs = filepath.Dir(abs)
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			return abs
		}
	}
}

func isGitRepo(root string) bool {
	_, err := os.Stat(filepath.Join(gitTop(root), ".git"))
	return err == nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isTerminal(w io.Writer) bool {
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
