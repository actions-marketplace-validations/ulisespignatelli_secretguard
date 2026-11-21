package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ulisespignatelli/secretguard/internal/detect"
	"github.com/ulisespignatelli/secretguard/internal/finding"
	"github.com/ulisespignatelli/secretguard/internal/remote"
	"github.com/ulisespignatelli/secretguard/internal/report"
)

const githubUsage = `secretguard github: escanea repositorios directamente desde GitHub (código actual + historial).

Uso:
  secretguard github duenio/repo
  secretguard github https://github.com/duenio/repo
  secretguard github --user NOMBRE     todos los repos de un usuario
  secretguard github --org NOMBRE      todos los repos de una organización

Opciones (además de --format, --output, --fail-on, --min-score, --exclude y --baseline):
  --no-history       solo el código actual de la rama principal
  --forks            incluir forks (por defecto se omiten)
  --archived=false   omitir repos archivados
  --max-repos N      tope de repositorios (por defecto 50)

Repos privados: definí GITHUB_TOKEN (o GH_TOKEN) con permiso de lectura. El token nunca se pasa por la
línea de comandos ni se guarda en disco. Usalo en tus repos o en los que tengas autorización.
`

// apiFactory permite reemplazar la API en los tests.
var apiFactory = remote.NewAPI

// cloneFunc permite reemplazar el clonado en los tests.
var cloneFunc = remote.Clone

func githubCmd(args []string, stdout, stderr io.Writer) int {
	var o scanOpts
	var user, org string
	var noHistory, forks bool
	archived := true
	maxRepos := 50
	fs := flag.NewFlagSet("github", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, githubUsage) }
	fs.StringVar(&user, "user", "", "")
	fs.StringVar(&org, "org", "", "")
	fs.BoolVar(&noHistory, "no-history", false, "")
	fs.BoolVar(&forks, "forks", false, "")
	fs.BoolVar(&archived, "archived", true, "")
	fs.IntVar(&maxRepos, "max-repos", 50, "")
	fs.StringVar(&o.format, "format", "text", "")
	fs.StringVar(&o.output, "output", "", "")
	fs.StringVar(&o.baseline, "baseline", "", "")
	fs.StringVar(&o.failOn, "fail-on", "baja", "")
	fs.IntVar(&o.minScore, "min-score", 0, "")
	fs.IntVar(&o.workers, "workers", 8, "")
	fs.StringVar(&o.exclude, "exclude", "", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	failOn, ok := finding.ParseSeverity(o.failOn)
	if !ok || (o.format != "text" && o.format != "json" && o.format != "sarif") {
		fmt.Fprintln(stderr, "opciones inválidas: revisá --fail-on y --format")
		return 2
	}
	o.history = !noHistory
	token := remote.Token()
	ctx := context.Background()

	var repos []remote.Repo
	target := ""
	switch {
	case user != "" || org != "":
		kind, owner := "users", user
		if org != "" {
			kind, owner = "orgs", org
		}
		target = owner
		all, err := apiFactory(token).ListRepos(ctx, kind, owner, 0)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		for _, r := range all {
			if (r.Fork && !forks) || (r.Archived && !archived) {
				continue
			}
			repos = append(repos, r)
		}
		if maxRepos > 0 && len(repos) > maxRepos {
			fmt.Fprintf(stderr, "aviso: %d repos; se escanean los %d con actividad más reciente (--max-repos)\n", len(repos), maxRepos)
			repos = repos[:maxRepos]
		}
	case len(pos) == 1:
		r, ok := remote.ParseRepo(pos[0])
		if !ok {
			fmt.Fprintf(stderr, "no reconozco %q como repo de GitHub (usá duenio/repo o la URL)\n", pos[0])
			return 2
		}
		repos, target = []remote.Repo{r}, r.FullName()
	default:
		fmt.Fprint(stderr, githubUsage)
		return 2
	}
	if len(repos) == 0 {
		fmt.Fprintln(stderr, "no hay repositorios para escanear")
		return 0
	}

	sum := report.Summary{Target: target, History: o.history, Version: version, Repos: len(repos)}
	exclude := splitList(o.exclude)
	var found []finding.Finding
	failed := 0
	for i, r := range repos {
		fmt.Fprintf(stderr, "[%d/%d] %s…\n", i+1, len(repos), r.FullName())
		fs, files, err := scanRepo(ctx, r, token, o, exclude, stderr)
		if err != nil {
			failed++
			fmt.Fprintln(stderr, "  error:", err)
			continue
		}
		sum.Files += files
		found = append(found, fs...)
	}
	if failed == len(repos) {
		return 2
	}
	return finish(found, sum, o, failOn, o.baseline, stdout, stderr)
}

func scanRepo(ctx context.Context, r remote.Repo, token string, o scanOpts, exclude []string, stderr io.Writer) ([]finding.Finding, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	dir, cleanup, err := cloneFunc(ctx, r, token)
	if err != nil {
		return nil, 0, err
	}
	defer cleanup()
	fs, files, _, err := collect(dir, o, exclude, stderr)
	if err != nil {
		return nil, 0, err
	}
	for i := range fs {
		f := &fs[i]
		f.Repo = r.FullName()
		ref := "HEAD"
		if f.HistoryOnly && f.Commit != "" {
			ref = f.Commit
		}
		f.URL = r.BlobURL(ref, f.File, f.Line)
		f.Fingerprint = finding.Fingerprint(f.RuleID, r.FullName()+"/"+f.File, f.Fingerprint)
		detect.Score(f)
		if r.Private {
			f.Reasons = append(f.Reasons, "repositorio privado")
		} else {
			f.Score = min(100, f.Score+5)
			f.Reasons = append(f.Reasons, "repositorio público: cualquiera puede verlo")
		}
	}
	return fs, files, nil
}

// looksRemote decide si "scan X" en realidad pide un repo de GitHub.
func looksRemote(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && remote.IsGitHubURL(a) {
			return true
		}
	}
	return false
}
