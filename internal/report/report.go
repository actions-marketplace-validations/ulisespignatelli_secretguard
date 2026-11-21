// Package report escribe los hallazgos en texto legible, JSON o SARIF 2.1.0 (GitHub code scanning).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ulisespignatelli/secretguard/internal/finding"
	"github.com/ulisespignatelli/secretguard/internal/rules"
)

// Summary resume un escaneo.
type Summary struct {
	Target    string `json:"target"`
	Files     int    `json:"files_scanned"`
	History   bool   `json:"history"`
	Staged    bool   `json:"staged"`
	Baselined int    `json:"baselined"`
	Repos     int    `json:"repos,omitempty"`
	Version   string `json:"version"`
}

// Text escribe un informe para la terminal, del mas riesgoso al menos.
func Text(w io.Writer, fs []finding.Finding, s Summary, color bool) {
	c := func(code, t string) string {
		if !color {
			return t
		}
		return "\x1b[" + code + "m" + t + "\x1b[0m"
	}
	sevColor := map[finding.Severity]string{finding.Critical: "1;31", finding.High: "31", finding.Medium: "33", finding.Low: "36"}
	what := "archivos"
	if s.Staged {
		what = "cambios preparados"
	}
	fmt.Fprintf(w, "%s %s · %d %s revisados", c("1", "secretguard"), s.Version, s.Files, what)
	if s.Repos > 0 {
		fmt.Fprintf(w, " · %d repo(s) de GitHub (%s)", s.Repos, s.Target)
	}
	if s.History {
		fmt.Fprint(w, " · con historial de git")
	}
	fmt.Fprintln(w)
	if len(fs) == 0 {
		fmt.Fprintln(w, c("32", "✔ No se encontraron secretos."))
		if s.Baselined > 0 {
			fmt.Fprintf(w, "  (%d hallazgo(s) aceptado(s) en la línea base)\n", s.Baselined)
		}
		return
	}
	for i, f := range fs {
		loc := fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Column)
		label := map[finding.Severity]string{finding.Critical: "CRÍTICA", finding.High: "ALTA   ", finding.Medium: "MEDIA  ", finding.Low: "BAJA   "}[f.Severity]
		fmt.Fprintf(w, "\n%s %s  %s\n", c(sevColor[f.Severity], fmt.Sprintf("[%3d] %s", f.Score, label)), f.RuleName, c("2", fmt.Sprintf("#%d", i+1)))
		if f.Repo != "" {
			loc = f.Repo + " · " + loc
		}
		fmt.Fprintf(w, "      lugar:   %s\n", loc)
		if f.URL != "" {
			fmt.Fprintf(w, "      ver:     %s\n", f.URL)
		}
		fmt.Fprintf(w, "      secreto: %s\n", f.Redacted)
		if f.Commit != "" {
			state := "introducido en el commit"
			if f.HistoryOnly {
				state = "solo en el historial, commit"
			}
			fmt.Fprintf(w, "      git:     %s %s (%s)\n", state, f.Commit, f.CommitDate)
		}
		fmt.Fprintf(w, "      por qué: %s\n", strings.Join(f.Reasons, "; "))
		fmt.Fprintf(w, "      qué hacer: %s\n", f.Remediation)
	}
	count := map[finding.Severity]int{}
	for _, f := range fs {
		count[f.Severity]++
	}
	fmt.Fprintf(w, "\n%s %d hallazgo(s): %d crítico(s), %d alto(s), %d medio(s), %d bajo(s)",
		c("1;31", "✖"), len(fs), count[finding.Critical], count[finding.High], count[finding.Medium], count[finding.Low])
	if s.Baselined > 0 {
		fmt.Fprintf(w, " · %d aceptado(s) en la línea base", s.Baselined)
	}
	fmt.Fprintln(w, ".\n  Un secreto subido a git queda en el historial: borrarlo del archivo no alcanza, hay que rotarlo.")
}

// JSON escribe el resultado completo.
func JSON(w io.Writer, fs []finding.Finding, s Summary) error {
	if fs == nil {
		fs = []finding.Finding{}
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(map[string]any{"summary": s, "findings": fs})
}

// SARIF escribe un informe SARIF 2.1.0 para la pestaña Security de GitHub.
func SARIF(w io.Writer, fs []finding.Finding, s Summary) error {
	level := map[finding.Severity]string{finding.Critical: "error", finding.High: "error", finding.Medium: "warning", finding.Low: "note"}
	secSev := map[finding.Severity]string{finding.Critical: "9.5", finding.High: "8.0", finding.Medium: "5.5", finding.Low: "3.0"}
	var ruleDefs []map[string]any
	for _, r := range rules.All() {
		ruleDefs = append(ruleDefs, map[string]any{
			"id": r.ID, "name": r.ID, "shortDescription": map[string]string{"text": r.Name},
			"help":       map[string]string{"text": r.Remediation},
			"properties": map[string]any{"security-severity": secSev[r.Severity], "tags": []string{"security", "secret"}},
		})
	}
	results := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		msg := fmt.Sprintf("%s (%s). Riesgo %d/100: %s. %s", f.RuleName, f.Redacted, f.Score, strings.Join(f.Reasons, "; "), f.Remediation)
		results = append(results, map[string]any{
			"ruleId": f.RuleID, "level": level[f.Severity], "message": map[string]string{"text": msg},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": sarifURI(f)},
				"region":           map[string]int{"startLine": max(1, f.Line), "startColumn": max(1, f.Column)},
			}}},
			"partialFingerprints": map[string]string{"secretguard/v1": f.Fingerprint},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "secretguard", "version": s.Version, "informationUri": "https://github.com/ulisespignatelli/secretguard",
				"rules": ruleDefs}},
			"results": results,
		}},
	}
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(doc)
}

func sarifURI(f finding.Finding) string {
	if f.Repo != "" {
		return f.Repo + "/" + f.File
	}
	return f.File
}
