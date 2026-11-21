// Package detect busca secretos en texto y les asigna un puntaje de riesgo.
package detect

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ulisespignatelli/secretguard/internal/finding"
	"github.com/ulisespignatelli/secretguard/internal/rules"
)

// AllowMarker en la misma linea marca un falso positivo aceptado a proposito.
const AllowMarker = "secretguard:allow"

// MaxLineLen evita perder tiempo en lineas gigantes (archivos minificados).
const MaxLineLen = 4096

// Detector aplica las reglas a un texto.
type Detector struct {
	Rules []rules.Rule
}

// New crea un detector con las reglas indicadas (o todas si no se indica ninguna).
func New(r []rules.Rule) *Detector {
	if len(r) == 0 {
		r = rules.All()
	}
	return &Detector{Rules: r}
}

type span struct{ start, end int }

// Scan revisa un contenido linea por linea. path solo se usa para el informe y el puntaje.
func (d *Detector) Scan(content []byte, path string) []finding.Finding {
	var out []finding.Finding
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if len(line) > MaxLineLen || strings.Contains(line, AllowMarker) {
			continue
		}
		out = append(out, d.ScanLine(line, path, lineNo)...)
	}
	return out
}

// ScanLine revisa una sola linea (lo usa tambien el escaneo de diffs de git).
func (d *Detector) ScanLine(line, path string, lineNo int) []finding.Finding {
	if strings.Contains(line, AllowMarker) {
		return nil
	}
	low := strings.ToLower(line)
	var out []finding.Finding
	var taken []span
	for _, r := range d.Rules {
		if !hasKeyword(low, r.Keywords) {
			continue
		}
		for _, m := range r.Pattern.FindAllStringSubmatchIndex(line, -1) {
			s, e := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 {
				s, e = m[2], m[3]
			}
			if overlaps(taken, s, e) {
				continue
			}
			secret := line[s:e]
			ent := Entropy(secret)
			if r.ID == "generic-secret" && notASecret(line, m[0], secret) {
				continue
			}
			if r.ID == "jwt" && IsExampleJWT(secret) {
				continue
			}
			if r.ID != "private-key" {
				if r.MinEntropy > 0 && ent < r.MinEntropy {
					continue
				}
				if IsPlaceholder(secret) {
					continue
				}
			}
			taken = append(taken, span{m[0], m[1]})
			out = append(out, finding.Finding{
				RuleID: r.ID, RuleName: r.Name, Severity: r.Severity, SeverityStr: r.Severity.String(),
				File: path, Line: lineNo, Column: s + 1, Redacted: finding.Redact(secret), Entropy: ent,
				Fingerprint: finding.Fingerprint(r.ID, path, secret), Remediation: r.Remediation,
			})
		}
	}
	return out
}

// passwdLine reconoce el formato de /etc/passwd o /etc/shadow ("root:x:0:0:..."), que no es un secreto.
var passwdLine = regexp.MustCompile(`^[a-z_][a-z0-9_-]*:[x*!]:\d+:\d+:`)

// notASecret descarta falsos positivos tipicos de la regla generica:
//   - la "clave" es parte de una ruta ("/etc/passwd": "...", config.password_file)
//   - el valor es contenido de /etc/passwd en un fixture de pruebas
func notASecret(line string, start int, value string) bool {
	if start > 0 && strings.ContainsRune("/\\.", rune(line[start-1])) {
		return true
	}
	return passwdLine.MatchString(value)
}

// exampleJWTSignatures son firmas de tokens de ejemplo muy difundidos (jwt.io, documentacion de RFC 7519).
var exampleJWTSignatures = []string{
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", // jwt.io, HS256 "your-256-bit-secret"
	"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", // RFC 7519
}

// IsExampleJWT reconoce tokens de ejemplo publicos, que aparecen en documentacion y en herramientas de prueba.
func IsExampleJWT(tok string) bool {
	for _, s := range exampleJWTSignatures {
		if strings.HasSuffix(tok, s) {
			return true
		}
	}
	return false
}

func hasKeyword(low string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	for _, k := range kws {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

func overlaps(spans []span, s, e int) bool {
	for _, x := range spans {
		if s < x.end && e > x.start {
			return true
		}
	}
	return false
}

// testHints son rutas donde un "secreto" suele ser un dato de prueba.
var testHints = []string{"test", "spec", "fixture", "mock", "example", "sample", "demo", "docs/", "testdata"}

// configExt son archivos donde un secreto real es mas probable (y mas grave).
var configNames = []string{".env", "config", "settings", "secrets", "credentials", "docker-compose", ".tfvars", ".npmrc",
	".pypirc", ".netrc", "application.properties", "application.yml"}

// Score calcula el riesgo real (0-100) segun el tipo de secreto y donde aparece, y explica por que.
func Score(f *finding.Finding) {
	base := map[finding.Severity]int{finding.Critical: 70, finding.High: 55, finding.Medium: 40, finding.Low: 20}[f.Severity]
	score := base
	reasons := []string{"tipo " + f.RuleName + " (gravedad " + f.Severity.String() + ")"}
	p := strings.ToLower(filepath.ToSlash(f.File))
	if f.HistoryOnly {
		score -= 10
		reasons = append(reasons, "ya no está en el código actual, pero sigue en el historial de git")
	} else {
		score += 15
		reasons = append(reasons, "está en el código actual")
	}
	for _, h := range testHints {
		if strings.Contains(p, h) {
			score -= 30
			reasons = append(reasons, "la ruta parece de pruebas o ejemplos ("+h+")")
			break
		}
	}
	for _, c := range configNames {
		if strings.Contains(filepath.Base(p), c) {
			score += 10
			reasons = append(reasons, "archivo de configuración o credenciales")
			break
		}
	}
	if f.RuleID == "generic-secret" && f.Entropy >= 4.5 {
		score += 5
		reasons = append(reasons, "valor con aspecto aleatorio (entropía alta)")
	}
	f.Score = max(0, min(100, score))
	f.Reasons = reasons
}
