// Package finding define el resultado de un escaneo. El secreto nunca se guarda completo.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
)

// Severity ordena la gravedad de un tipo de secreto.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "crítica"
	case High:
		return "alta"
	case Medium:
		return "media"
	default:
		return "baja"
	}
}

// ParseSeverity acepta los nombres en castellano o en ingles.
func ParseSeverity(v string) (Severity, bool) {
	switch v {
	case "critica", "crítica", "critical":
		return Critical, true
	case "alta", "high":
		return High, true
	case "media", "medium":
		return Medium, true
	case "baja", "low":
		return Low, true
	}
	return 0, false
}

// Finding es un posible secreto encontrado.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Score       int      `json:"score"`   // 0-100: riesgo real (tipo + contexto)
	Reasons     []string `json:"reasons"` // por que tiene ese puntaje
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Redacted    string   `json:"secret_redacted"`
	Entropy     float64  `json:"entropy"`
	Commit      string   `json:"commit,omitempty"`
	CommitDate  string   `json:"commit_date,omitempty"`
	HistoryOnly bool     `json:"history_only,omitempty"` // ya no esta en el codigo actual
	Fingerprint string   `json:"fingerprint"`
	Remediation string   `json:"remediation"`
}

// Fingerprint identifica un hallazgo sin guardar el secreto: hash de regla + archivo + hash del secreto.
// No incluye la linea, asi un hallazgo aceptado no "reaparece" cuando el archivo cambia de lugar.
func Fingerprint(ruleID, file, secret string) string {
	s := sha256.Sum256([]byte(secret))
	h := sha256.Sum256([]byte(ruleID + "\x00" + file + "\x00" + hex.EncodeToString(s[:])))
	return hex.EncodeToString(h[:])[:24]
}

// Redact deja ver solo el principio del secreto, lo justo para reconocerlo.
func Redact(secret string) string {
	r := []rune(secret)
	switch {
	case len(r) <= 8:
		return "****"
	case len(r) <= 20:
		return string(r[:3]) + "…****"
	default:
		return string(r[:6]) + "…****"
	}
}
