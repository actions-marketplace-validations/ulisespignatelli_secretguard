package detect

import (
	"math"
	"strings"
)

// Entropy calcula la entropia de Shannon en bits por caracter. Un token aleatorio de base64 ronda 5-6;
// una palabra o "changeme" queda muy por debajo.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return math.Round(h*100) / 100
}

// placeholders son valores que aparecen en ejemplos y documentacion, no secretos reales.
var placeholders = []string{
	"example", "sample", "dummy", "changeme", "change_me", "placeholder", "your_", "your-", "<", "${", "{{",
	"xxxx", "****", "redacted", "insert", "replace", "todo", "fixme", "test1234", "password123", "secret123",
	"process.env", "os.environ", "getenv", "env(", "ejemplo", "tu_clave", "tu-clave", "aqui", "acá",
}

// commonValues son contrasenas "de manual" que aparecen en documentacion y ejemplos locales.
var commonValues = map[string]bool{"password": true, "passwd": true, "pass": true, "secret": true, "admin": true,
	"root": true, "postgres": true, "mysql": true, "user": true, "test": true, "guest": true, "qwerty": true,
	"letmein": true, "contraseña": true, "clave": true}

// IsPlaceholder detecta valores de ejemplo y referencias a variables de entorno.
func IsPlaceholder(v string) bool {
	low := strings.ToLower(v)
	if commonValues[low] {
		return true
	}
	for _, p := range placeholders {
		if strings.Contains(low, p) {
			return true
		}
	}
	// "aaaaaaaa", "12345678": repeticiones o secuencias triviales
	if len(strings.Trim(low, string(low[0]))) == 0 {
		return true
	}
	return strings.Contains("0123456789abcdefghijklmnopqrstuvwxyz", low)
}
