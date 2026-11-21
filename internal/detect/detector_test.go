package detect

import (
	"strings"
	"testing"

	"github.com/ulisespignatelli/secretguard/internal/finding"
	. "github.com/ulisespignatelli/secretguard/internal/testutil"
)

func positives() map[string]string {
	return map[string]string{
		"private-key":              J("-----BEGIN RSA ", "PRIVATE KEY-----"),
		"aws-access-key-id":        `key = "` + J("AK", "IA", Rand(16, Upper, 1)) + `"`,
		"aws-secret-access-key":    `aws_secret_access_key = ` + Rand(40, B64, 2),
		"github-token":             `token: ` + J("gh", "p_", Rand(36, Alnum, 3)),
		"gitlab-token":             J("gl", "pat-", Rand(20, URL, 4)),
		"anthropic-api-key":        J("sk-", "ant-", "api03-", Rand(90, URL, 5)),
		"openai-api-key":           J("sk-", "proj-", Rand(48, URL, 6)),
		"stripe-secret-key":        J("sk", "_live_", Rand(28, Alnum, 7)),
		"mercadopago-access-token": J("APP", "_USR-", "1234567890123456", "-112233-", Rand(32, Hex, 8), "-123456789"),
		"google-api-key":           J("AI", "za", Rand(35, URL, 9)),
		"slack-token":              J("xo", "xb-", "1234567890-", Rand(24, Alnum, 10)),
		"slack-webhook":            J("https://hooks.slack", ".com/services/T", "0ABCDEF/B", "0ABCDEF/", Rand(24, Alnum, 11)),
		"discord-webhook":          J("https://discord", ".com/api/webhooks/", "123456789012345678/", Rand(68, URL, 12)),
		"telegram-bot-token":       J("1234567890", ":AA", Rand(33, URL, 13)),
		"sendgrid-api-key":         J("SG", ".", Rand(22, URL, 14), ".", Rand(43, URL, 15)),
		"npm-token":                J("np", "m_", Rand(36, Alnum, 16)),
		"pypi-token":               J("py", "pi-AgEIcHlwaS5vcmc", Rand(60, URL, 17)),
		"azure-storage-key":        J("DefaultEndpointsProtocol=https;AccountName=x;Account", "Key=", Rand(86, B64, 18), "=="),
		"database-url":             J("postgres://app:", Rand(16, Alnum, 19), "@db.internal:5432/prod"),
		"jwt":                      J("ey", "J", Rand(20, URL, 20), ".ey", "J", Rand(30, URL, 21), ".", Rand(43, URL, 22)),
		"generic-secret":           `password = "` + Rand(20, Alnum, 23) + `"`,
	}
}

func TestEveryRuleDetects(t *testing.T) {
	d := New(nil)
	for id, line := range positives() {
		fs := d.ScanLine(line, "app/main.go", 1)
		if len(fs) != 1 || fs[0].RuleID != id {
			got := []string{}
			for _, f := range fs {
				got = append(got, f.RuleID)
			}
			t.Errorf("%s: esperaba 1 hallazgo de %s, obtuve %v", id, id, got)
		}
	}
}

func TestNegatives(t *testing.T) {
	d := New(nil)
	for _, line := range []string{
		`password = "changeme123"`,
		`api_key = os.environ["API_KEY"]`,
		`token: "${GITHUB_TOKEN}"`,
		`password = "aaaaaaaaaaaa"`,
		`secret = "<tu_clave_aqui>"`,
		J(`AWS key `, "AK", "IAIOSFODNN7", "EXAMPLE"),
		J("postgres://user:", "password", "@localhost/db"),
		`const password = getPassword()`,
		`password = "` + Rand(20, Alnum, 99) + `" // secretguard:allow (dato de prueba)`,
		`    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",`,
		`shadow = "root:*:19000:0:99999:7:::"`,
		J(`const demo = "ey`, `JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ey`, `JzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`,
			`SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`),
	} {
		if fs := d.ScanLine(line, "app.py", 1); len(fs) != 0 {
			t.Errorf("falso positivo en %q: %s", line, fs[0].RuleID)
		}
	}
}

func TestSpecificRuleWinsOverGeneric(t *testing.T) {
	line := `api_key = "` + J("gh", "p_", Rand(36, Alnum, 30)) + `"`
	fs := New(nil).ScanLine(line, "x.go", 1)
	if len(fs) != 1 || fs[0].RuleID != "github-token" {
		t.Fatalf("esperaba solo github-token, obtuve %+v", fs)
	}
}

func TestNeverStoresFullSecret(t *testing.T) {
	tok := J("gh", "p_", Rand(36, Alnum, 31))
	f := New(nil).ScanLine("t="+tok, "x", 1)[0]
	if strings.Contains(f.Redacted, tok[8:]) || !strings.HasSuffix(f.Redacted, "****") {
		t.Fatalf("el secreto no quedó enmascarado: %s", f.Redacted)
	}
}

func TestScanMultiline(t *testing.T) {
	content := "a\nb\n" + positives()["stripe-secret-key"] + "\n"
	fs := New(nil).Scan([]byte(content), "config.js")
	if len(fs) != 1 || fs[0].Line != 3 || fs[0].Column != 1 {
		t.Fatalf("línea/columna incorrecta: %+v", fs)
	}
}

func TestScore(t *testing.T) {
	mk := func(file string, hist bool) finding.Finding {
		f := finding.Finding{RuleID: "aws-access-key-id", RuleName: "AWS", Severity: finding.Critical, File: file, HistoryOnly: hist}
		Score(&f)
		return f
	}
	cfg, code, test, hist := mk(".env", false), mk("src/app.go", false), mk("tests/fixtures/app.go", false), mk("src/app.go", true)
	if !(cfg.Score > code.Score && code.Score > hist.Score && hist.Score > test.Score) {
		t.Fatalf("orden de riesgo inesperado: env=%d código=%d historial=%d test=%d", cfg.Score, code.Score, hist.Score, test.Score)
	}
	if cfg.Score > 100 || test.Score < 0 || len(cfg.Reasons) < 2 {
		t.Fatalf("puntaje fuera de rango o sin motivos: %+v", cfg)
	}
}

func TestEntropyAndPlaceholders(t *testing.T) {
	if Entropy("aaaa") != 0 || Entropy(Rand(40, Alnum, 1)) < 4.5 {
		t.Fatal("entropía inesperada")
	}
	for _, v := range []string{"YOUR_API_KEY", "12345678", "xxxxxxxx", "process.env.TOKEN"} {
		if !IsPlaceholder(v) {
			t.Errorf("%q debería ser un valor de ejemplo", v)
		}
	}
}
