// Package rules contiene los tipos de secreto que detecta secretguard.
//
// Los patrones se escribieron a partir de los formatos que cada proveedor documenta publicamente.
// Cada regla trae palabras clave (filtro rapido antes de la expresion regular), una entropia minima
// opcional para descartar textos de ejemplo y los pasos para revocar el secreto si se filtro.
package rules

import (
	"regexp"

	"github.com/ulisespignatelli/secretguard/internal/finding"
)

// Rule describe un tipo de secreto.
type Rule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp // si tiene un grupo, el secreto es el grupo 1
	Keywords    []string       // en minusculas; la linea debe contener al menos una
	Severity    finding.Severity
	MinEntropy  float64 // 0 = sin control de entropia
	Remediation string
}

var re = regexp.MustCompile

// All devuelve las reglas incluidas. Se ordenan de mas especifica a mas generica: cuando dos reglas
// encuentran el mismo texto, gana la primera.
func All() []Rule {
	return []Rule{
		{ID: "private-key", Name: "Clave privada (PEM/OpenSSH/PGP)",
			Pattern:  re(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
			Keywords: []string{"private key"}, Severity: finding.Critical,
			Remediation: "Generá un par de claves nuevo, reemplazá la clave pública donde se use (servidores, certificados, deploy keys) y revocá la anterior."},
		{ID: "aws-access-key-id", Name: "AWS Access Key ID",
			Pattern:  re(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`),
			Keywords: []string{"akia", "asia", "abia", "acca"}, Severity: finding.Critical, MinEntropy: 3.0,
			Remediation: "En AWS IAM desactivá y borrá la clave de acceso, creá una nueva y revisá CloudTrail por uso indebido."},
		{ID: "aws-secret-access-key", Name: "AWS Secret Access Key",
			Pattern:  re(`(?i)aws.{0,20}(?:secret|private).{0,20}['"=:\s]+([A-Za-z0-9/+=]{40})\b`),
			Keywords: []string{"aws"}, Severity: finding.Critical, MinEntropy: 4.0,
			Remediation: "En AWS IAM desactivá la clave de acceso asociada, creá una nueva y revisá CloudTrail."},
		{ID: "github-token", Name: "Token de GitHub",
			Pattern:  re(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`),
			Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, Severity: finding.Critical,
			Remediation: "Revocalo en GitHub > Settings > Developer settings > Tokens y revisá el log de seguridad de la cuenta."},
		{ID: "gitlab-token", Name: "Token de GitLab",
			Pattern:  re(`\b(glpat-[A-Za-z0-9_-]{20,})\b`),
			Keywords: []string{"glpat-"}, Severity: finding.Critical,
			Remediation: "Revocalo en GitLab > Preferences > Access Tokens."},
		{ID: "anthropic-api-key", Name: "Clave de API de Anthropic",
			Pattern:  re(`\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})`),
			Keywords: []string{"sk-ant-"}, Severity: finding.High,
			Remediation: "Desactivala en console.anthropic.com > API Keys y creá una nueva."},
		{ID: "openai-api-key", Name: "Clave de API de OpenAI",
			Pattern:  re(`\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})`),
			Keywords: []string{"sk-proj-", "sk-svcacct-", "sk-admin-"}, Severity: finding.High,
			Remediation: "Revocala en platform.openai.com > API keys."},
		{ID: "stripe-secret-key", Name: "Clave secreta de Stripe (producción)",
			Pattern:  re(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b`),
			Keywords: []string{"sk_live_", "rk_live_"}, Severity: finding.Critical,
			Remediation: "Rotala en el panel de Stripe > Developers > API keys y revisá los eventos recientes."},
		{ID: "mercadopago-access-token", Name: "Access token de Mercado Pago (producción)",
			Pattern:  re(`\b(APP_USR-\d{10,20}-\d{6}-[a-f0-9]{32}-\d{6,12})\b`),
			Keywords: []string{"app_usr-"}, Severity: finding.Critical,
			Remediation: "Renová las credenciales de producción en Mercado Pago > Tus integraciones > Credenciales."},
		{ID: "google-api-key", Name: "Clave de API de Google",
			Pattern:  re(`\b(AIza[0-9A-Za-z_-]{35})\b`),
			Keywords: []string{"aiza"}, Severity: finding.High,
			Remediation: "Regenerala en Google Cloud Console > APIs y servicios > Credenciales y restringila por API y origen."},
		{ID: "slack-token", Name: "Token de Slack",
			Pattern:  re(`\b(xox[abposr]-[A-Za-z0-9-]{10,})\b`),
			Keywords: []string{"xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"}, Severity: finding.High,
			Remediation: "Revocalo desde la configuración de la app en api.slack.com y generá uno nuevo."},
		{ID: "slack-webhook", Name: "Webhook de Slack",
			Pattern:  re(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`),
			Keywords: []string{"hooks.slack.com"}, Severity: finding.Medium,
			Remediation: "Eliminá el webhook en la configuración de la app de Slack y creá otro."},
		{ID: "discord-webhook", Name: "Webhook de Discord",
			Pattern:  re(`(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{60,})`),
			Keywords: []string{"discord"}, Severity: finding.Medium,
			Remediation: "Borrá el webhook desde Configuración del canal > Integraciones."},
		{ID: "telegram-bot-token", Name: "Token de bot de Telegram",
			Pattern:  re(`\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b`),
			Keywords: []string{":aa"}, Severity: finding.High,
			Remediation: "Pedile a @BotFather un token nuevo con /revoke."},
		{ID: "sendgrid-api-key", Name: "Clave de API de SendGrid",
			Pattern:  re(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`),
			Keywords: []string{"sg."}, Severity: finding.High,
			Remediation: "Borrala en SendGrid > Settings > API Keys."},
		{ID: "npm-token", Name: "Token de npm",
			Pattern:  re(`\b(npm_[A-Za-z0-9]{36})\b`),
			Keywords: []string{"npm_"}, Severity: finding.High,
			Remediation: "Revocalo con `npm token revoke` o desde npmjs.com > Access Tokens."},
		{ID: "pypi-token", Name: "Token de PyPI",
			Pattern:  re(`\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})`),
			Keywords: []string{"pypi-ageichlwas5vcmc"}, Severity: finding.High,
			Remediation: "Borralo en pypi.org > Account settings > API tokens."},
		{ID: "azure-storage-key", Name: "Cadena de conexión de Azure Storage",
			Pattern:  re(`(?i)AccountKey=([A-Za-z0-9+/]{86}==)`),
			Keywords: []string{"accountkey="}, Severity: finding.Critical,
			Remediation: "Rotá la clave de la cuenta de almacenamiento en el portal de Azure (Claves de acceso)."},
		{ID: "database-url", Name: "URL de base de datos con contraseña",
			Pattern:  re(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^:\s/'"@]+:([^@\s/'"]{4,})@[^\s'"]+`),
			Keywords: []string{"://"}, Severity: finding.High, MinEntropy: 2.5,
			Remediation: "Cambiá la contraseña del usuario de la base y pasala por una variable de entorno o un gestor de secretos."},
		{ID: "jwt", Name: "JSON Web Token",
			Pattern:  re(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
			Keywords: []string{"eyj"}, Severity: finding.Low,
			Remediation: "Si es un token real y vigente, invalidalo en el emisor (o rotá la clave de firma) y no lo guardes en el código."},
		{ID: "generic-secret", Name: "Secreto genérico asignado en el código",
			Pattern:  re(`(?i)\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|contrase(?:ñ|n)a|clave)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']`),
			Keywords: []string{"pass", "pwd", "secret", "key", "token", "contrase", "clave"}, Severity: finding.Medium, MinEntropy: 3.5,
			Remediation: "Sacalo del código: usá variables de entorno o un gestor de secretos, y cambiá el valor si alguna vez se subió."},
	}
}
