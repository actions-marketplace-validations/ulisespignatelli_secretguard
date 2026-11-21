// Package remote trae repositorios de GitHub para escanearlos: los clona en una carpeta temporal (con el
// historial completo) y la borra al terminar. Tambien lista los repositorios de un usuario u organizacion.
//
// El token (GITHUB_TOKEN o GH_TOKEN) es opcional: hace falta para repos privados y sube el limite de la API.
// Nunca se pasa por la linea de comandos ni se escribe en disco: viaja como cabecera HTTP de git.
package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Repo identifica un repositorio de GitHub.
type Repo struct {
	Owner, Name string
	Private     bool
	Fork        bool
	Archived    bool
}

// FullName devuelve "duenio/repo".
func (r Repo) FullName() string { return r.Owner + "/" + r.Name }

// CloneURL es la URL HTTPS del repositorio.
func (r Repo) CloneURL() string { return "https://github.com/" + r.FullName() + ".git" }

// BlobURL arma el enlace a una linea en GitHub (ref puede ser HEAD o un commit).
func (r Repo) BlobURL(ref, path string, line int) string {
	return fmt.Sprintf("https://github.com/%s/blob/%s/%s#L%d", r.FullName(), ref, escapePath(path), line)
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

var namePart = `[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})`
var targetRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com/(` + namePart + `)/(` + namePart + `)/?$`)
var shortRe = regexp.MustCompile(`^(` + namePart + `)/(` + namePart + `)$`)

// ParseRepo acepta "https://github.com/duenio/repo", "github.com/duenio/repo" o "duenio/repo".
func ParseRepo(s string) (Repo, bool) {
	s = strings.TrimSpace(s)
	if m := targetRe.FindStringSubmatch(s); m != nil {
		return Repo{Owner: m[1], Name: strings.TrimSuffix(m[2], ".git")}, true
	}
	if m := shortRe.FindStringSubmatch(s); m != nil {
		return Repo{Owner: m[1], Name: m[2]}, true
	}
	return Repo{}, false
}

// IsGitHubURL indica si el argumento es claramente una URL de GitHub (y no una ruta local).
func IsGitHubURL(s string) bool {
	return targetRe.MatchString(strings.TrimSpace(s)) && strings.Contains(s, "github.com")
}

// Token lee el token de las variables de entorno habituales.
func Token() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

// Clone clona el repositorio completo (todas las ramas) en una carpeta temporal. cleanup la borra.
func Clone(ctx context.Context, r Repo, token string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "secretguard-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	noHooks, err := os.MkdirTemp("", "secretguard-nohooks-*")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer os.RemoveAll(noHooks)

	args := []string{
		"-c", "core.hooksPath=" + noHooks, // nunca ejecutar hooks
		"-c", "protocol.file.allow=never", // sin submodulos/rutas locales maliciosas
		"-c", "core.symlinks=false",
	}
	if token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		args = append(args, "-c", "http.https://github.com/.extraheader=AUTHORIZATION: basic "+basic)
	}
	args = append(args, "clone", "--quiet", "--no-recurse-submodules", r.CloneURL(), dir)
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204: sin shell; URL validada por ParseRepo
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		msg := strings.TrimSpace(string(out))
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "****")
		}
		if strings.Contains(msg, "not found") || strings.Contains(msg, "Authentication failed") ||
			strings.Contains(msg, "could not read Username") {
			return "", nil, fmt.Errorf("no se pudo acceder a %s: no existe o es privado (para repos privados definí GITHUB_TOKEN) [%s]", r.FullName(), msg)
		}
		return "", nil, fmt.Errorf("git clone %s falló: %s", r.FullName(), msg)
	}
	return dir, cleanup, nil
}

// API habla con la API REST de GitHub (solo lectura).
type API struct {
	Base   string // https://api.github.com (configurable para tests)
	Token  string
	Client *http.Client
}

// NewAPI crea un cliente con tiempo de espera.
func NewAPI(token string) *API {
	return &API{Base: "https://api.github.com", Token: token, Client: &http.Client{Timeout: 30 * time.Second}}
}

type apiRepo struct {
	Name     string `json:"name"`
	Private  bool   `json:"private"`
	Fork     bool   `json:"fork"`
	Archived bool   `json:"archived"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// ListRepos devuelve los repositorios de un usuario u organizacion (kind = "users" u "orgs").
func (a *API) ListRepos(ctx context.Context, kind, owner string, max int) ([]Repo, error) {
	if !regexp.MustCompile(`^` + namePart + `$`).MatchString(owner) {
		return nil, fmt.Errorf("nombre de usuario u organización inválido: %q", owner)
	}
	next := fmt.Sprintf("%s/%s/%s/repos?per_page=100&sort=pushed", a.Base, kind, url.PathEscape(owner))
	if kind == "users" {
		next += "&type=owner"
	}
	var out []Repo
	for next != "" && (max <= 0 || len(out) < max) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "secretguard")
		if a.Token != "" {
			req.Header.Set("Authorization", "Bearer "+a.Token)
		}
		resp, err := a.Client.Do(req)
		if err != nil {
			return nil, err
		}
		var page []apiRepo
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return nil, fmt.Errorf("no existe el usuario u organización %q", owner)
		case resp.StatusCode == http.StatusTooManyRequests || resp.Header.Get("X-RateLimit-Remaining") == "0":
			return nil, errors.New("GitHub limitó las consultas: esperá un rato o definí GITHUB_TOKEN")
		case resp.StatusCode == http.StatusUnauthorized:
			return nil, errors.New("GitHub rechazó el token: revisá GITHUB_TOKEN")
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("la API de GitHub respondió HTTP %d", resp.StatusCode)
		case err != nil:
			return nil, fmt.Errorf("respuesta inválida de GitHub: %w", err)
		}
		for _, p := range page {
			out = append(out, Repo{Owner: p.Owner.Login, Name: p.Name, Private: p.Private, Fork: p.Fork, Archived: p.Archived})
		}
		next = ""
		if m := linkNext.FindStringSubmatch(resp.Header.Get("Link")); m != nil && strings.HasPrefix(m[1], a.Base) {
			next = m[1]
		}
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, nil
}
