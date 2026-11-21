package remote

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRepo(t *testing.T) {
	ok := map[string]string{
		"https://github.com/ulisespignatelli/argos":     "ulisespignatelli/argos",
		"https://github.com/ulisespignatelli/argos.git": "ulisespignatelli/argos",
		"github.com/ulisespignatelli/argos/":            "ulisespignatelli/argos",
		"ulisespignatelli/secret-guard.v2":              "ulisespignatelli/secret-guard.v2",
		"http://www.github.com/Org-Name/repo_name":      "Org-Name/repo_name",
	}
	for in, want := range ok {
		r, good := ParseRepo(in)
		if !good || r.FullName() != want {
			t.Errorf("%s -> %v %s", in, good, r.FullName())
		}
	}
	for _, bad := range []string{"https://gitlab.com/a/b", "a/b/c", "../etc/passwd", "-x/y", "https://github.com/a", "a; rm -rf /"} {
		if _, good := ParseRepo(bad); good {
			t.Errorf("%q no debería aceptarse", bad)
		}
	}
	if IsGitHubURL("ulisespignatelli/argos") || !IsGitHubURL("https://github.com/a/b") {
		t.Error("IsGitHubURL debería exigir github.com")
	}
}

func TestBlobURL(t *testing.T) {
	r := Repo{Owner: "o", Name: "r"}
	if got := r.BlobURL("HEAD", "src/mi archivo.js", 7); got != "https://github.com/o/r/blob/HEAD/src/mi%20archivo.js#L7" {
		t.Fatal(got)
	}
}

func TestListReposPaginates(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if req.URL.Query().Get("page") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<%s/users/u/repos?page=2>; rel="next"`, srv.URL))
			fmt.Fprint(w, `[{"name":"a","owner":{"login":"u"}},{"name":"b","fork":true,"owner":{"login":"u"}}]`)
			return
		}
		fmt.Fprint(w, `[{"name":"c","private":true,"owner":{"login":"u"}}]`)
	}))
	defer srv.Close()
	api := &API{Base: srv.URL, Token: "tok", Client: srv.Client()}
	repos, err := api.ListRepos(context.Background(), "users", "u", 0)
	if err != nil || len(repos) != 3 || !repos[1].Fork || !repos[2].Private {
		t.Fatalf("%v %+v", err, repos)
	}
	if _, err := (&API{Base: srv.URL, Client: srv.Client()}).ListRepos(context.Background(), "users", "u", 0); err == nil {
		t.Fatal("sin token debería fallar contra este servidor")
	}
	if _, err := api.ListRepos(context.Background(), "users", "../x", 0); err == nil {
		t.Fatal("nombre inválido aceptado")
	}
}
