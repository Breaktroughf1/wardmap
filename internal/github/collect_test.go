package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const wf = `on: [push]
permissions: {id-token: write}
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: {role-to-assume: "arn:aws:iam::1:role/deploy", aws-region: us-east-1}
`

func TestCollect(t *testing.T) {
	var methods []string
	routes := map[string]any{
		"/orgs/acme/repos":                                  []map[string]any{{"full_name": "acme/api", "default_branch": "main", "private": true}},
		"/orgs/acme/actions/secrets":                        map[string]any{"secrets": []map[string]any{{"name": "NPM_TOKEN", "visibility": "selected", "updated_at": "2026-01-01T00:00:00Z"}}},
		"/orgs/acme/actions/secrets/NPM_TOKEN/repositories": map[string]any{"repositories": []map[string]any{{"full_name": "acme/api"}}},
		"/repos/acme/api/actions/secrets":                   map[string]any{"secrets": []map[string]any{{"name": "DEPLOY_KEY", "updated_at": "2026-02-01T00:00:00Z"}}},
		"/repos/acme/api/actions/organization-secrets":      map[string]any{"secrets": []map[string]any{{"name": "NPM_TOKEN"}}},
		"/repos/acme/api/environments": map[string]any{"environments": []map[string]any{
			{"name": "prod", "protection_rules": []map[string]any{{"type": "required_reviewers"}}, "deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true}},
		}},
		"/repos/acme/api/environments/prod/deployment-branch-policies": map[string]any{"branch_policies": []map[string]any{{"name": "main", "type": "branch"}}},
		"/repos/acme/api/environments/prod/secrets":                    map[string]any{"secrets": []map[string]any{{"name": "DB_URL"}}},
		"/repos/acme/api/actions/oidc/customization/sub":               map[string]any{"use_default": false, "include_claim_keys": []string{"repo", "context"}},
		"/repos/acme/api/branches":                                     []map[string]any{{"name": "main", "protected": true}, {"name": "dev", "protected": false}},
		"/repos/acme/api/contents/.github/workflows":                   []map[string]any{{"path": ".github/workflows/deploy.yml", "type": "file"}},
		"/repos/acme/api/contents/.github/workflows/deploy.yml":        map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(wf)), "encoding": "base64"},
		"/repos/acme/api/pulls":                                        []map[string]any{{"number": 1, "title": "docs: dependency audit notes", "created_at": time.Now().Format(time.RFC3339), "user": map[string]any{"login": "x"}, "head": map[string]any{"ref": "wfx-docs"}}},
		"/repos/acme/api/commits":                                      []map[string]any{{"sha": "abc", "commit": map[string]any{"message": "ci: restore", "author": map[string]any{"name": "x", "date": time.Now().Format(time.RFC3339)}}}},
		"/repos/acme/api/commits/abc":                                  map[string]any{"sha": "abc", "files": []map[string]any{{"filename": ".ci-abcdef.sh"}}},
		"/repos/acme/api/actions/runs":                                 map[string]any{"workflow_runs": []map[string]any{{"workflow_id": 1, "path": ".github/workflows/deploy.yml", "run_number": 3}}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Header.Get("Authorization") != "Bearer t" {
			w.WriteHeader(401)
			return
		}
		if v, ok := routes[r.URL.Path]; ok {
			_ = json.NewEncoder(w).Encode(v)
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client(), UserAgent: "test"}
	s, err := Collect(context.Background(), c, Options{Owner: "acme", Hunt: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range methods {
		if m != http.MethodGet {
			t.Fatalf("non-GET request %s", m)
		}
	}
	if len(s.Repos) != 1 {
		t.Fatalf("repos %d", len(s.Repos))
	}
	r := s.Repos[0]
	if len(r.Secrets) != 1 || len(r.OrgSecretsVisible) != 1 || len(s.OrgSecrets) != 1 || s.OrgSecrets[0].SelectedRepos[0] != "acme/api" {
		t.Fatalf("secrets wrong: %+v %+v", r, s.OrgSecrets)
	}
	e := r.Environments[0]
	if !e.RequiredReviewers || e.BranchPolicy != "custom" || e.BranchPatterns[0] != "main" || len(e.Secrets) != 1 {
		t.Fatalf("env wrong: %+v", e)
	}
	if strings.Join(r.OIDCSubTemplate, ",") != "repo,context" || strings.Join(r.ProtectedBranches, ",") != "main" {
		t.Fatalf("template/protection wrong: %+v", r)
	}
	if len(r.Workflows) != 1 || !r.Workflows[0].Jobs[0].IDTokenWrite {
		t.Fatalf("workflow wrong: %+v", r.Workflows)
	}
	if len(r.PullRequests) != 1 || len(r.Commits) != 1 || r.Commits[0].Files[0] != ".ci-abcdef.sh" || len(r.Runs) != 1 {
		t.Fatalf("hunt data wrong: %+v", r)
	}
}

func TestAccessDeniedBecomesGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/api" {
			_, _ = w.Write([]byte(`{"full_name":"acme/api","default_branch":"main"}`))
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), UserAgent: "test"}
	s, err := Collect(context.Background(), c, Options{Repos: []string{"acme/api"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Gaps) == 0 {
		t.Fatal("403s must be recorded as collection gaps")
	}
}

func TestLargeWorkflowAndEmptyRepo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/big":
			_, _ = w.Write([]byte(`{"full_name":"o/big","default_branch":"main"}`))
		case "/repos/o/big/contents/.github/workflows":
			_, _ = w.Write([]byte(`[{"path":".github/workflows/ci.yml","type":"file"}]`))
		case "/repos/o/big/contents/.github/workflows/ci.yml":
			if r.Header.Get("Accept") == "application/vnd.github.raw" {
				_, _ = w.Write([]byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: echo}]\n"))
				return
			}
			_, _ = w.Write([]byte(`{"encoding":"none","content":"","size":1500000}`))
		case "/repos/o/empty":
			_, _ = w.Write([]byte(`{"full_name":"o/empty","default_branch":"main"}`))
		case "/repos/o/empty/commits":
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"message":"Git Repository is empty."}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), UserAgent: "test"}
	s, err := Collect(context.Background(), c, Options{Repos: []string{"o/big", "o/empty"}, Hunt: true})
	if err != nil {
		t.Fatal(err)
	}
	big := s.Repos[0]
	if len(big.Workflows) != 1 || big.Workflows[0].ParseError != "" || len(big.Workflows[0].Jobs) != 1 {
		t.Fatalf("large workflow not fetched raw: %+v", big.Workflows)
	}
	for _, g := range s.Gaps {
		if strings.Contains(g, "o/empty commits") || strings.Contains(g, "409") {
			t.Errorf("an empty repository's 409 must not produce a gap: %s", g)
		}
	}
}
