package analysis

import (
	"testing"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/model"
)

func snap() *model.Snapshot {
	return &model.Snapshot{
		SchemaVersion: 1,
		OrgSecrets: []model.OrgSecret{
			{Name: "NPM_TOKEN", Visibility: "all", UpdatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
			{Name: "SELECTED", Visibility: "selected", SelectedRepos: []string{"web"}},
		},
		Repos: []model.Repo{{
			FullName: "acme/api", DefaultBranch: "main", Private: true,
			ProtectedBranches: []string{"main"},
			Secrets:           []model.Secret{{Name: "AWS_SECRET_ACCESS_KEY"}},
			Environments: []model.Environment{
				{Name: "prod", RequiredReviewers: true, BranchPolicy: "protected", Secrets: []model.Secret{{Name: "DB_URL"}}},
				{Name: "dev", BranchPolicy: "all", Secrets: []model.Secret{{Name: "DEV_KEY"}}},
			},
		}},
		AWSRoles: []model.AWSRole{
			{ARN: "arn:aws:iam::1:role/prod", TrustPolicy: map[string]any{"Statement": []any{map[string]any{
				"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
				"Principal": map[string]any{"Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
				"Condition": map[string]any{"StringEquals": map[string]any{
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
					"token.actions.githubusercontent.com:sub": "repo:acme/api:environment:prod"}}}}}},
			{ARN: "arn:aws:iam::1:role/broad", TrustPolicy: map[string]any{"Statement": []any{map[string]any{
				"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
				"Principal": map[string]any{"Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
				"Condition": map[string]any{"StringLike": map[string]any{
					"token.actions.githubusercontent.com:sub": "repo:acme/*"}}}}}},
			{ARN: "arn:aws:iam::1:role/backdoor", TrustPolicy: map[string]any{"Statement": []any{map[string]any{
				"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": "*"}}}}},
		},
		AzureFICs: []model.AzureFIC{{AppID: "app1", Name: "wfx-ci-1a2b", Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:acme/api:ref:refs/heads/x"}},
	}
}

func rules(r Result) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.RuleID]++
	}
	return m
}

func TestAnalyze(t *testing.T) {
	r := Analyze(snap(), Options{Now: time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)})
	got := rules(r)
	for _, want := range []string{"WM001", "WM002", "WM003", "WM004", "WM005", "WM007", "WM010", "WM011", "WM012"} {
		if got[want] == 0 {
			t.Errorf("expected rule %s to fire; got %v", want, got)
		}
	}
	if got["WM006"] != 0 {
		t.Errorf("no role trusts external repos; got WM006")
	}
	reach := map[string]string{}
	for _, e := range r.Edges {
		reach[e.To] = e.Verdict
	}
	if reach["aws-role:arn:aws:iam::1:role/prod"] != "" {
		t.Error("gated prod role must not be reachable")
	}
	if reach["aws-role:arn:aws:iam::1:role/broad"] != "reachable" {
		t.Error("org-wide role must be reachable")
	}
	if reach["secret:acme/api/env/prod/DB_URL"] != "gated" || reach["secret:acme/api/env/dev/DEV_KEY"] != "reachable" {
		t.Errorf("environment gating wrong: %v", reach)
	}
	if reach["secret:org/SELECTED"] != "" {
		t.Error("selected org secret should not reach acme/api")
	}
	plan := RotatePlan(r, []string{"acme/api"})
	if len(plan) == 0 || plan[0].Phase != "persistence" {
		t.Fatalf("rotation plan should start with cloud trust: %+v", plan)
	}
}

func TestTokenAndKeySecrets(t *testing.T) {
	s := &model.Snapshot{Repos: []model.Repo{
		{FullName: "o/app", Branches: []string{"main"}, Secrets: []model.Secret{
			{Name: "LYNX_SYNC_PAT"}, {Name: "GHCR_PAT"}, {Name: "GH_TOKEN"}, {Name: "EC2_SSH_KEY"},
			{Name: "DEPLOY_SSH_PRIVATE_KEY"}, {Name: "SLACK_WEBHOOK"}, {Name: "PATH_PREFIX"}, {Name: "NPM_TOKEN"},
		}},
		{FullName: "o/empty"},
	}}
	got := map[string][]string{}
	for _, f := range Analyze(s, Options{}).Findings {
		got[f.RuleID] = append(got[f.RuleID], f.Key)
	}
	if len(got["WM019"]) != 3 {
		t.Errorf("want LYNX_SYNC_PAT, GHCR_PAT and GH_TOKEN flagged as PATs, got %v", got["WM019"])
	}
	if len(got["WM011"]) != 2 {
		t.Errorf("want two SSH keys flagged, got %v", got["WM011"])
	}
	for _, k := range got["WM016"] {
		if k == "o/empty/branches" {
			t.Error("empty repository should not get a branch-protection notice")
		}
	}
}

func TestFingerprintStable(t *testing.T) {
	a := Analyze(snap(), Options{})
	b := Analyze(snap(), Options{})
	if len(a.Findings) != len(b.Findings) {
		t.Fatal("non-deterministic")
	}
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != b.Findings[i].Fingerprint {
			t.Fatal("fingerprints unstable")
		}
	}
}
