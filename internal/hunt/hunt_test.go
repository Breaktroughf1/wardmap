package hunt

import (
	"testing"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/model"
)

func TestHunt(t *testing.T) {
	ts := func(d int) time.Time { return time.Date(2026, 11, d, 12, 0, 0, 0, time.UTC) }
	s := &model.Snapshot{
		Repos: []model.Repo{{
			FullName: "acme/api",
			Branches: []string{"main", "wfx-docs-3f2a"},
			PullRequests: []model.PullRequest{
				{Number: 7, Title: "docs: dependency audit notes", Author: "victim", HeadRef: "wfx-docs-3f2a", CreatedAt: ts(11)},
			},
			Commits: []model.Commit{
				{SHA: "abcdef0123456789", Message: "ci: refresh build cache\n\nbody", Author: "victim", Date: ts(11), Files: []string{".ci-a1b2c3.sh", ".github/workflows/ci.yml"}},
				{SHA: "bcdef0123456789a", Message: "fix: typo", Author: "dev", Date: ts(9)},
			},
			Runs: []model.Run{
				{WorkflowPath: ".github/workflows/ci.yml", RunNumber: 40, CreatedAt: ts(10)},
				{WorkflowPath: ".github/workflows/ci.yml", RunNumber: 43, CreatedAt: ts(12)},
			},
		}},
		AzureFICs: []model.AzureFIC{{AppID: "a", Name: "wfx-ci-9x"}},
		AWSRoles:  []model.AWSRole{{ARN: "r", TrustPolicy: map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "*"}}}}}},
		CloudTrail: []model.OIDCAssumeEvent{
			{Time: ts(11), RoleARN: "arn:aws:iam::1:role/deploy", Subject: "repo:acme/api:ref:refs/heads/tmp-xyz", SourceIP: "203.0.113.9"},
			{Time: ts(11), RoleARN: "arn:aws:iam::1:role/deploy", Subject: "repo:acme/api:ref:refs/heads/main"},
		},
	}
	packs, err := LoadPacks("")
	if err != nil {
		t.Fatal(err)
	}
	hits := Run(s, packs)
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Indicator] = true
	}
	for _, want := range []string{"wfx-branch", "wfx-pr-title", "wfx-pr-branch", "wfx-commit-cache", "wfx-script-root", "wfx-entra-fic", "wfx-aws-trust", "wfx-run-gap", "oidc-from-deleted-branch"} {
		if !got[want] {
			t.Errorf("missing hit %s", want)
		}
	}
	for _, h := range hits {
		if h.Indicator == "oidc-from-deleted-branch" && h.Evidence == "" {
			t.Error("empty evidence")
		}
		if h.Indicator == "wfx-pr-title" && !h.InWindow {
			t.Error("PR should be inside campaign window")
		}
	}
	if hits[0].Confidence != "high" {
		t.Error("hits should be sorted by confidence")
	}
}
