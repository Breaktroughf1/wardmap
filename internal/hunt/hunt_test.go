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

func TestBuiltinPacksAreSourced(t *testing.T) {
	packs, err := LoadPacks("")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packs {
		for _, in := range p.Indicators {
			if p.ID != "generic" && (len(in.Sources) == 0 || in.Verified == "") {
				t.Errorf("%s/%s: campaign indicators must cite sources and a verification level", p.ID, in.ID)
			}
			if in.Pattern == "*/audit.y*ml" || in.Pattern == "*/ci-check.y*ml" {
				t.Errorf("%s/%s: unsupported GhostAction name is back", p.ID, in.ID)
			}
		}
	}
}

func TestValidateRejectsTypos(t *testing.T) {
	bad := []Pack{
		{ID: "x", Version: "1", Indicators: []Indicator{{ID: "a", Type: "branch_nmae", Pattern: "x", Confidence: "high"}}},
		{ID: "x", Version: "1", Indicators: []Indicator{{ID: "a", Type: "branch_name", Confidence: "high"}}},
		{ID: "x", Version: "1", Indicators: []Indicator{{ID: "a", Type: "branch_name", Pattern: "x", Confidence: "very"}}},
		{ID: "x", Version: "1", Indicators: []Indicator{{ID: "a", Type: "run_number_gap", Confidence: "low"}, {ID: "a", Type: "run_number_gap", Confidence: "low"}}},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("case %d should be rejected", i)
		}
	}
}

func TestDay2Indicators(t *testing.T) {
	ts := time.Date(2026, 11, 11, 3, 0, 0, 0, time.UTC)
	s := &model.Snapshot{
		Repos: []model.Repo{{
			FullName: "acme/web",
			Workflows: []model.Workflow{{
				Path:      ".github/workflows/github_actions_security.yml",
				Endpoints: []string{"http://193.32.204.199/x"},
				Jobs:      []model.Job{{ID: "a", DumpsSecrets: true}},
			}},
			Commits: []model.Commit{{SHA: "1234567890abcdef", Message: "Add Github Actions Security workflow", Date: ts,
				Files: []string{"docs/wfx-audit.md", ".github/workflows/build-audit-a1b2c3.yml"}}},
			Branches: []string{"ci-check-4821"},
		}},
		CloudTrail: []model.OIDCAssumeEvent{{Time: ts, RoleARN: "r", Subject: "repo:acme/web:ref:refs/heads/main", SessionName: "wfx-9f3a"}},
		CloudTrailEvents: []model.CloudTrailEvent{
			{Time: ts, EventName: "UpdateAssumeRolePolicy", SessionName: "wfx-9f3a", Target: "deploy"},
			{Time: ts, EventName: "CreateAccessKey", SessionName: "wfx-9f3a", Target: "ci-user"},
			{Time: ts, EventName: "UpdateAssumeRolePolicy", SessionName: "alice", Target: "other"},
		},
		AzureAudit: []model.AzureAuditEvent{{Time: ts, Activity: "Update application", AppName: "deployer", FICNames: []string{"wfx-ci-77aa"}}},
	}
	packs, err := LoadPacks("")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, h := range Run(s, packs) {
		got[h.Indicator]++
	}
	for _, want := range []string{"ghost-workflow", "ghost-exfil-2026", "ghost-commit-add", "secrets-context-dump",
		"wfx-probe-file", "wfx-workflow-commit", "wfx-branch-ci-check", "wfx-aws-session", "wfx-aws-trust-change",
		"wfx-aws-access-key", "wfx-entra-audit"} {
		if got[want] == 0 {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
	if got["wfx-aws-trust-change"] != 1 {
		t.Errorf("session filter not applied: %d", got["wfx-aws-trust-change"])
	}
	if got["trust-policy-change"] != 2 {
		t.Errorf("generic trust change should see both events, got %d", got["trust-policy-change"])
	}
	if got["wfx-aws-session"] != 3 {
		t.Errorf("session name should match the assume event and two follow-ups, got %d", got["wfx-aws-session"])
	}
}
