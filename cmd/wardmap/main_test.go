package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demo = "../../examples/demo/"

func wm(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code, err := run(context.Background(), args, &out, &errb)
	if err != nil && code == 0 {
		t.Fatalf("%v: %v", args, err)
	}
	if err != nil {
		t.Logf("%v: %v (%s)", args, err, errb.String())
	}
	return code, out.String()
}

func demoSnapshot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s := filepath.Join(dir, "s.json")
	b, err := os.ReadFile(demo + "snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s, b, 0o600); err != nil {
		t.Fatal(err)
	}
	code, _ := wm(t, "import", "-s", s, "--quiet",
		"--aws", demo+"aws-roles.json",
		"--azure", demo+"fic-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.json",
		"--gcp", demo+"gcp-providers.json",
		"--cloudtrail", demo+"cloudtrail.json",
		"--azure-audit", demo+"entra-audit.json")
	if code != 0 {
		t.Fatalf("import exit %d", code)
	}
	return s
}

func TestDemoScan(t *testing.T) {
	s := demoSnapshot(t)
	code, out := wm(t, "scan", "-s", s, "--format", "json")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var res struct {
		Edges []struct{ From, To, Verdict string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	reach := map[string]string{}
	for _, e := range res.Edges {
		reach[e.From+" -> "+e.To] = e.Verdict
	}
	if v := reach["write@example-org/api -> aws-role:arn:aws:iam::111122223333:role/api-prod-deploy"]; v != "" {
		t.Errorf("production role is gated by reviewers but reported %q", v)
	}
	if reach["write@example-org/website -> aws-role:arn:aws:iam::111122223333:role/org-artifacts-read"] != "reachable" {
		t.Error("org-wide role should be reachable from every repository")
	}
	if reach["write@example-org/api -> aws-role:arn:aws:iam::111122223333:role/api-staging"] != "reachable" {
		t.Error("staging role (URL-encoded policy, ungated env) should be reachable")
	}
	if code, _ := wm(t, "scan", "-s", s, "--fail-on", "high"); code != 1 {
		t.Errorf("--fail-on high should exit 1, got %d", code)
	}
}

func TestDemoBaselineAndHunt(t *testing.T) {
	s := demoSnapshot(t)
	b := filepath.Join(t.TempDir(), "b.json")
	if code, _ := wm(t, "baseline", "-s", s, "-o", b); code != 0 {
		t.Fatal("baseline failed")
	}
	if code, _ := wm(t, "scan", "-s", s, "--baseline", b, "--fail-on", "high"); code != 0 {
		t.Errorf("baselined scan should pass, got %d", code)
	}
	code, out := wm(t, "hunt", "-s", s, "--fail-on", "high")
	if code != 1 || !strings.Contains(out, "oidc-from-deleted-branch") || !strings.Contains(out, "wfx-run-gap") ||
		!strings.Contains(out, "wfx-entra-audit") || !strings.Contains(out, "wfx-aws-trust-change") {
		t.Errorf("hunt exit %d output:\n%s", code, out)
	}
	_, sarif := wm(t, "scan", "-s", s, "--format", "sarif")
	var doc map[string]any
	if err := json.Unmarshal([]byte(sarif), &doc); err != nil || doc["version"] != "2.1.0" {
		t.Errorf("invalid SARIF: %v", err)
	}
	for _, f := range []string{"md", "mermaid", "dot"} {
		if code, out := wm(t, "scan", "-s", s, "--format", f); code != 0 || len(out) < 100 {
			t.Errorf("format %s: exit %d, %d bytes", f, code, len(out))
		}
	}
	if code, out := wm(t, "reach", "-s", s, "NPM_TOKEN"); code != 0 || !strings.Contains(out, "write@example-org/website") {
		t.Errorf("reach: %d %s", code, out)
	}
	if code, out := wm(t, "hunt", "-s", s, "--format", "json"); code != 0 || !strings.Contains(out, `"hits"`) {
		t.Errorf("hunt json: %d", code)
	}
	if code, _ := wm(t, "rules"); code != 0 {
		t.Error("rules failed")
	}
	if code, _ := wm(t, "nope"); code != 2 {
		t.Error("unknown command should exit 2")
	}
	_, plan := wm(t, "rotate-plan", "-s", s, "--repo", "example-org/api")
	if !strings.Contains(plan, "| 1 | persistence |") {
		t.Errorf("rotation plan should start with persistence:\n%s", plan)
	}
}

func TestLocal(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github/workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	wf := "on: pull_request_target\npermissions: {id-token: write}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: '${{ github.event.pull_request.head.sha }}'}\n"
	if err := os.WriteFile(filepath.Join(dir, ".github/workflows/x.yml"), []byte(wf), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := wm(t, "run", "--offline", "--dir", dir, "--repo", "o/r", "--format", "sarif", "--repo-relative", "o/r", "--fail-on", "high")
	if code != 1 || !strings.Contains(out, "WM008") || !strings.Contains(out, `".github/workflows/x.yml"`) {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestFailSafeExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github/workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, ".github/workflows/ok.yml"), []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: echo}]\n"), 0o644)
	// An offline snapshot always has a gap (no secret inventory).
	if code, _ := wm(t, "run", "--offline", "--dir", dir, "--repo", "o/r", "--fail-on", "high"); code != 0 {
		t.Errorf("clean offline scan should pass without --fail-on-gaps, got %d", code)
	}
	if code, _ := wm(t, "run", "--offline", "--dir", dir, "--repo", "o/r", "--fail-on-gaps"); code != 1 {
		t.Errorf("--fail-on-gaps must fail when data is incomplete, got %d", code)
	}
	// A hunt with nothing to check must not pass a gate.
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"schema_version":1}`), 0o600)
	if code, out := wm(t, "hunt", "-s", empty, "--fail-on", "high"); code != 2 {
		t.Errorf("hunt with no data and --fail-on must exit 2, got %d:\n%s", code, out)
	}
	if code, out := wm(t, "hunt", "-s", empty); code != 0 || !strings.Contains(out, "Nothing to hunt in") {
		t.Errorf("hunt with no data must say so: %d\n%s", code, out)
	}
	// Workflows but no history or cloud data: say what was not checked.
	snap := filepath.Join(dir, "s.json")
	if code, _ := wm(t, "local", "--dir", dir, "--repo", "o/r", "-o", snap); code != 0 {
		t.Fatal("local failed")
	}
	if _, out := wm(t, "hunt", "-s", snap); !strings.Contains(out, "pull requests, commits and workflow runs were not collected") || !strings.Contains(out, "no CloudTrail") {
		t.Errorf("hunt must list unchecked sources:\n%s", out)
	}
}

func TestDemoCommandAndHTML(t *testing.T) {
	code, out := wm(t, "demo")
	if code != 0 || !strings.Contains(out, "Wardmap demo") || !strings.Contains(out, "wfx-entra-audit") {
		t.Fatalf("demo: %d\n%s", code, out[:min(len(out), 400)])
	}
	code, html := wm(t, "demo", "--format", "html")
	if code != 0 || !strings.HasPrefix(html, "<!doctype html>") || !strings.Contains(html, "Indicators of compromise") || strings.Contains(html, "<script") {
		t.Fatalf("demo html: %d", code)
	}
	s := demoSnapshot(t)
	if code, out := wm(t, "scan", "-s", s, "--format", "html"); code != 0 || !strings.Contains(out, "Blast radius per repository") {
		t.Errorf("scan html: %d", code)
	}
}
