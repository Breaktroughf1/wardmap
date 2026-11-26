package workflow

import "testing"

const deploy = `
name: deploy
on:
  push:
    branches: [main]
  pull_request_target:
permissions:
  contents: read
env:
  GLOBAL: ${{ secrets.GLOBAL_TOKEN }}
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    environment: prod
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: aws-actions/configure-aws-credentials@0123456789abcdef0123456789abcdef01234567
        with:
          role-to-assume: arn:aws:iam::111122223333:role/deploy
          aws-region: us-east-1
      - uses: some-vendor/notify@v2
        with:
          token: ${{ secrets.SLACK_TOKEN }}
      - run: echo ${{ secrets['NPM_TOKEN'] }} ${{ secrets.GITHUB_TOKEN }}
  call:
    uses: acme/shared/.github/workflows/release.yml@main
    secrets: inherit
`

func TestParse(t *testing.T) {
	w := Parse(".github/workflows/deploy.yml", []byte(deploy))
	if w.ParseError != "" {
		t.Fatal(w.ParseError)
	}
	if len(w.Triggers) != 2 || w.Triggers[0] != "pull_request_target" || w.Triggers[1] != "push" {
		t.Fatalf("triggers %v", w.Triggers)
	}
	if len(w.PushBranches) != 1 || w.PushBranches[0] != "main" {
		t.Fatalf("push branches %v", w.PushBranches)
	}
	b := w.Jobs[0]
	if !b.IDTokenWrite || b.Environment != "prod" || !b.ChecksOutPR {
		t.Fatalf("job facts wrong: %+v", b)
	}
	want := map[string]bool{"GLOBAL_TOKEN": true, "SLACK_TOKEN": true, "NPM_TOKEN": true}
	if len(b.SecretsUsed) != 3 {
		t.Fatalf("secrets %v", b.SecretsUsed)
	}
	for _, s := range b.SecretsUsed {
		if !want[s] {
			t.Fatalf("unexpected secret %s", s)
		}
	}
	if len(b.CloudLogins) != 1 || !b.CloudLogins[0].UsesOIDC || b.CloudLogins[0].Target != "arn:aws:iam::111122223333:role/deploy" {
		t.Fatalf("cloud login %+v", b.CloudLogins)
	}
	var vendor bool
	for _, s := range b.Steps {
		if s.Uses == "some-vendor/notify@v2" {
			vendor = true
			if s.Pinned || !s.ThirdParty || len(s.SecretsPass) != 2 {
				t.Fatalf("vendor step %+v", s)
			}
		}
		if s.Uses == "actions/checkout@v4" && s.ThirdParty {
			t.Fatal("actions/ is first party")
		}
	}
	if !vendor {
		t.Fatal("vendor step missing")
	}
	c := w.Jobs[1]
	if !c.InheritsAll || len(c.Steps) != 1 || c.Steps[0].Pinned {
		t.Fatalf("reusable call %+v", c)
	}
}

func TestParseErrorIsolated(t *testing.T) {
	w := Parse("bad.yml", []byte("on: [push\njobs:"))
	if w.ParseError == "" {
		t.Fatal("expected parse error")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(deploy))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = Parse("f.yml", b)
	})
}
