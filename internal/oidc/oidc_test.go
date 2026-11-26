package oidc

import (
	"encoding/json"
	"testing"

	"github.com/Breaktroughf1/wardmap/internal/model"
)

func repo() model.Repo {
	return model.Repo{
		FullName:          "acme/api",
		DefaultBranch:     "main",
		Private:           true,
		ProtectedBranches: []string{"main"},
		Environments: []model.Environment{
			{Name: "prod", RequiredReviewers: true, BranchPolicy: model.BranchPolicyProtected},
			{Name: "staging", BranchPolicy: model.BranchPolicyAll},
		},
	}
}

func trust(t *testing.T, js string) AWSTrust {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatal(err)
	}
	tr, err := ParseAWSTrust(m)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

const ghPrincipal = `"Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"`

func anyReachable(tr AWSTrust, cs []Candidate) (bool, bool) {
	reach, unknown := false, false
	for _, c := range cs {
		switch tr.Evaluate(c).Verdict {
		case Reachable:
			reach = true
		case Unknown:
			unknown = true
		}
	}
	return reach, unknown
}

func TestAWSVectors(t *testing.T) {
	cs := Candidates(repo())
	ext := ExternalCandidate()
	cases := []struct {
		name          string
		cond          string
		wantReach     bool
		wantExternal  bool
		wantUnknownOK bool
	}{
		{"protected main only", `{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}`, false, false, false},
		{"gated prod environment", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:environment:prod"}}`, false, false, false},
		{"ungated staging environment", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:environment:staging"}}`, true, false, false},
		{"environment that does not exist yet", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:environment:production"}}`, true, false, false},
		{"repo wildcard", `{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/api:*"}}`, true, false, false},
		{"org wildcard", `{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`, true, false, false},
		{"any repo anywhere", `{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}`, true, true, false},
		{"aud only, no sub", `{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`, true, true, false},
		{"unprotected release branch", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/release"}}`, true, false, false},
		{"tags", `{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/tags/v*"}}`, true, false, false},
		{"pull request", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:pull_request"}}`, true, false, false},
		{"other repo", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/web:ref:refs/heads/main"}}`, false, false, false},
		{"StringEquals with star is literal", `{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:*"}}`, false, false, false},
		{"unsupported operator", `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := trust(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":`+c.cond+`}]}`)
			r, u := anyReachable(tr, cs)
			if r != c.wantReach {
				t.Errorf("reachable=%v want %v", r, c.wantReach)
			}
			if u && !c.wantUnknownOK {
				t.Errorf("unexpected needs-review verdict")
			}
			if c.wantUnknownOK && !u {
				t.Errorf("expected needs-review verdict")
			}
			if got := tr.Evaluate(ext).Verdict == Reachable; got != c.wantExternal {
				t.Errorf("external=%v want %v", got, c.wantExternal)
			}
		})
	}
}

func TestAWSWildcardPrincipal(t *testing.T) {
	tr := trust(t, `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`)
	if !tr.WildcardPrincipal {
		t.Fatal("wildcard principal not detected")
	}
}

func TestAWSURLEncoded(t *testing.T) {
	m, err := DecodePolicy("%7B%22Statement%22%3A%5B%5D%7D")
	if err != nil || m["Statement"] == nil {
		t.Fatalf("decode failed: %v %v", m, err)
	}
}

func TestCustomTemplate(t *testing.T) {
	r := repo()
	r.OIDCSubTemplate = []string{"repo", "context", "job_workflow_ref"}
	cs := Candidates(r)
	// Pinning to the protected branch's deploy workflow is not reachable.
	tr := trust(t, `{"Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main:job_workflow_ref:acme/api/.github/workflows/deploy.yml@refs/heads/main"}}}]}`)
	if r, _ := anyReachable(tr, cs); r {
		t.Error("protected-branch job_workflow_ref should not be reachable")
	}
	tr = trust(t, `{"Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/api:*:job_workflow_ref:acme/api/.github/workflows/deploy.yml@*"}}}]}`)
	if r, _ := anyReachable(tr, cs); !r {
		t.Error("wildcard ref on job_workflow_ref should be reachable")
	}
}

func TestUnprotectedDefaultBranch(t *testing.T) {
	r := repo()
	r.ProtectedBranches = nil
	tr := trust(t, `{"Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/api:ref:refs/heads/main"}}}]}`)
	if ok, _ := anyReachable(tr, Candidates(r)); !ok {
		t.Error("main without protection must be reachable by a write credential")
	}
}

func TestAzure(t *testing.T) {
	cs := Candidates(repo())
	cases := []struct {
		f    model.AzureFIC
		want Verdict
	}{
		{model.AzureFIC{Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:acme/api:environment:prod"}, NotReachable},
		{model.AzureFIC{Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:acme/api:ref:refs/heads/feature"}, Reachable},
		{model.AzureFIC{Issuer: "https://token.actions.githubusercontent.com", ClaimsMatching: "claims['sub'] matches 'repo:acme/api:*'"}, Reachable},
		{model.AzureFIC{Issuer: "https://token.actions.githubusercontent.com", ClaimsMatching: "claims['sub'] startswith 'x'"}, Unknown},
		{model.AzureFIC{Issuer: "https://sts.windows.net/x", Subject: "repo:acme/api:pull_request"}, NotReachable},
	}
	for i, c := range cases {
		best := NotReachable
		for _, cand := range cs {
			v := EvaluateAzure(c.f, cand).Verdict
			if v == Reachable || (v == Unknown && best == NotReachable) {
				best = v
			}
		}
		if best != c.want {
			t.Errorf("case %d: got %v want %v", i, best, c.want)
		}
	}
}

func TestGCP(t *testing.T) {
	cs := Candidates(repo())
	mapping := map[string]string{"google.subject": "assertion.sub", "attribute.repository": "assertion.repository", "attribute.ref": "assertion.ref"}
	cases := []struct {
		cond     string
		want     Verdict
		external bool
	}{
		{"", Reachable, true},
		{"assertion.repository_owner == 'acme'", Reachable, false},
		{"assertion.repository == 'acme/api' && assertion.ref == 'refs/heads/main'", NotReachable, false},
		{"attribute.repository == 'acme/api' && attribute.ref == 'refs/heads/main'", NotReachable, false},
		{"assertion.repository == 'acme/api' && assertion.ref.startsWith('refs/heads/')", Reachable, false},
		{"assertion.repository in ['acme/web', 'acme/api'] && assertion.environment == 'prod'", NotReachable, false},
		{"assertion.repository == 'acme/api' && assertion.environment == 'staging'", Reachable, false},
		{"assertion.repository == 'acme/api' && !(assertion.ref.startsWith('refs/heads/'))", Reachable, false},
		{"assertion.repository == 'acme/api' && assertion.ref != 'refs/heads/main'", Reachable, false},
		{"assertion.repository.matches('^acme/')", Unknown, false},
	}
	for _, c := range cases {
		p := model.GCPProvider{Name: "p", IssuerURI: "https://token.actions.githubusercontent.com", AttributeCondition: c.cond, AttributeMapping: mapping}
		best := NotReachable
		for _, cand := range cs {
			v := EvaluateGCP(p, cand).Verdict
			if v == Reachable || (v == Unknown && best == NotReachable) {
				best = v
			}
		}
		if best != c.want {
			t.Errorf("%q: got %v want %v", c.cond, best, c.want)
		}
		if got := EvaluateGCP(p, ExternalCandidate()).Verdict == Reachable; got != c.external {
			t.Errorf("%q: external=%v want %v", c.cond, got, c.external)
		}
	}
}

// Regression tests for false negatives found in the fail-safe review.
func TestFailSafeAWS(t *testing.T) {
	cs := Candidates(repo())
	cases := []struct {
		name, cond string
		want       bool
	}{
		{"condition key case is ignored", `{"StringLike":{"token.actions.githubusercontent.com:Sub":"repo:acme/api:*"}}`, true},
		{"upper-case key, protected main only", `{"StringEquals":{"TOKEN.ACTIONS.GITHUBUSERCONTENT.COM:SUB":"repo:acme/api:ref:refs/heads/main"}}`, false},
		{"IfExists passes when claim is absent", `{"StringEqualsIfExists":{"token.actions.githubusercontent.com:environment":"prod"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/api:*"}}`, true},
		{"IfExists still checks a present claim", `{"StringEqualsIfExists":{"token.actions.githubusercontent.com:repository":"acme/web"}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := trust(t, `{"Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":`+c.cond+`}]}`)
			if got, _ := anyReachable(tr, cs); got != c.want {
				t.Errorf("reachable=%v want %v", got, c.want)
			}
		})
	}
}

func TestTemplateProbe(t *testing.T) {
	r := repo()
	r.OIDCSubTemplateUnknown = true
	// Written for a custom template the collector could not read.
	tr := trust(t, `{"Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repository_owner_id:42:repo:acme/api:context:ref:refs/heads/feature"}}}]}`)
	if ok, _ := anyReachable(tr, Candidates(r)); ok {
		t.Fatal("default-template candidates should not match a custom-format subject")
	}
	if tr.Evaluate(TemplateProbe(r)).Verdict != Reachable {
		t.Fatal("probe must flag trust that mentions the repository")
	}
	other := trust(t, `{"Statement":[{"Effect":"Allow",`+ghPrincipal+`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/web:ref:refs/heads/main"}}}]}`)
	if other.Evaluate(TemplateProbe(r)).Verdict == Reachable {
		t.Fatal("probe must not match other repositories")
	}
}

func TestGCPMalformedNeverPanicsOrPasses(t *testing.T) {
	cs := Candidates(repo())
	for _, cond := range []string{"'x' in", "'x' in 'y'", "assertion.repository ==", "!(", "!(assertion.ref == 'a'", "(((", "assertion.ref.startsWith(", "'a' == "} {
		p := model.GCPProvider{IssuerURI: "https://token.actions.githubusercontent.com", AttributeCondition: cond}
		for _, c := range cs {
			if v := EvaluateGCP(p, c).Verdict; v == NotReachable {
				t.Errorf("%q: malformed condition must not read as not reachable", cond)
			}
		}
	}
}

func FuzzAWSTrust(f *testing.F) {
	f.Add(`{"Statement":[{"Effect":"Allow",` + ghPrincipal + `,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:a/*"}}}]}`)
	f.Add(`{"Statement":{"Effect":"Allow","Principal":"*","Action":["sts:*"],"Condition":{"Null":{"x":"true"}}}}`)
	cs := append(Candidates(repo()), ExternalCandidate())
	f.Fuzz(func(t *testing.T, doc string) {
		var m map[string]any
		if json.Unmarshal([]byte(doc), &m) != nil {
			return
		}
		tr, err := ParseAWSTrust(m)
		if err != nil {
			return
		}
		for _, c := range cs {
			_ = tr.Evaluate(c)
		}
	})
}

func FuzzGCPCondition(f *testing.F) {
	f.Add("assertion.repository == 'acme/api' && !(assertion.ref.startsWith('refs/heads/'))")
	f.Add("attribute.repository in ['a/b', 'acme/api'] || assertion.environment != 'prod'")
	cs := append(Candidates(repo()), ExternalCandidate())
	f.Fuzz(func(t *testing.T, cond string) {
		if len(cond) > 256 {
			return
		}
		p := model.GCPProvider{IssuerURI: "https://token.actions.githubusercontent.com", AttributeCondition: cond,
			AttributeMapping: map[string]string{"attribute.repository": "assertion.repository"}}
		for _, c := range cs {
			_ = EvaluateGCP(p, c)
		}
	})
}
