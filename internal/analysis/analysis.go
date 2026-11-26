// Package analysis joins GitHub secret scoping with cloud OIDC trust into a
// reach graph and evaluates rules over it.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/glob"
	"github.com/Breaktroughf1/wardmap/internal/model"
	"github.com/Breaktroughf1/wardmap/internal/oidc"
)

// Severity of a finding.
type Severity int

// Severities, ordered.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string { return sevNames[s] }

// ParseSeverity parses a severity name.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(n, s) {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of %s)", s, strings.Join(sevNames, ", "))
}

// Edge is one reach relationship.
type Edge struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Kind    string `json:"kind"` // secret | aws-role | azure-app | gcp-provider
	Via     string `json:"via"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// Key is the stable identity of an edge, used by baselines.
func (e Edge) Key() string { return e.From + " -> " + e.To }

// Finding is a rule result.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Message     string   `json:"message"`
	Repo        string   `json:"repo,omitempty"`
	Path        string   `json:"path,omitempty"`
	Key         string   `json:"-"`
	Fingerprint string   `json:"fingerprint"`
}

// Result is the full analysis output.
type Result struct {
	Edges    []Edge    `json:"edges"`
	Findings []Finding `json:"findings"`
	Gaps     []string  `json:"collection_gaps,omitempty"`
}

// Options tune rules.
type Options struct {
	StaleDays int
	Now       time.Time
}

// ActorFor names the "write credential on repo" principal.
func ActorFor(repo string) string { return "write@" + repo }

// ExternalActor names the synthetic outside attacker.
const ExternalActor = "any-github-repository"

// Analyze builds the reach graph and evaluates every rule.
func Analyze(s *model.Snapshot, o Options) Result {
	if o.StaleDays == 0 {
		o.StaleDays = 180
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	a := &analyzer{s: s, o: o}
	a.run()
	sort.Slice(a.res.Edges, func(i, j int) bool { return a.res.Edges[i].Key() < a.res.Edges[j].Key() })
	sort.SliceStable(a.res.Findings, func(i, j int) bool {
		fi, fj := a.res.Findings[i], a.res.Findings[j]
		if fi.Severity != fj.Severity {
			return fi.Severity > fj.Severity
		}
		if fi.RuleID != fj.RuleID {
			return fi.RuleID < fj.RuleID
		}
		return fi.Key < fj.Key
	})
	a.res.Gaps = s.Gaps
	return a.res
}

type analyzer struct {
	s   *model.Snapshot
	o   Options
	res Result
	aws []parsedRole
}

type parsedRole struct {
	role  model.AWSRole
	trust oidc.AWSTrust
	err   error
}

func (a *analyzer) add(rule string, sev Severity, repo, path, key, msg string) {
	h := sha256.Sum256([]byte(rule + "|" + key))
	a.res.Findings = append(a.res.Findings, Finding{
		RuleID: rule, Severity: sev, SeverityStr: sev.String(), Message: msg,
		Repo: repo, Path: path, Key: key, Fingerprint: hex.EncodeToString(h[:12]),
	})
}

func (a *analyzer) run() {
	for _, r := range a.s.AWSRoles {
		doc, err := oidc.DecodePolicy(any(r.TrustPolicy))
		var t oidc.AWSTrust
		if err == nil {
			t, err = oidc.ParseAWSTrust(doc)
		}
		a.aws = append(a.aws, parsedRole{r, t, err})
	}
	a.secretReach()
	a.cloudReach()
	a.cloudLint()
	a.workflowRules()
	a.secretHygiene()
	for _, g := range a.s.Gaps {
		a.add("WM016", Info, "", "", g, "Collection gap: "+strings.TrimRight(g, ". ")+". Results for the affected scope are incomplete.")
	}
}

// orgSecretVisible reports whether org secret os is available to repo r.
func orgSecretVisible(os model.OrgSecret, r model.Repo) bool {
	switch os.Visibility {
	case model.VisibilityAll:
		return true
	case model.VisibilityPrivate:
		return r.Private
	case model.VisibilitySelected:
		for _, n := range os.SelectedRepos {
			if n == r.FullName || strings.HasSuffix(r.FullName, "/"+n) {
				return true
			}
		}
	}
	return false
}

func (a *analyzer) secretReach() {
	orgByName := map[string]model.OrgSecret{}
	for _, os := range a.s.OrgSecrets {
		orgByName[os.Name] = os
	}
	publicRepos := 0
	for _, r := range a.s.Repos {
		if !r.Private {
			publicRepos++
		}
	}
	for _, os := range a.s.OrgSecrets {
		if os.Visibility == model.VisibilityAll {
			sev := Medium
			if publicRepos > 0 {
				sev = High
			}
			a.add("WM001", sev, "", "", "org/"+os.Name,
				fmt.Sprintf("Organisation secret %s has visibility \"all\": any workflow in any repository (%d public) can read it. Restrict it to selected repositories or move it to an environment.", os.Name, publicRepos))
		}
	}
	for _, r := range a.s.Repos {
		if r.Archived {
			continue
		}
		actor := ActorFor(r.FullName)
		var ungated []string
		for _, sec := range r.Secrets {
			a.res.Edges = append(a.res.Edges, Edge{From: actor, To: "secret:" + r.FullName + "/" + sec.Name, Kind: "secret", Via: "repository secret (any branch, any workflow)", Verdict: "reachable"})
			ungated = append(ungated, sec.Name)
		}
		seen := map[string]bool{}
		for _, os := range a.s.OrgSecrets {
			if orgSecretVisible(os, r) {
				seen[os.Name] = true
			}
		}
		for _, n := range r.OrgSecretsVisible {
			seen[n] = true
		}
		var orgNames []string
		for n := range seen {
			orgNames = append(orgNames, n)
		}
		sort.Strings(orgNames)
		for _, n := range orgNames {
			a.res.Edges = append(a.res.Edges, Edge{From: actor, To: "secret:org/" + n, Kind: "secret", Via: "organisation secret visible to repository", Verdict: "reachable"})
			ungated = append(ungated, "org/"+n)
		}
		for _, e := range r.Environments {
			gated := oidc.EnvironmentGated(e, r.ProtectedBranches)
			for _, sec := range e.Secrets {
				ed := Edge{From: actor, To: "secret:" + r.FullName + "/env/" + e.Name + "/" + sec.Name, Kind: "secret", Via: "environment " + e.Name}
				if gated {
					ed.Verdict = "gated"
					ed.Reason = gateReason(e)
				} else {
					ed.Verdict = "reachable"
					ed.Reason = "environment has no required reviewers and admits unprotected branches"
				}
				a.res.Edges = append(a.res.Edges, ed)
			}
			if !gated && len(e.Secrets) > 0 {
				a.add("WM007", Medium, r.FullName, "", r.FullName+"/env/"+e.Name,
					fmt.Sprintf("Environment %s in %s holds %d secret(s) but has no required reviewers and admits unprotected branches, so a write credential can read them. Add required reviewers or restrict deployment branches to protected branches.", e.Name, r.FullName, len(e.Secrets)))
			}
		}
		if len(ungated) > 0 {
			sort.Strings(ungated)
			a.add("WM002", Medium, r.FullName, "", r.FullName,
				fmt.Sprintf("%d secret(s) are readable from any branch of %s by anyone with write access (the wfx-loot/GhostAction technique): %s. Move deployment secrets to protected environments.", len(ungated), r.FullName, strings.Join(ungated, ", ")))
		}
		empty := len(r.Workflows) == 0 && len(r.Secrets) == 0 && len(r.Environments) == 0
		if len(r.ProtectedBranches) == 0 && len(r.Branches) == 0 && !empty {
			a.add("WM016", Info, r.FullName, "", r.FullName+"/branches",
				"Branch protection for "+r.FullName+" was not collected; every branch is treated as pushable by a write credential.")
		}
	}
}

func gateReason(e model.Environment) string {
	switch {
	case e.RequiredReviewers:
		return "required reviewers"
	case e.BranchPolicy == model.BranchPolicyProtected:
		return "protected branches only"
	default:
		return "deployment branches limited to protected branches"
	}
}

type target struct {
	kind, id string
	eval     func(oidc.Candidate) oidc.Result
}

func (a *analyzer) targets() []target {
	var ts []target
	for _, pr := range a.aws {
		pr := pr
		if pr.err != nil {
			continue
		}
		ts = append(ts, target{"aws-role", pr.role.ARN, pr.trust.Evaluate})
	}
	for _, f := range a.s.AzureFICs {
		f := f
		ts = append(ts, target{"azure-app", f.AppID + "/" + f.Name, func(c oidc.Candidate) oidc.Result { return oidc.EvaluateAzure(f, c) }})
	}
	for _, p := range a.s.GCPProviders {
		p := p
		ts = append(ts, target{"gcp-provider", p.Name, func(c oidc.Candidate) oidc.Result { return oidc.EvaluateGCP(p, c) }})
	}
	return ts
}

func (a *analyzer) cloudReach() {
	ts := a.targets()
	for _, t := range ts {
		var ext oidc.Candidate
		r := oidc.Result{}
		for _, e := range oidc.ExternalCandidates() {
			if rr := t.eval(e); rr.Verdict == oidc.Reachable {
				ext, r = e, rr
				break
			}
		}
		if r.Verdict == oidc.Reachable {
			a.res.Edges = append(a.res.Edges, Edge{From: ExternalActor, To: t.kind + ":" + t.id, Kind: t.kind, Via: ext.Label, Verdict: "reachable", Reason: r.Reason})
			a.add("WM006", Critical, "", "", t.kind+":"+t.id,
				fmt.Sprintf("%s %s trusts GitHub OIDC tokens from ANY GitHub repository (%s). Anyone on GitHub can obtain credentials. Constrain the subject to your repositories and protected refs or environments.", t.kind, t.id, r.Reason))
		}
	}
	for _, repo := range a.s.Repos {
		if repo.Archived {
			continue
		}
		cands := oidc.Candidates(repo)
		for _, t := range ts {
			var hit *oidc.Result
			var via string
			var unknown *oidc.Result
			for _, c := range cands {
				r := t.eval(c)
				if r.Verdict == oidc.Reachable {
					rr := r
					hit, via = &rr, c.Label
					break
				}
				if r.Verdict == oidc.Unknown && unknown == nil {
					rr := r
					unknown = &rr
				}
			}
			if hit == nil && unknown == nil && repo.OIDCSubTemplateUnknown {
				if r := t.eval(oidc.TemplateProbe(repo)); r.Verdict != oidc.NotReachable {
					unknown = &oidc.Result{Verdict: oidc.Unknown, Reason: "this repository's OIDC subject template could not be read, and the trust may admit it (" + r.Reason + ")"}
				}
			}
			actor := ActorFor(repo.FullName)
			switch {
			case hit != nil:
				a.res.Edges = append(a.res.Edges, Edge{From: actor, To: t.kind + ":" + t.id, Kind: t.kind, Via: via, Verdict: "reachable", Reason: hit.Reason})
				a.add("WM003", High, repo.FullName, "", repo.FullName+"|"+t.kind+":"+t.id,
					fmt.Sprintf("A write credential on %s can obtain %s %s via %s (%s). Bind the trust to a protected branch or an environment with required reviewers.", repo.FullName, t.kind, t.id, via, hit.Reason))
			case unknown != nil:
				a.res.Edges = append(a.res.Edges, Edge{From: actor, To: t.kind + ":" + t.id, Kind: t.kind, Via: "unevaluated condition", Verdict: "needs-review", Reason: unknown.Reason})
				// Fail closed: an undecidable trust is treated as seriously as
				// a reachable one until a person reviews it.
				a.add("WM014", High, repo.FullName, "", repo.FullName+"|"+t.kind+":"+t.id,
					fmt.Sprintf("Could not decide whether %s can reach %s %s: %s. Wardmap never reports this as safe; review it manually.", repo.FullName, t.kind, t.id, unknown.Reason))
			}
		}
	}
}

var orgWideSub = regexp.MustCompile(`^repo:[^/:]+/\*`)

func (a *analyzer) cloudLint() {
	for _, pr := range a.aws {
		if pr.err != nil {
			a.add("WM014", High, "", "", "aws-parse:"+pr.role.ARN, "Trust policy for "+pr.role.ARN+" could not be parsed: "+pr.err.Error())
			continue
		}
		if pr.trust.WildcardPrincipal {
			a.add("WM012", Critical, "", "", "aws:"+pr.role.ARN,
				"Role "+pr.role.ARN+" trusts a wildcard principal (\"*\" or {\"AWS\":\"*\"}). This is the wfx-loot persistence pattern: any AWS account can assume it. Treat as a possible compromise, investigate CloudTrail UpdateAssumeRolePolicy events, and restore the trust policy.")
		}
		if len(pr.trust.GitHub) == 0 {
			continue
		}
		subs, hasAud, unconstrained := pr.trust.SubPatterns()
		if !hasAud {
			a.add("WM005", Low, "", "", "aws:"+pr.role.ARN,
				"Role "+pr.role.ARN+" does not constrain the token audience. Add aud = sts.amazonaws.com as defence in depth (the requesting workflow chooses aud, so this does not stop a malicious workflow).")
		}
		if unconstrained {
			a.add("WM004", High, "", "", "aws-nosub:"+pr.role.ARN,
				"Role "+pr.role.ARN+" has a GitHub OIDC statement with no sub condition.")
		}
		var nameOnly []string
		for _, s := range subs {
			if parts := strings.SplitN(s, ":", 3); len(parts) >= 2 && parts[0] == "repo" && !strings.Contains(parts[1], "@") && !glob.HasWildcard(parts[1]) {
				nameOnly = append(nameOnly, s)
			}
		}
		if len(nameOnly) > 0 {
			a.add("WM021", Low, "", "", "aws-names:"+pr.role.ARN,
				fmt.Sprintf("Role %s identifies repositories by name only (%s). If the organisation or repository name is ever deleted and re-registered, the new owner can assume the role. Use GitHub's immutable subjects (repo:OWNER@ID/REPO@ID:...), the default for repositories created after 15 July 2026, or add repository_id/repository_owner_id conditions.", pr.role.ARN, strings.Join(nameOnly, ", ")))
		}
		for _, s := range subs {
			if s == "*" || orgWideSub.MatchString(s) {
				a.add("WM004", High, "", "", "aws-sub:"+pr.role.ARN+":"+s,
					fmt.Sprintf("Role %s trusts sub %q, which admits every repository of the owner. Any write credential on any repository can assume it.", pr.role.ARN, s))
			}
		}
	}
	for _, p := range a.s.GCPProviders {
		if !strings.Contains(p.IssuerURI, model.GitHubIssuer) {
			continue
		}
		c := strings.TrimSpace(p.AttributeCondition)
		if c == "" {
			a.add("WM013", Critical, "", "", "gcp:"+p.Name, "Workload identity provider "+p.Name+" has no attribute condition: any GitHub repository can exchange tokens.")
		} else if !strings.Contains(c, "repository") || regexp.MustCompile(`^\s*assertion\.repository_owner\s*==\s*'[^']+'\s*$`).MatchString(c) {
			a.add("WM004", High, "", "", "gcp:"+p.Name, "Workload identity provider "+p.Name+" condition ("+c+") only constrains the owner, admitting every repository of the organisation.")
		}
	}
	for _, f := range a.s.AzureFICs {
		if strings.HasPrefix(strings.ToLower(f.Name), "wfx-ci-") {
			a.add("WM012", Critical, "", "", "azure:"+f.AppID+"/"+f.Name,
				"Federated credential "+f.Name+" on app "+f.AppID+" matches the wfx-loot persistence naming pattern (wfx-ci-*). Treat as compromise: remove it and review Entra audit logs.")
		}
	}
}

var untrustedTriggers = map[string]bool{"pull_request_target": true, "workflow_run": true, "issue_comment": true, "pull_request_review_comment": true, "discussion_comment": true}

func (a *analyzer) workflowRules() {
	for _, r := range a.s.Repos {
		if r.Archived {
			continue
		}
		for _, w := range r.Workflows {
			if w.ParseError != "" {
				a.add("WM018", Info, r.FullName, w.Path, r.FullName+"/"+w.Path, "Workflow could not be parsed: "+w.ParseError)
				continue
			}
			var risky []string
			for _, t := range w.Triggers {
				if t == "workflow_run" && trustedRunSources(r, w) {
					continue
				}
				if untrustedTriggers[t] {
					risky = append(risky, t)
				}
			}
			for _, j := range w.Jobs {
				k := r.FullName + "/" + w.Path + "#" + j.ID
				if j.IDTokenWrite && len(risky) > 0 {
					a.add("WM008", High, r.FullName, w.Path, k,
						fmt.Sprintf("Job %s requests id-token: write on untrusted trigger(s) %s. Code from outside contributors can influence a job that mints cloud credentials.", j.ID, strings.Join(risky, ", ")))
				}
				if j.ChecksOutPR && contains(w.Triggers, "pull_request_target") && (len(j.SecretsUsed) > 0 || j.IDTokenWrite || j.InheritsAll) {
					a.add("WM015", High, r.FullName, w.Path, k,
						"Job "+j.ID+" runs on pull_request_target, checks out the pull request head and has secrets or id-token access (\"pwn request\"). Use pull_request, or never execute PR code in this job.")
				}
				for _, st := range j.Steps {
					if st.ThirdParty && !st.Pinned && len(st.SecretsPass) > 0 {
						a.add("WM009", Medium, r.FullName, w.Path, k+"|"+st.Uses,
							fmt.Sprintf("Job %s passes secret(s) %s to %s, which is not pinned to a full commit SHA. A retagged release would receive them.", j.ID, strings.Join(st.SecretsPass, ", "), st.Uses))
					}
					if st.ThirdParty && contains(st.SecretsPass, "*") {
						a.add("WM017", Low, r.FullName, w.Path, k+"|inherit|"+st.Uses,
							"Job "+j.ID+" passes ALL secrets (secrets: inherit) to "+st.Uses+". Pass only the secrets it needs.")
					}
				}
				for _, cl := range j.CloudLogins {
					if !cl.UsesOIDC {
						a.add("WM011", Medium, r.FullName, w.Path, k+"|login|"+cl.Provider,
							fmt.Sprintf("Job %s logs in to %s with a long-lived credential. Switch to GitHub OIDC so no static cloud key is stored in GitHub.", j.ID, strings.ToUpper(cl.Provider)))
					}
				}
			}
		}
	}
}

// maintainerTriggers can only be started by people with write access (or by
// a schedule), never by an outside contributor's pull request or comment.
var maintainerTriggers = map[string]bool{"push": true, "schedule": true, "workflow_dispatch": true, "release": true}

// trustedRunSources reports whether every workflow that can fire w's
// workflow_run trigger is in this repository and itself starts only on
// maintainer triggers. Anything unresolved counts as untrusted (fail safe).
func trustedRunSources(r model.Repo, w model.Workflow) bool {
	if len(w.RunSources) == 0 {
		return false
	}
	for _, src := range w.RunSources {
		found := false
		for _, o := range r.Workflows {
			if o.ParseError != "" || (o.Name != src && !(o.Name == "" && o.Path == src)) {
				continue
			}
			found = true
			if len(o.Triggers) == 0 {
				return false
			}
			for _, t := range o.Triggers {
				if !maintainerTriggers[t] {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

var staticCloudSecret = regexp.MustCompile(`(?i)^(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_ACCESS_KEY|AWS_SECRET_KEY|AZURE_CREDENTIALS|AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET|GCP_SA_KEY|GCP_CREDENTIALS|GOOGLE_CREDENTIALS|GOOGLE_APPLICATION_CREDENTIALS|GCLOUD_SERVICE_KEY|.*_SERVICE_ACCOUNT_KEY|.*_SA_KEY|DO_TOKEN|DIGITALOCEAN_ACCESS_TOKEN)$`)

var (
	sshKeySecret = regexp.MustCompile(`(?i)SSH.*(KEY|PRIVATE|PEM)|(KEY|PRIVATE).*SSH|(^|_)(ID_RSA|ID_ED25519|PEM_KEY)$`)
	// githubTokenSecret matches names that conventionally hold GitHub
	// personal access tokens. GITHUB_TOKEN itself cannot be a secret.
	githubTokenSecret = regexp.MustCompile(`(?i)(^|_)(PAT|GH_TOKEN|GH_PAT|GITHUB_PAT|PERSONAL_ACCESS_TOKEN)$|^(PAT|GH|GITHUB)_[A-Z0-9_]*TOKEN$|_PAT_`)
)

func (a *analyzer) secretHygiene() {
	stale := a.o.Now.AddDate(0, 0, -a.o.StaleDays)
	check := func(repo, scope string, s model.Secret) {
		if staticCloudSecret.MatchString(s.Name) {
			a.add("WM011", Medium, repo, "", "static|"+scope+"/"+s.Name,
				"Secret "+scope+"/"+s.Name+" looks like a long-lived cloud credential. Replace it with GitHub OIDC federation and delete the key.")
		} else if sshKeySecret.MatchString(s.Name) {
			a.add("WM011", Medium, repo, "", "static|"+scope+"/"+s.Name,
				"Secret "+scope+"/"+s.Name+" looks like a long-lived SSH private key for a server. Anyone who can read it can log in to that host. Prefer short-lived access (for example AWS SSM or EC2 Instance Connect via OIDC), or at least keep the key in an environment with required reviewers and rotate it.")
		}
		if githubTokenSecret.MatchString(s.Name) && s.Name != "GITHUB_TOKEN" {
			a.add("WM019", Medium, repo, "", "pat|"+scope+"/"+s.Name,
				"Secret "+scope+"/"+s.Name+" looks like a GitHub personal access token. Whoever can read it acts as the token's owner on every repository the token reaches: the lateral-movement path stolen credentials give an attacker. Prefer GITHUB_TOKEN with scoped permissions (for example packages: write for GHCR) or a GitHub App installation token; otherwise use a fine-grained token limited to the target repositories, kept in an environment with required reviewers.")
		}
		if !s.UpdatedAt.IsZero() && s.UpdatedAt.Before(stale) {
			a.add("WM010", Low, repo, "", "stale|"+scope+"/"+s.Name,
				fmt.Sprintf("Secret %s/%s was last updated %s (older than %d days). If it was exposed in a past campaign it is still valid.", scope, s.Name, s.UpdatedAt.Format("2006-01-02"), a.o.StaleDays))
		}
	}
	for _, os := range a.s.OrgSecrets {
		check("", "org", model.Secret{Name: os.Name, UpdatedAt: os.UpdatedAt})
	}
	for _, r := range a.s.Repos {
		for _, s := range r.Secrets {
			check(r.FullName, r.FullName, s)
		}
		for _, e := range r.Environments {
			for _, s := range e.Secrets {
				check(r.FullName, r.FullName+"/env/"+e.Name, s)
			}
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
