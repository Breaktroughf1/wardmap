// Package oidc predicts the GitHub Actions OIDC claims an attacker can obtain
// and decides whether cloud trust configuration (AWS IAM role trust policies,
// Entra federated identity credentials, GCP workload identity providers)
// accepts them.
//
// Threat model: an attacker holds a credential with write access to a
// repository (a stolen PAT or a hijacked account, as in the wfx-loot and
// GhostAction campaigns). With write access they can push a new branch or tag
// containing a new workflow that requests `id-token: write`, open a
// same-repository pull request, or reference an environment that does not yet
// exist (GitHub creates it on first use with no protection). They cannot push
// to protected branches or bypass required reviewers on an environment.
package oidc

import (
	"strconv"
	"strings"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/glob"
	"github.com/Breaktroughf1/wardmap/internal/model"
)

// Slot marks the attacker-chosen part of a claim value.
const Slot = "*"

// ExternalOwner is a synthetic repository owner used to test whether trust
// admits repositories outside the estate (any GitHub user).
const ExternalOwner = "wardmap-external-attacker"

// Candidate is a family of OIDC tokens an attacker can mint.
type Candidate struct {
	Repo  string // owner/name, or ExternalOwner/* for the external probe
	Label string // human description, e.g. "any unprotected branch"
	// Claims holds claim values, with '*' where the attacker chooses.
	Claims map[string]string
	// Excluded holds, per claim, concrete values the attacker cannot reach
	// even though they match the wildcard (protected branches, gated envs).
	Excluded map[string][]string
}

// Admits reports whether the candidate can produce a value of claim that
// matches pattern (IAM StringLike semantics; a pattern without wildcards is
// an exact match).
func (c Candidate) Admits(claim, pattern string) bool {
	v, ok := c.Claims[claim]
	if !ok {
		// Claim absent from the token: only a pattern that accepts anything
		// could be considered satisfied, and IAM treats absent keys as
		// non-matching, so report false.
		return false
	}
	if !glob.Overlap(pattern, v) {
		return false
	}
	if !glob.HasWildcard(pattern) {
		for _, x := range c.Excluded[claim] {
			if glob.Match(x, pattern) {
				return false
			}
		}
	}
	return true
}

// AdmitsNot reports whether the candidate can produce a value of claim that
// does NOT match pattern.
func (c Candidate) AdmitsNot(claim, pattern string) bool {
	v, ok := c.Claims[claim]
	if !ok {
		return true
	}
	if !glob.HasWildcard(v) {
		return !glob.Match(pattern, v)
	}
	return !(pattern == "*" || pattern == v)
}

// ImmutableCutoff is when GitHub made immutable subject claims the default
// for new repositories (and for repositories renamed or transferred later).
var ImmutableCutoff = time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)

// SubPrefixes returns the repo segment(s) the repository's sub claims may
// start with. Fail safe: when the format cannot be determined, both the
// name-based and the immutable (ID-based) forms are evaluated.
func SubPrefixes(r model.Repo) []string {
	owner, name := r.FullName, ""
	if i := strings.IndexByte(r.FullName, '/'); i >= 0 {
		owner, name = r.FullName[:i], r.FullName[i+1:]
	}
	legacy := "repo:" + r.FullName
	immutable := "repo:" + owner + "@" + idOrSlot(r.OwnerID) + "/" + name + "@" + idOrSlot(r.RepoID)
	if p := strings.TrimSpace(r.SubClaimPrefix); p != "" {
		if strings.HasPrefix(p, "repo:") {
			return []string{p}
		}
		return []string{"repo:" + p, legacy, immutable}
	}
	if (r.ImmutableSubject != nil && *r.ImmutableSubject) || (!r.CreatedAt.IsZero() && !r.CreatedAt.Before(ImmutableCutoff)) {
		return []string{immutable}
	}
	return []string{legacy, immutable}
}

// Candidates enumerates the token families an attacker with write access to
// repo can mint, in every sub format the repository may use.
func Candidates(repo model.Repo) []Candidate {
	prefixes := SubPrefixes(repo)
	var out []Candidate
	for _, p := range prefixes {
		cs := candidatesFor(repo, p)
		if len(prefixes) > 1 && strings.Contains(p, "@") {
			for i := range cs {
				cs[i].Label += " [immutable sub format]"
			}
		}
		out = append(out, cs...)
	}
	return out
}

func candidatesFor(repo model.Repo, prefix string) []Candidate {
	protectedBranches := repo.ProtectedBranches
	owner := repo.FullName
	if i := strings.IndexByte(owner, '/'); i >= 0 {
		owner = owner[:i]
	}
	vis := "public"
	if repo.Private {
		vis = "private"
	}
	base := func() map[string]string {
		return map[string]string{
			"repository":            repo.FullName,
			"repository_owner":      owner,
			"repository_visibility": vis,
			"repository_id":         idOrSlot(repo.RepoID),
			"repository_owner_id":   idOrSlot(repo.OwnerID),
			"actor":                 Slot,
			"actor_id":              Slot,
			"workflow":              Slot,
			"event_name":            Slot,
			"run_attempt":           Slot,
			"aud":                   Slot, // the requester chooses the audience
			"iss":                   "https://" + model.GitHubIssuer,
		}
	}
	tpl := repo.OIDCSubTemplate
	var out []Candidate

	mk := func(label, context string, extra map[string]string, exclVals []string, excl func(string) (string, map[string]string)) {
		cl := base()
		for k, v := range extra {
			cl[k] = v
		}
		cl["context"] = context
		cl["sub"] = RenderSub(tpl, prefix, cl)
		c := Candidate{Repo: repo.FullName, Label: label, Claims: cl, Excluded: map[string][]string{}}
		for _, x := range exclVals {
			ctx, ex := excl(x)
			ecl := base()
			for k, v := range ex {
				ecl[k] = v
			}
			ecl["context"] = ctx
			for k, v := range ecl {
				if cl[k] != v && glob.HasWildcard(cl[k]) {
					c.Excluded[k] = append(c.Excluded[k], v)
				}
			}
			c.Excluded["sub"] = append(c.Excluded["sub"], RenderSub(tpl, prefix, ecl))
		}
		out = append(out, c)
	}

	jwr := repo.FullName + "/.github/workflows/*@"
	branchClaims := func(b string) (string, map[string]string) {
		ref := "refs/heads/" + b
		return "ref:" + ref, map[string]string{"ref": ref, "ref_type": "branch",
			"job_workflow_ref": jwr + ref, "workflow_ref": jwr + ref}
	}
	ctx, extra := branchClaims(Slot)
	mk("any unprotected branch (new branch + new workflow)", ctx, extra, protectedBranches, branchClaims)

	tagRef := "refs/tags/" + Slot
	mk("any tag", "ref:"+tagRef, map[string]string{"ref": tagRef, "ref_type": "tag",
		"job_workflow_ref": jwr + tagRef, "workflow_ref": jwr + tagRef}, nil, nil)

	// Environments: any name not already gated. Referencing a missing
	// environment creates it with no protection rules.
	var gated []string
	for _, e := range repo.Environments {
		if EnvironmentGated(e, protectedBranches) {
			gated = append(gated, e.Name)
		}
	}
	envClaims := func(n string) (string, map[string]string) {
		ref := "refs/heads/" + Slot
		return "environment:" + n, map[string]string{"environment": n, "ref": ref, "ref_type": "branch",
			"job_workflow_ref": jwr + ref, "workflow_ref": jwr + ref}
	}
	ctx, extra = envClaims(Slot)
	mk("any ungated environment (existing or auto-created)", ctx, extra, gated, envClaims)

	// Jobs on attacker branches never carry a protected branch's ref.
	for i := range out {
		if out[i].Claims["ref_type"] != "branch" {
			continue
		}
		for _, b := range protectedBranches {
			ref := "refs/heads/" + b
			out[i].Excluded["ref"] = append(out[i].Excluded["ref"], ref)
			out[i].Excluded["job_workflow_ref"] = append(out[i].Excluded["job_workflow_ref"], jwr+ref)
			out[i].Excluded["workflow_ref"] = append(out[i].Excluded["workflow_ref"], jwr+ref)
		}
	}

	prRef := "refs/pull/" + Slot + "/merge"
	mk("same-repository pull request", "pull_request", map[string]string{"ref": prRef, "event_name": "pull_request",
		"head_ref": Slot, "base_ref": Slot, "job_workflow_ref": jwr + prRef, "workflow_ref": jwr + prRef}, nil, nil)
	return out
}

// TemplateProbe models a token from repo whose custom OIDC subject template
// could not be read: the sub claim may take any form that mentions the
// repository. It is only used to turn a "not reachable" into "needs review".
func TemplateProbe(repo model.Repo) Candidate {
	c := ExternalCandidate()
	owner := repo.FullName
	if i := strings.IndexByte(owner, '/'); i >= 0 {
		owner = owner[:i]
	}
	c.Repo = repo.FullName
	c.Label = "unknown OIDC subject template"
	c.Claims["repository"] = repo.FullName
	c.Claims["repository_owner"] = owner
	// Owner and name, with anything (such as immutable IDs) around them.
	name := strings.TrimPrefix(repo.FullName, owner+"/")
	c.Claims["sub"] = Slot + owner + Slot + "/" + name + Slot
	return c
}

func idOrSlot(id int64) string {
	if id > 0 {
		return strconv.FormatInt(id, 10)
	}
	return Slot
}

// ExternalCandidates models tokens from repositories outside the estate, in
// both sub formats.
func ExternalCandidates() []Candidate {
	legacy := ExternalCandidate()
	immutable := ExternalCandidate()
	immutable.Label += " [immutable sub format]"
	immutable.Claims["sub"] = "repo:" + ExternalOwner + "@" + Slot + "/" + Slot + "@" + Slot + ":" + Slot
	return []Candidate{legacy, immutable}
}

// ExternalCandidate models a token minted from a repository the estate does
// not own, to detect trust that admits arbitrary GitHub users.
func ExternalCandidate() Candidate {
	r := ExternalOwner + "/" + Slot
	cl := map[string]string{
		"repository": r, "repository_owner": ExternalOwner, "repository_visibility": Slot,
		"repository_id": Slot, "repository_owner_id": Slot, "actor": Slot, "actor_id": Slot,
		"workflow": Slot, "event_name": Slot, "ref": Slot, "ref_type": Slot, "environment": Slot,
		"job_workflow_ref": r + "/.github/workflows/*@*", "workflow_ref": r + "/.github/workflows/*@*",
		"context": Slot, "aud": Slot, "iss": "https://" + model.GitHubIssuer,
	}
	cl["sub"] = "repo:" + r + ":" + Slot
	return Candidate{Repo: r, Label: "any GitHub repository outside this estate", Claims: cl, Excluded: map[string][]string{}}
}

// EnvironmentGated reports whether an attacker with write access cannot run
// a job in environment e unaided.
func EnvironmentGated(e model.Environment, protectedBranches []string) bool {
	if e.RequiredReviewers {
		return true
	}
	switch e.BranchPolicy {
	case model.BranchPolicyProtected:
		return true
	case model.BranchPolicyCustom:
		for _, p := range e.BranchPatterns {
			if glob.HasWildcard(p) {
				return false
			}
			if !contains(protectedBranches, p) {
				return false
			}
		}
		return true
	}
	return false
}

// RenderSub renders the sub claim using the repository's OIDC subject
// template (include_claim_keys). prefix is the repo segment ("repo:o/r", or
// "repo:o@ID/r@ID" for immutable subjects). GitHub always uses it for the
// "repo" key, and the default template is prefix + ":" + context.
func RenderSub(keys []string, prefix string, claims map[string]string) string {
	if len(keys) == 0 {
		return prefix + ":" + claims["context"]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		switch k {
		case "context":
			parts = append(parts, claims["context"])
		case "repo":
			parts = append(parts, prefix)
		default:
			v, ok := claims[k]
			if !ok {
				v = ""
			}
			parts = append(parts, k+":"+v)
		}
	}
	return strings.Join(parts, ":")
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
