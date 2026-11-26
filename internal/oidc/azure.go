package oidc

import (
	"regexp"
	"strings"

	"github.com/Breaktroughf1/wardmap/internal/model"
)

// flexible FIC expressions we can evaluate: claims['sub'] matches '...'
var ficExprRe = regexp.MustCompile(`^\s*claims\[['"]([a-z_]+)['"]\]\s+(matches|eq)\s+'([^']*)'\s*$`)

// EvaluateAzure decides whether candidate c satisfies federated credential f.
func EvaluateAzure(f model.AzureFIC, c Candidate) Result {
	if strings.TrimSuffix(f.Issuer, "/") != "https://"+model.GitHubIssuer {
		return Result{NotReachable, "issuer is not GitHub Actions"}
	}
	if f.ClaimsMatching != "" {
		var terms []string
		for _, t := range strings.Split(f.ClaimsMatching, " and ") {
			terms = append(terms, t)
		}
		for _, t := range terms {
			m := ficExprRe.FindStringSubmatch(t)
			if m == nil {
				return Result{Unknown, "claims matching expression not understood: " + f.ClaimsMatching}
			}
			if !c.Admits(m[1], m[3]) {
				return Result{NotReachable, "expression rejects " + c.Label}
			}
		}
		return Result{Reachable, "flexible credential expression " + f.ClaimsMatching}
	}
	if f.Subject == "" {
		return Result{Unknown, "credential has neither subject nor expression"}
	}
	// Entra compares the subject exactly (no wildcards).
	if strings.ContainsAny(f.Subject, "*?") {
		return Result{NotReachable, "subject contains a wildcard, which Entra treats literally"}
	}
	if c.Admits("sub", f.Subject) {
		return Result{Reachable, "subject " + f.Subject}
	}
	return Result{NotReachable, "subject " + f.Subject + " rejects " + c.Label}
}
