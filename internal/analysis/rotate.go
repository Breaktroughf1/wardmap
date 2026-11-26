package analysis

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// RotationStep is one item in an ordered rotation runbook.
type RotationStep struct {
	Order  int    `json:"order"`
	Phase  string `json:"phase"`
	Target string `json:"target"`
	Action string `json:"action"`
}

var (
	registryRe = regexp.MustCompile(`(?i)(NPM|PYPI|TWINE|CARGO|RUBYGEMS|GEM_HOST|NUGET|MAVEN|SONATYPE|OSSRH|DOCKER|GHCR|REGISTRY|PUB_DEV|HEX|COCOAPODS)`)
	githubRe   = regexp.MustCompile(`(?i)(GH_|GITHUB_|_PAT$|^PAT_|BOT_TOKEN|APP_PRIVATE_KEY)`)
	cloudRe    = regexp.MustCompile(`(?i)(AWS_|AZURE_|ARM_|GCP_|GOOGLE_|GCLOUD|DIGITALOCEAN|DO_TOKEN|CLOUDFLARE|VERCEL|NETLIFY|HEROKU)`)
)

// RotatePlan derives an ordered rotation runbook for the given compromised
// repositories (all repositories when repos is empty). The order follows
// incident-response practice for CI credential theft: remove attacker
// persistence, then tighten cloud trust, then credentials that let the attacker publish or
// re-enter (registries, GitHub), then cloud keys, then application secrets.
func RotatePlan(res Result, repos []string) []RotationStep {
	want := map[string]bool{}
	for _, r := range repos {
		want[ActorFor(r)] = true
	}
	phaseOrder := map[string]int{"0-persistence": 0, "1-cloud-trust": 1, "2-registry": 2, "3-github": 3, "4-cloud-key": 4, "5-app": 5}
	type item struct{ phase, target, action string }
	seen := map[string]bool{}
	var items []item
	for _, f := range res.Findings {
		if f.RuleID == "WM012" || f.RuleID == "WM006" || f.RuleID == "WM013" {
			k := "trust|" + f.Key
			if !seen[k] {
				seen[k] = true
				items = append(items, item{"0-persistence", f.Key, "Remove attacker persistence or internet-wide trust first: " + f.Message})
			}
		}
	}
	for _, e := range res.Edges {
		if e.Verdict != "reachable" || (len(want) > 0 && !want[e.From]) {
			continue
		}
		if seen[e.To] {
			continue
		}
		seen[e.To] = true
		switch e.Kind {
		case "secret":
			name := e.To[strings.LastIndex(e.To, "/")+1:]
			switch {
			case registryRe.MatchString(name):
				items = append(items, item{"2-registry", e.To, "Revoke and reissue the package-registry token, then audit recent publishes for unexpected versions."})
			case githubRe.MatchString(name):
				items = append(items, item{"3-github", e.To, "Revoke the GitHub token/key, review its audit log, and reissue with the narrowest scope."})
			case cloudRe.MatchString(name):
				items = append(items, item{"4-cloud-key", e.To, "Deactivate the cloud key, review provider audit logs for its use, and replace with OIDC federation."})
			default:
				items = append(items, item{"5-app", e.To, "Rotate the secret at its issuer and update it in GitHub."})
			}
		case "aws-role", "azure-app", "gcp-provider":
			items = append(items, item{"1-cloud-trust", e.To, fmt.Sprintf("Review sessions issued to this identity (via %s); tighten trust to protected refs or gated environments; revoke active sessions.", e.Via)})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if phaseOrder[items[i].phase] != phaseOrder[items[j].phase] {
			return phaseOrder[items[i].phase] < phaseOrder[items[j].phase]
		}
		return items[i].target < items[j].target
	})
	out := make([]RotationStep, len(items))
	for i, it := range items {
		out[i] = RotationStep{Order: i + 1, Phase: it.phase[2:], Target: it.target, Action: it.action}
	}
	return out
}
