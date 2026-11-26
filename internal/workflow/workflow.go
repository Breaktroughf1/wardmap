// Package workflow extracts the security-relevant facts from a GitHub Actions
// workflow file: triggers, OIDC permission, environments, secret references,
// actions that receive secrets, and cloud login steps. It deliberately does
// not re-implement general workflow linting (use zizmor for that).
package workflow

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Breaktroughf1/wardmap/internal/model"
)

var (
	secretDotRe     = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)
	secretIndexRe   = regexp.MustCompile(`secrets\[\s*['"]([^'"]+)['"]\s*\]`)
	secretsDumpRe   = regexp.MustCompile(`toJSON\(\s*secrets\s*\)`)
	contextDumpRe   = regexp.MustCompile(`toJSON\(\s*(secrets|vars)\s*\)`)
	urlRe           = regexp.MustCompile(`https?://[^\s"'<>()]+`)
	ipv4Re          = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)
	shaPinRe        = regexp.MustCompile(`@[0-9a-f]{40}$`)
	prHeadRefRe     = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/`)
	firstPartyOwner = map[string]bool{"actions": true, "github": true}
)

// Parse parses one workflow file. Parse errors are returned inside the
// Workflow so a single malformed file does not hide the rest of the estate.
func Parse(path string, data []byte) model.Workflow {
	w := model.Workflow{Path: path}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		w.ParseError = err.Error()
		return w
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		w.ParseError = "workflow is not a mapping"
		return w
	}
	doc := root.Content[0]
	w.Endpoints = endpoints(string(data))
	onNode := mapGet(doc, "on")
	if onNode == nil {
		onNode = mapGet(doc, "true") // YAML 1.1 parsers turn `on` into true
	}
	w.Triggers, w.PushBranches = triggers(onNode)
	topIDToken := idTokenWrite(mapGet(doc, "permissions"))
	topEnvSecrets := secretRefs(mapGet(doc, "env"))

	jobs := mapGet(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		w.ParseError = "no jobs"
		return w
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		id := jobs.Content[i].Value
		jn := jobs.Content[i+1]
		if jn.Kind != yaml.MappingNode {
			continue
		}
		j := model.Job{ID: id}
		if p := mapGet(jn, "permissions"); p != nil {
			j.IDTokenWrite = idTokenWrite(p)
		} else {
			j.IDTokenWrite = topIDToken
		}
		if e := mapGet(jn, "environment"); e != nil {
			if e.Kind == yaml.ScalarNode {
				j.Environment = e.Value
			} else if n := mapGet(e, "name"); n != nil {
				j.Environment = n.Value
			}
		}
		all := nodeText(jn)
		if secretsDumpRe.MatchString(all) {
			j.InheritsAll = true
		}
		if contextDumpRe.MatchString(all) {
			j.DumpsSecrets = true
		}
		if s := mapGet(jn, "secrets"); s != nil && s.Kind == yaml.ScalarNode && s.Value == "inherit" {
			j.InheritsAll = true
		}
		j.SecretsUsed = uniq(append(secretRefs(jn), topEnvSecrets...))
		jobEnvSecrets := uniq(append(secretRefs(mapGet(jn, "env")), topEnvSecrets...))

		if u := mapGet(jn, "uses"); u != nil { // reusable workflow call
			su := stepUse(u.Value)
			su.SecretsPass = secretRefs(mapGet(jn, "secrets"))
			if j.InheritsAll {
				su.SecretsPass = append(su.SecretsPass, "*")
			}
			j.Steps = append(j.Steps, su)
		}
		if steps := mapGet(jn, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			for _, st := range steps.Content {
				u := mapGet(st, "uses")
				if u == nil {
					continue
				}
				su := stepUse(u.Value)
				passed := append(secretRefs(mapGet(st, "with")), secretRefs(mapGet(st, "env"))...)
				passed = append(passed, jobEnvSecrets...)
				su.SecretsPass = uniq(passed)
				j.Steps = append(j.Steps, su)
				if cl, ok := cloudLogin(u.Value, mapGet(st, "with")); ok {
					j.CloudLogins = append(j.CloudLogins, cl)
				}
				if strings.HasPrefix(u.Value, "actions/checkout@") {
					if r := mapGet(mapGet(st, "with"), "ref"); r != nil && prHeadRefRe.MatchString(r.Value) {
						j.ChecksOutPR = true
					}
				}
			}
		}
		w.Jobs = append(w.Jobs, j)
	}
	return w
}

// endpoints extracts URLs and IPv4 addresses (deduplicated, sorted). Common
// documentation hosts are kept: filtering is left to IOC patterns.
func endpoints(text string) []string {
	var out []string
	out = append(out, urlRe.FindAllString(text, -1)...)
	out = append(out, ipv4Re.FindAllString(text, -1)...)
	return uniq(out)
}

func triggers(n *yaml.Node) (trig []string, push []string) {
	if n == nil {
		return nil, nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		trig = []string{n.Value}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			trig = append(trig, c.Value)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			name := n.Content[i].Value
			trig = append(trig, name)
			if name == "push" {
				if b := mapGet(n.Content[i+1], "branches"); b != nil {
					for _, c := range b.Content {
						push = append(push, c.Value)
					}
				}
			}
		}
	}
	for _, t := range trig {
		if t == "push" && len(push) == 0 {
			push = []string{"*"}
		}
	}
	sort.Strings(trig)
	return trig, push
}

func idTokenWrite(p *yaml.Node) bool {
	if p == nil {
		return false
	}
	if p.Kind == yaml.ScalarNode {
		return p.Value == "write-all"
	}
	v := mapGet(p, "id-token")
	return v != nil && v.Value == "write"
}

func stepUse(uses string) model.StepUse {
	su := model.StepUse{Uses: uses}
	switch {
	case strings.HasPrefix(uses, "./"):
		su.Pinned = true // local action, same commit
	case strings.HasPrefix(uses, "docker://"):
		su.ThirdParty = true
		su.Pinned = strings.Contains(uses, "@sha256:")
	default:
		owner := uses
		if i := strings.IndexByte(owner, '/'); i >= 0 {
			owner = owner[:i]
		}
		su.ThirdParty = !firstPartyOwner[strings.ToLower(owner)]
		su.Pinned = shaPinRe.MatchString(uses)
	}
	return su
}

func cloudLogin(uses string, with *yaml.Node) (model.CloudLogin, bool) {
	name := uses
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	get := func(k string) string {
		if v := mapGet(with, k); v != nil {
			return v.Value
		}
		return ""
	}
	switch strings.ToLower(name) {
	case "aws-actions/configure-aws-credentials":
		return model.CloudLogin{Provider: "aws", Target: get("role-to-assume"), UsesOIDC: get("aws-access-key-id") == "" && get("role-to-assume") != ""}, true
	case "azure/login":
		return model.CloudLogin{Provider: "azure", Target: get("client-id"), UsesOIDC: get("creds") == "" && get("client-id") != ""}, true
	case "google-github-actions/auth":
		return model.CloudLogin{Provider: "gcp", Target: get("workload_identity_provider"), UsesOIDC: get("credentials_json") == "" && get("workload_identity_provider") != ""}, true
	}
	return model.CloudLogin{}, false
}

func secretRefs(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	s := nodeText(n)
	var out []string
	for _, m := range secretDotRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	for _, m := range secretIndexRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return uniq(filterToken(out))
}

func filterToken(xs []string) []string {
	out := xs[:0]
	for _, x := range xs {
		if x != "GITHUB_TOKEN" {
			out = append(out, x)
		}
	}
	return out
}

func nodeText(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		return fmt.Sprint(n.Value)
	}
	return string(b)
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func uniq(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	m := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
