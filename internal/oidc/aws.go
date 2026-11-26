package oidc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Verdict is a tri-state reachability result. Wardmap never turns something
// it cannot evaluate into "not reachable".
type Verdict int

// Verdict values.
const (
	NotReachable Verdict = iota
	Reachable
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case Reachable:
		return "reachable"
	case Unknown:
		return "needs-review"
	}
	return "not-reachable"
}

// Result explains a verdict.
type Result struct {
	Verdict Verdict
	Reason  string
}

// AWSTrust is a parsed IAM role trust policy, reduced to what matters for
// GitHub OIDC.
type AWSTrust struct {
	GitHub []awsStatement // Allow statements whose principal is GitHub OIDC
	// WildcardPrincipal is set when any Allow statement trusts "*" or
	// {"AWS":"*"} — the wfx-loot persistence pattern.
	WildcardPrincipal bool
	// HasDeny is set when a Deny statement targets the GitHub provider.
	HasDeny bool
}

type awsStatement struct {
	Sid        string
	Conditions []awsCond
}

type awsCond struct {
	Op     string // e.g. StringLike, ForAnyValue:StringEquals
	Key    string // claim name, e.g. sub
	RawKey string
	Values []string
}

// ParseAWSTrust parses a trust policy given either as a decoded object or as
// a (possibly URL-encoded) JSON string.
func ParseAWSTrust(doc map[string]any) (AWSTrust, error) {
	var t AWSTrust
	for _, st := range asList(doc["Statement"]) {
		m, ok := st.(map[string]any)
		if !ok {
			continue
		}
		effect, _ := m["Effect"].(string)
		if !actionAllowsWebIdentity(m["Action"]) && !actionAllowsAssume(m["Action"]) {
			continue
		}
		if isWildcardPrincipal(m["Principal"]) && strings.EqualFold(effect, "Allow") {
			t.WildcardPrincipal = true
		}
		if !principalIsGitHub(m["Principal"]) || !actionAllowsWebIdentity(m["Action"]) {
			continue
		}
		if strings.EqualFold(effect, "Deny") {
			t.HasDeny = true
			continue
		}
		s := awsStatement{}
		s.Sid, _ = m["Sid"].(string)
		cond, _ := m["Condition"].(map[string]any)
		ops := make([]string, 0, len(cond))
		for op := range cond {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			kv, ok := cond[op].(map[string]any)
			if !ok {
				return t, fmt.Errorf("condition operator %s is not an object", op)
			}
			keys := make([]string, 0, len(kv))
			for k := range kv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				c := awsCond{Op: op, RawKey: k, Values: asStrings(kv[k])}
				if strings.HasPrefix(strings.ToLower(k), "token.actions.githubusercontent.com:") {
					// IAM condition keys are case-insensitive; claim names are lower case.
					c.Key = strings.ToLower(k[len("token.actions.githubusercontent.com:"):])
				}
				s.Conditions = append(s.Conditions, c)
			}
		}
		t.GitHub = append(t.GitHub, s)
	}
	return t, nil
}

// DecodePolicy turns a policy value from AWS output into an object. IAM APIs
// return trust policies URL-encoded; the AWS CLI usually decodes them.
func DecodePolicy(v any) (map[string]any, error) {
	switch x := v.(type) {
	case map[string]any:
		return x, nil
	case string:
		s := x
		if strings.HasPrefix(s, "%7B") || strings.HasPrefix(s, "%7b") {
			d, err := url.QueryUnescape(s)
			if err != nil {
				return nil, err
			}
			s = d
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil, err
		}
		return m, nil
	}
	return nil, fmt.Errorf("unsupported policy type %T", v)
}

// Evaluate decides whether candidate c can assume the role.
func (t AWSTrust) Evaluate(c Candidate) Result {
	if len(t.GitHub) == 0 {
		return Result{NotReachable, "role does not trust GitHub OIDC"}
	}
	best := Result{NotReachable, "no statement admits this token"}
	for _, s := range t.GitHub {
		r := s.evaluate(c)
		if r.Verdict == Reachable {
			best = r
			break
		}
		if r.Verdict == Unknown {
			best = r
		}
	}
	if best.Verdict == Reachable && t.HasDeny {
		return Result{Unknown, best.Reason + "; a Deny statement also targets GitHub OIDC — review manually"}
	}
	return best
}

func (s awsStatement) evaluate(c Candidate) Result {
	reasons := []string{}
	for _, cond := range s.Conditions {
		if cond.Key == "" {
			return Result{Unknown, "condition on non-GitHub key " + cond.RawKey}
		}
		op := strings.TrimPrefix(strings.TrimPrefix(cond.Op, "ForAnyValue:"), "ForAllValues:")
		ignoreCase := strings.Contains(op, "IgnoreCase")
		op = strings.Replace(op, "IgnoreCase", "", 1)
		ifExists := strings.HasSuffix(op, "IfExists")
		op = strings.TrimSuffix(op, "IfExists")
		if _, present := c.Claims[cond.Key]; ifExists && !present {
			// ...IfExists conditions pass when the token lacks the claim.
			reasons = append(reasons, fmt.Sprintf("%s %s (claim absent)", cond.Op, cond.Key))
			continue
		}
		vals := cond.Values
		cand := c
		if ignoreCase {
			cand = lowerCandidate(c)
			vals = lowerAll(vals)
		}
		switch op {
		case "StringEquals", "StringLike":
			ok := false
			for _, v := range vals {
				if op == "StringEquals" && strings.ContainsAny(v, "*?") {
					// StringEquals treats wildcards literally; GitHub claim
					// values never contain them, so this cannot match.
					continue
				}
				if cand.Admits(cond.Key, v) {
					ok = true
					break
				}
			}
			if !ok {
				return Result{NotReachable, fmt.Sprintf("%s %s %v rejects %s", cond.Op, cond.Key, cond.Values, c.Label)}
			}
			reasons = append(reasons, fmt.Sprintf("%s %s %v", cond.Op, cond.Key, cond.Values))
		case "StringNotEquals", "StringNotLike":
			ok := true
			for _, v := range vals {
				if !cand.AdmitsNot(cond.Key, v) {
					ok = false
					break
				}
			}
			if !ok {
				return Result{NotReachable, fmt.Sprintf("%s %s %v rejects %s", cond.Op, cond.Key, cond.Values, c.Label)}
			}
		default:
			return Result{Unknown, "unsupported condition operator " + cond.Op}
		}
	}
	if len(reasons) == 0 {
		return Result{Reachable, "statement has no conditions on GitHub claims"}
	}
	return Result{Reachable, "admitted by " + strings.Join(reasons, " AND ")}
}

// SubPatterns returns every sub value pattern in the policy, for linting.
func (t AWSTrust) SubPatterns() (subs []string, hasAud bool, unconstrained bool) {
	for _, s := range t.GitHub {
		hasSub := false
		for _, c := range s.Conditions {
			switch c.Key {
			case "sub":
				hasSub = true
				subs = append(subs, c.Values...)
			case "aud":
				hasAud = true
			}
		}
		if !hasSub {
			unconstrained = true
		}
	}
	return
}

func lowerCandidate(c Candidate) Candidate {
	n := Candidate{Repo: c.Repo, Label: c.Label, Claims: map[string]string{}, Excluded: map[string][]string{}}
	for k, v := range c.Claims {
		n.Claims[k] = strings.ToLower(v)
	}
	for k, v := range c.Excluded {
		n.Excluded[k] = lowerAll(v)
	}
	return n
}

func lowerAll(xs []string) []string {
	o := make([]string, len(xs))
	for i, x := range xs {
		o[i] = strings.ToLower(x)
	}
	return o
}

func asList(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case nil:
		return nil
	default:
		return []any{x}
	}
}

func asStrings(v any) []string {
	var out []string
	for _, x := range asList(v) {
		switch s := x.(type) {
		case string:
			out = append(out, s)
		case bool:
			out = append(out, fmt.Sprint(s))
		}
	}
	return out
}

func principalIsGitHub(p any) bool {
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	for _, f := range asStrings(m["Federated"]) {
		if strings.HasSuffix(f, "token.actions.githubusercontent.com") {
			return true
		}
	}
	return false
}

func isWildcardPrincipal(p any) bool {
	if s, ok := p.(string); ok {
		return s == "*"
	}
	m, ok := p.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"AWS", "Federated"} {
		for _, v := range asStrings(m[k]) {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

func actionAllowsWebIdentity(a any) bool {
	for _, s := range asStrings(a) {
		l := strings.ToLower(s)
		if l == "*" || l == "sts:*" || l == "sts:assumerolewithwebidentity" {
			return true
		}
	}
	return false
}

func actionAllowsAssume(a any) bool {
	for _, s := range asStrings(a) {
		l := strings.ToLower(s)
		if l == "*" || l == "sts:*" || strings.HasPrefix(l, "sts:assumerole") {
			return true
		}
	}
	return false
}
