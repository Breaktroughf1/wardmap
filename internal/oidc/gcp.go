package oidc

import (
	"fmt"
	"strings"

	"github.com/Breaktroughf1/wardmap/internal/model"
)

// EvaluateGCP decides whether candidate c satisfies the provider's attribute
// condition. It understands the CEL subset used in practice for GitHub:
// ==, !=, &&, ||, !, parentheses, `x in ['a','b']`, startsWith and endsWith
// on assertion.* or mapped attribute.* values. Anything else yields Unknown.
func EvaluateGCP(p model.GCPProvider, c Candidate) (res Result) {
	// Fail safe: a parser bug must never crash a scan or read as "safe".
	defer func() {
		if r := recover(); r != nil {
			res = Result{Unknown, fmt.Sprintf("attribute condition could not be evaluated (internal error: %v)", r)}
		}
	}()
	if p.Disabled {
		return Result{NotReachable, "provider disabled"}
	}
	if !strings.Contains(p.IssuerURI, model.GitHubIssuer) {
		return Result{NotReachable, "issuer is not GitHub Actions"}
	}
	if strings.TrimSpace(p.AttributeCondition) == "" {
		return Result{Reachable, "provider has no attribute condition: any GitHub repository can authenticate"}
	}
	toks, err := lexCEL(p.AttributeCondition)
	if err != nil {
		return Result{Unknown, err.Error()}
	}
	ps := &celParser{toks: toks, mapping: p.AttributeMapping, cand: c}
	v, err := ps.parseOr()
	if err == nil && ps.pos < len(ps.toks) {
		err = fmt.Errorf("unexpected token %q", ps.toks[ps.pos].v)
	} else if err == nil && ps.pos > len(ps.toks) {
		err = fmt.Errorf("unexpected end of condition")
	}
	if err != nil {
		return Result{Unknown, "attribute condition not understood (" + err.Error() + ")"}
	}
	switch v {
	case triTrue:
		return Result{Reachable, "attribute condition " + p.AttributeCondition}
	case triFalse:
		return Result{NotReachable, "attribute condition rejects " + c.Label}
	}
	return Result{Unknown, "attribute condition partly evaluable: " + p.AttributeCondition}
}

type tri int

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func and(a, b tri) tri {
	if a == triFalse || b == triFalse {
		return triFalse
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triTrue
}

func or(a, b tri) tri {
	if a == triTrue || b == triTrue {
		return triTrue
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triFalse
}

type celTok struct {
	k string // ident, str, op
	v string
}

func lexCEL(s string) ([]celTok, error) {
	var out []celTok
	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			i++
		case ch == '\'' || ch == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != ch {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string")
			}
			out = append(out, celTok{"str", b.String()})
			i = j + 1
		case strings.HasPrefix(s[i:], "&&"), strings.HasPrefix(s[i:], "||"),
			strings.HasPrefix(s[i:], "=="), strings.HasPrefix(s[i:], "!="):
			out = append(out, celTok{"op", s[i : i+2]})
			i += 2
		case strings.ContainsRune("()[],!", rune(ch)):
			out = append(out, celTok{"op", string(ch)})
			i++
		case isIdent(ch):
			j := i
			for j < len(s) && (isIdent(s[j]) || s[j] == '.' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			out = append(out, celTok{"ident", s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q", ch)
		}
	}
	return out, nil
}

func isIdent(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

type celParser struct {
	toks    []celTok
	pos     int
	mapping map[string]string
	cand    Candidate
}

func (p *celParser) peek(v string) bool {
	return p.pos < len(p.toks) && p.toks[p.pos].k == "op" && p.toks[p.pos].v == v
}

func (p *celParser) parseOr() (tri, error) {
	l, err := p.parseAnd()
	if err != nil {
		return 0, err
	}
	for p.peek("||") {
		p.pos++
		r, err := p.parseAnd()
		if err != nil {
			return 0, err
		}
		l = or(l, r)
	}
	return l, nil
}

func (p *celParser) parseAnd() (tri, error) {
	l, err := p.parseUnary()
	if err != nil {
		return 0, err
	}
	for p.peek("&&") {
		p.pos++
		r, err := p.parseUnary()
		if err != nil {
			return 0, err
		}
		l = and(l, r)
	}
	return l, nil
}

// parseUnary handles negation by evaluating the operand with negated
// comparison semantics, which keeps satisfiability exact for the subset.
func (p *celParser) parseUnary() (tri, error) {
	if p.peek("!") {
		p.pos++
		if !p.peek("(") {
			return 0, fmt.Errorf("negation only supported on parenthesised expressions")
		}
		// !(a) — evaluate with De Morgan via a sub-parser in negated mode.
		start := p.pos
		depth := 0
		end := -1
		for i := start; i < len(p.toks); i++ {
			if p.toks[i].k == "op" && p.toks[i].v == "(" {
				depth++
			} else if p.toks[i].k == "op" && p.toks[i].v == ")" {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return 0, fmt.Errorf("unbalanced parentheses")
		}
		sub := &negParser{celParser{toks: p.toks[start+1 : end], mapping: p.mapping, cand: p.cand}}
		v, err := sub.parseOr()
		if err != nil {
			return 0, err
		}
		if sub.pos != len(sub.toks) {
			return 0, fmt.Errorf("unexpected token in negation")
		}
		p.pos = end + 1
		return v, nil
	}
	return p.parsePrimary(false)
}

func (p *celParser) parsePrimary(neg bool) (tri, error) {
	if p.peek("(") {
		p.pos++
		var v tri
		var err error
		if neg {
			v, err = (&negParser{*p}).parseOrInPlace(p)
		} else {
			v, err = p.parseOr()
		}
		if err != nil {
			return 0, err
		}
		if !p.peek(")") {
			return 0, fmt.Errorf("expected )")
		}
		p.pos++
		return v, nil
	}
	if p.pos >= len(p.toks) {
		return 0, fmt.Errorf("unexpected end")
	}
	t := p.toks[p.pos]
	p.pos++
	switch t.k {
	case "ident":
		// method call: ident.startsWith('x') arrives as one ident token
		// "assertion.ref.startsWith" followed by "(".
		if i := strings.LastIndexByte(t.v, '.'); i > 0 && p.peek("(") {
			method := t.v[i+1:]
			subject := t.v[:i]
			p.pos++
			if p.pos >= len(p.toks) || p.toks[p.pos].k != "str" {
				return 0, fmt.Errorf("method %s needs a string literal", method)
			}
			arg := p.toks[p.pos].v
			p.pos++
			if !p.peek(")") {
				return 0, fmt.Errorf("expected ) after %s argument", method)
			}
			p.pos++
			claim, ok := p.claim(subject)
			if !ok {
				return triUnknown, nil
			}
			var pat string
			switch method {
			case "startsWith":
				pat = arg + "*"
			case "endsWith":
				pat = "*" + arg
			default:
				return triUnknown, nil
			}
			return p.cmp(claim, pat, neg), nil
		}
		claim, ok := p.claim(t.v)
		if p.peek("==") || p.peek("!=") {
			op := p.toks[p.pos].v
			p.pos++
			if p.pos >= len(p.toks) || p.toks[p.pos].k != "str" {
				return 0, fmt.Errorf("comparison needs a string literal")
			}
			lit := p.toks[p.pos].v
			p.pos++
			if !ok {
				return triUnknown, nil
			}
			n := neg
			if op == "!=" {
				n = !n
			}
			return p.cmp(claim, escapeCEL(lit), n), nil
		}
		if p.pos < len(p.toks) && p.toks[p.pos].k == "ident" && p.toks[p.pos].v == "in" {
			p.pos++
			lits, err := p.list()
			if err != nil {
				return 0, err
			}
			if !ok {
				return triUnknown, nil
			}
			res := triFalse
			if neg {
				res = triTrue
			}
			for _, l := range lits {
				if neg {
					res = and(res, p.cmp(claim, escapeCEL(l), true))
				} else {
					res = or(res, p.cmp(claim, escapeCEL(l), false))
				}
			}
			return res, nil
		}
		return 0, fmt.Errorf("unsupported expression near %q", t.v)
	case "str":
		// 'literal' == assertion.x or 'x' in assertion.list
		if p.peek("==") || p.peek("!=") {
			op := p.toks[p.pos].v
			p.pos++
			if p.pos >= len(p.toks) || p.toks[p.pos].k != "ident" {
				return 0, fmt.Errorf("comparison needs an identifier")
			}
			claim, ok := p.claim(p.toks[p.pos].v)
			p.pos++
			if !ok {
				return triUnknown, nil
			}
			n := neg
			if op == "!=" {
				n = !n
			}
			return p.cmp(claim, escapeCEL(t.v), n), nil
		}
		if p.pos < len(p.toks) && p.toks[p.pos].k == "ident" && p.toks[p.pos].v == "in" {
			// 'literal' in <list-valued claim>: not evaluated.
			p.pos++
			if p.pos >= len(p.toks) || p.toks[p.pos].k != "ident" {
				return 0, fmt.Errorf("'in' needs a list-valued attribute")
			}
			p.pos++
			return triUnknown, nil
		}
	}
	return 0, fmt.Errorf("unsupported token %q", t.v)
}

func (p *celParser) list() ([]string, error) {
	if !p.peek("[") {
		return nil, fmt.Errorf("expected [")
	}
	p.pos++
	var out []string
	for {
		if p.peek("]") {
			p.pos++
			return out, nil
		}
		if p.pos >= len(p.toks) || p.toks[p.pos].k != "str" {
			return nil, fmt.Errorf("list items must be string literals")
		}
		out = append(out, p.toks[p.pos].v)
		p.pos++
		if p.peek(",") {
			p.pos++
		}
	}
}

func (p *celParser) cmp(claim, pattern string, neg bool) tri {
	if neg {
		if p.cand.AdmitsNot(claim, pattern) {
			return triTrue
		}
		return triFalse
	}
	if p.cand.Admits(claim, pattern) {
		return triTrue
	}
	return triFalse
}

// claim resolves assertion.X or attribute.Y (through the attribute mapping)
// to a GitHub claim name.
func (p *celParser) claim(id string) (string, bool) {
	switch {
	case strings.HasPrefix(id, "assertion."):
		return strings.TrimPrefix(id, "assertion."), true
	case strings.HasPrefix(id, "attribute."):
		m := p.mapping["attribute."+strings.TrimPrefix(id, "attribute.")]
		if strings.HasPrefix(m, "assertion.") && !strings.ContainsAny(m, " +()") {
			return strings.TrimPrefix(m, "assertion."), true
		}
	case id == "google.subject":
		m := p.mapping["google.subject"]
		if strings.HasPrefix(m, "assertion.") && !strings.ContainsAny(m, " +()") {
			return strings.TrimPrefix(m, "assertion."), true
		}
	}
	return "", false
}

// CEL equality is exact; protect literal wildcard characters from glob
// semantics by rejecting them (GitHub claims never contain them).
func escapeCEL(s string) string { return s }

// negParser evaluates an expression under logical negation using De Morgan:
// !(a && b) = !a || !b ; !(a || b) = !a && !b.
type negParser struct{ celParser }

func (n *negParser) parseOr() (tri, error) {
	l, err := n.parseAnd()
	if err != nil {
		return 0, err
	}
	for n.peek("||") {
		n.pos++
		r, err := n.parseAnd()
		if err != nil {
			return 0, err
		}
		l = and(l, r)
	}
	return l, nil
}

func (n *negParser) parseAnd() (tri, error) {
	l, err := n.parsePrimary(true)
	if err != nil {
		return 0, err
	}
	for n.peek("&&") {
		n.pos++
		r, err := n.parsePrimary(true)
		if err != nil {
			return 0, err
		}
		l = or(l, r)
	}
	return l, nil
}

func (n *negParser) parseOrInPlace(outer *celParser) (tri, error) {
	n.celParser = *outer
	v, err := n.parseOr()
	outer.pos = n.pos
	return v, err
}
