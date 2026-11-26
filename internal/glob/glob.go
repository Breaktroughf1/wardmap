// Package glob implements the wildcard semantics used by AWS IAM StringLike
// conditions ('*' any run of characters, '?' exactly one character) and the
// one operation Wardmap needs most: deciding whether two patterns can match a
// common string.
//
// Wardmap represents "values an attacker can choose" (for example any branch
// name) as '*' inside a candidate OIDC subject, and trust conditions as
// patterns. A role is reachable when the two patterns overlap.
package glob

// Match reports whether s matches pattern p.
func Match(p, s string) bool {
	return Overlap(p, escapeLiteral(s))
}

// escapeLiteral is the identity for strings without wildcards. Literal '*' or
// '?' in a value are vanishingly rare in OIDC claims and GitHub forbids them
// in ref names, so we treat them as wildcards rather than add escaping.
func escapeLiteral(s string) string { return s }

// Overlap reports whether some string matches both patterns a and b.
func Overlap(a, b string) bool {
	ar, br := []rune(a), []rune(b)
	n, m := len(ar), len(br)
	memo := make([]int8, (n+1)*(m+1)) // 0 unknown, 1 true, 2 false
	var f func(i, j int) bool
	f = func(i, j int) bool {
		k := i*(m+1) + j
		if memo[k] != 0 {
			return memo[k] == 1
		}
		res := false
		switch {
		case i == n && j == m:
			res = true
		case i < n && ar[i] == '*':
			// a's star matches empty, or absorbs b's next symbol.
			res = f(i+1, j) || (j < m && f(i, j+1))
		case j < m && br[j] == '*':
			res = f(i, j+1) || (i < n && f(i+1, j))
		case i < n && j < m:
			if ar[i] == br[j] || ar[i] == '?' || br[j] == '?' {
				res = f(i+1, j+1)
			}
		}
		if res {
			memo[k] = 1
		} else {
			memo[k] = 2
		}
		return res
	}
	return f(0, 0)
}

// HasWildcard reports whether p contains '*' or '?'.
func HasWildcard(p string) bool {
	for _, r := range p {
		if r == '*' || r == '?' {
			return true
		}
	}
	return false
}
