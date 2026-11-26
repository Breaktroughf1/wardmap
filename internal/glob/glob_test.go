package glob

import "testing"

func TestOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"repo:o/r:ref:refs/heads/main", "repo:o/r:ref:refs/heads/main", true},
		{"repo:o/r:ref:refs/heads/main", "repo:o/r:ref:refs/heads/dev", false},
		{"repo:o/r:*", "repo:o/r:ref:refs/heads/*", true},
		{"repo:o/*", "repo:o/r:pull_request", true},
		{"repo:o/r:environment:prod", "repo:o/r:ref:refs/heads/*", false},
		{"repo:o/r:ref:refs/heads/*", "repo:o/r:ref:refs/heads/release-?", true},
		{"repo:o/r:ref:refs/heads/main", "repo:o/r:ref:refs/heads/*", true},
		{"repo:x/r:*", "repo:o/r:ref:refs/heads/*", false},
		{"*", "", true},
		{"?", "", false},
		{"a*b", "*c*", true},
		{"a*b", "c*", false},
		{"*a", "*b", false},
		{"**", "x", true},
	}
	for _, c := range cases {
		if got := Overlap(c.a, c.b); got != c.want {
			t.Errorf("Overlap(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
		if got := Overlap(c.b, c.a); got != c.want {
			t.Errorf("Overlap(%q,%q) not symmetric", c.b, c.a)
		}
	}
}

func FuzzOverlapSelf(f *testing.F) {
	f.Add("repo:o/r:*")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 64 {
			return
		}
		if !Overlap(s, s) {
			t.Fatalf("pattern %q does not overlap itself", s)
		}
	})
}
