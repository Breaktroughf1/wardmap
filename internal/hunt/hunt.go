// Package hunt matches versioned IOC packs against a snapshot. IOC packs are
// data files, so new campaigns ship without a code release.
package hunt

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Breaktroughf1/wardmap/internal/glob"
	"github.com/Breaktroughf1/wardmap/internal/model"
)

//go:embed packs/*.yaml
var builtin embed.FS

// Pack is an IOC pack.
type Pack struct {
	ID         string      `yaml:"id"`
	Name       string      `yaml:"name"`
	Version    string      `yaml:"version"`
	Window     Window      `yaml:"window"`
	Primary    []string    `yaml:"primary"`
	References []string    `yaml:"references"`
	Indicators []Indicator `yaml:"indicators"`
}

// Window is the campaign activity window.
type Window struct {
	Start time.Time `yaml:"start"`
	End   time.Time `yaml:"end"`
}

func (w Window) contains(t time.Time) bool {
	if t.IsZero() || w.Start.IsZero() {
		return false
	}
	if t.Before(w.Start) {
		return false
	}
	return w.End.IsZero() || !t.After(w.End)
}

// Indicator is one IOC.
type Indicator struct {
	ID      string `yaml:"id" json:"id"`
	Type    string `yaml:"type" json:"type"`
	Pattern string `yaml:"pattern" json:"pattern,omitempty"`
	// Session optionally constrains cloudtrail_event to sessions whose name
	// matches this pattern.
	Session     string `yaml:"session" json:"session,omitempty"`
	Confidence  string `yaml:"confidence" json:"confidence"`
	Description string `yaml:"description" json:"description"`
	// Sources lists the write-ups that report this indicator.
	Sources []string `yaml:"sources" json:"sources,omitempty"`
	// Verified is "primary" when checked against the original researchers'
	// publication, "secondary" when only corroborated by other reporting.
	Verified string `yaml:"verified" json:"verified,omitempty"`
}

// Hit is a matched indicator.
type Hit struct {
	Pack       string    `json:"pack"`
	Indicator  string    `json:"indicator"`
	Confidence string    `json:"confidence"`
	Repo       string    `json:"repo,omitempty"`
	Evidence   string    `json:"evidence"`
	Time       time.Time `json:"time,omitempty"`
	InWindow   bool      `json:"in_campaign_window"`
	Note       string    `json:"note"`
}

var confRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// ConfidenceAtLeast reports whether c >= min.
func ConfidenceAtLeast(c, min string) bool { return confRank[c] >= confRank[min] }

// KnownTypes lists every indicator type Run understands.
var KnownTypes = map[string]bool{
	"branch_name": true, "pr_title": true, "pr_head_ref": true, "commit_message": true,
	"commit_file": true, "workflow_path": true, "workflow_endpoint": true,
	"workflow_secrets_dump": true, "azure_fic_name": true, "azure_audit_fic_name": true,
	"aws_wildcard_principal": true, "run_number_gap": true, "cloudtrail_session_name": true,
	"cloudtrail_event": true, "cloudtrail_deleted_branch": true, "cloudtrail_unknown_repo": true,
	"cloudtrail_pull_request": true,
}

var needsPattern = map[string]bool{
	"branch_name": true, "pr_title": true, "pr_head_ref": true, "commit_message": true,
	"commit_file": true, "workflow_path": true, "workflow_endpoint": true,
	"azure_fic_name": true, "azure_audit_fic_name": true, "cloudtrail_session_name": true,
	"cloudtrail_event": true,
}

// Validate rejects packs with unknown types, missing patterns, duplicate ids
// or bad confidence values, so a typo can never silently disable an IOC.
func (p Pack) Validate() error {
	if p.ID == "" || p.Version == "" {
		return fmt.Errorf("pack needs id and version")
	}
	seen := map[string]bool{}
	for _, in := range p.Indicators {
		switch {
		case in.ID == "":
			return fmt.Errorf("pack %s: indicator without id", p.ID)
		case seen[in.ID]:
			return fmt.Errorf("pack %s: duplicate indicator %s", p.ID, in.ID)
		case !KnownTypes[in.Type]:
			return fmt.Errorf("pack %s: indicator %s has unknown type %q", p.ID, in.ID, in.Type)
		case needsPattern[in.Type] && in.Pattern == "":
			return fmt.Errorf("pack %s: indicator %s needs a pattern", p.ID, in.ID)
		case confRank[in.Confidence] == 0:
			return fmt.Errorf("pack %s: indicator %s has confidence %q (want low, medium or high)", p.ID, in.ID, in.Confidence)
		case in.Verified != "" && in.Verified != "primary" && in.Verified != "secondary":
			return fmt.Errorf("pack %s: indicator %s has verified %q (want primary or secondary)", p.ID, in.ID, in.Verified)
		}
		seen[in.ID] = true
	}
	return nil
}

// LoadPacks loads built-in packs plus any *.yaml in dir (dir may be empty).
func LoadPacks(dir string) ([]Pack, error) {
	var packs []Pack
	err := fs.WalkDir(builtin, "packs", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := builtin.ReadFile(p)
		if err != nil {
			return err
		}
		var pk Pack
		if err := yaml.Unmarshal(b, &pk); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if err := pk.Validate(); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		packs = append(packs, pk)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return packs, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.y*ml"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var pk Pack
		if err := yaml.Unmarshal(b, &pk); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := pk.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		// A local pack with the same id replaces the built-in one.
		replaced := false
		for i := range packs {
			if packs[i].ID == pk.ID {
				packs[i], replaced = pk, true
			}
		}
		if !replaced {
			packs = append(packs, pk)
		}
	}
	return packs, nil
}

func m(pattern, s string) bool {
	return glob.Match(strings.ToLower(pattern), strings.ToLower(s))
}

// Coverage describes what hunting data a snapshot holds, so a report can say
// what was not checked instead of implying a clean result.
type Coverage struct {
	GitHubHistory bool // pull requests, commits, runs (collect --hunt)
	Cloud         bool // CloudTrail, Entra audit, cloud trust exports
	Anything      bool
}

// CoverageOf inspects a snapshot.
func CoverageOf(s *model.Snapshot) Coverage {
	c := Coverage{GitHubHistory: s.HuntCollected}
	for _, r := range s.Repos {
		if len(r.PullRequests)+len(r.Commits)+len(r.Runs) > 0 {
			c.GitHubHistory = true
		}
		if len(r.Branches)+len(r.Workflows) > 0 {
			c.Anything = true
		}
	}
	c.Cloud = len(s.CloudTrail)+len(s.CloudTrailEvents)+len(s.AzureAudit)+len(s.AzureFICs)+len(s.AWSRoles) > 0
	c.Anything = c.Anything || c.GitHubHistory || c.Cloud
	return c
}

// Run evaluates packs against the snapshot.
func Run(s *model.Snapshot, packs []Pack) []Hit {
	var hits []Hit
	add := func(p Pack, in Indicator, repo, ev string, t time.Time) {
		hits = append(hits, Hit{Pack: p.ID, Indicator: in.ID, Confidence: in.Confidence, Repo: repo,
			Evidence: ev, Time: t, InWindow: p.Window.contains(t), Note: in.Description})
	}
	repos := map[string]*model.Repo{}
	for i := range s.Repos {
		repos[s.Repos[i].FullName] = &s.Repos[i]
	}
	for _, p := range packs {
		for _, in := range p.Indicators {
			switch in.Type {
			case "branch_name":
				for _, r := range s.Repos {
					for _, b := range r.Branches {
						if m(in.Pattern, b) {
							add(p, in, r.FullName, "branch "+b, time.Time{})
						}
					}
				}
			case "pr_title", "pr_head_ref":
				for _, r := range s.Repos {
					for _, pr := range r.PullRequests {
						v := pr.Title
						if in.Type == "pr_head_ref" {
							v = pr.HeadRef
						}
						if m(in.Pattern, v) {
							add(p, in, r.FullName, fmt.Sprintf("PR #%d %q by %s", pr.Number, pr.Title, pr.Author), pr.CreatedAt)
						}
					}
				}
			case "commit_message":
				for _, r := range s.Repos {
					for _, c := range r.Commits {
						first := strings.SplitN(c.Message, "\n", 2)[0]
						if m(in.Pattern, first) {
							add(p, in, r.FullName, fmt.Sprintf("commit %s %q by %s", short(c.SHA), first, c.Author), c.Date)
						}
					}
				}
			case "commit_file":
				for _, r := range s.Repos {
					for _, c := range r.Commits {
						for _, f := range c.Files {
							if m(in.Pattern, f) {
								add(p, in, r.FullName, fmt.Sprintf("commit %s touched %s (author %s)", short(c.SHA), f, c.Author), c.Date)
							}
						}
					}
				}
			case "workflow_path":
				for _, r := range s.Repos {
					for _, w := range r.Workflows {
						if m(in.Pattern, w.Path) {
							add(p, in, r.FullName, "workflow file "+w.Path, time.Time{})
						}
					}
					for _, run := range r.Runs {
						if m(in.Pattern, run.WorkflowPath) {
							add(p, in, r.FullName, fmt.Sprintf("run #%d of %s on %s", run.RunNumber, run.WorkflowPath, run.HeadBranch), run.CreatedAt)
						}
					}
				}
			case "workflow_endpoint":
				for _, r := range s.Repos {
					for _, w := range r.Workflows {
						for _, e := range w.Endpoints {
							if m(in.Pattern, e) {
								add(p, in, r.FullName, fmt.Sprintf("workflow %s contacts %s", w.Path, e), time.Time{})
							}
						}
					}
				}
			case "workflow_secrets_dump":
				for _, r := range s.Repos {
					for _, w := range r.Workflows {
						for _, j := range w.Jobs {
							if j.DumpsSecrets {
								add(p, in, r.FullName, fmt.Sprintf("workflow %s job %s serialises the whole secrets/vars context", w.Path, j.ID), time.Time{})
							}
						}
					}
				}
			case "cloudtrail_session_name":
				for _, e := range s.CloudTrail {
					if e.SessionName != "" && m(in.Pattern, e.SessionName) {
						add(p, in, "", fmt.Sprintf("%s %s assumed %s with session %q (sub %s)", e.Time.Format(time.RFC3339), e.SourceIP, e.RoleARN, e.SessionName, e.Subject), e.Time)
					}
				}
				for _, e := range s.CloudTrailEvents {
					if e.SessionName != "" && m(in.Pattern, e.SessionName) {
						add(p, in, "", fmt.Sprintf("%s %s by session %q on %s", e.Time.Format(time.RFC3339), e.EventName, e.SessionName, e.Target), e.Time)
					}
				}
			case "cloudtrail_event":
				for _, e := range s.CloudTrailEvents {
					if !m(in.Pattern, e.EventName) || (in.Session != "" && !m(in.Session, e.SessionName)) {
						continue
					}
					add(p, in, "", fmt.Sprintf("%s %s on %s by %s (ip %s)", e.Time.Format(time.RFC3339), e.EventName, e.Target, e.Principal, e.SourceIP), e.Time)
				}
			case "azure_audit_fic_name":
				for _, e := range s.AzureAudit {
					for _, n := range e.FICNames {
						if m(in.Pattern, n) {
							add(p, in, "", fmt.Sprintf("%s %s added federated credential %s to app %s (%s) by %s", e.Time.Format(time.RFC3339), e.Activity, n, e.AppName, e.AppID, e.Initiator), e.Time)
						}
					}
				}
			case "azure_fic_name":
				for _, f := range s.AzureFICs {
					if m(in.Pattern, f.Name) {
						add(p, in, "", fmt.Sprintf("Entra app %s federated credential %s (subject %s)", f.AppID, f.Name, f.Subject), time.Time{})
					}
				}
			case "aws_wildcard_principal":
				for _, r := range s.AWSRoles {
					if hasWildcardPrincipal(r.TrustPolicy) {
						add(p, in, "", "role "+r.ARN+" trusts a wildcard principal", time.Time{})
					}
				}
			case "run_number_gap":
				for _, r := range s.Repos {
					for _, g := range runGaps(r.Runs) {
						h := Hit{Pack: p.ID, Indicator: in.ID, Confidence: in.Confidence, Repo: r.FullName,
							Evidence: g.desc, Time: g.after, InWindow: p.Window.contains(g.after) || p.Window.contains(g.before), Note: in.Description}
						hits = append(hits, h)
					}
				}
			case "cloudtrail_deleted_branch", "cloudtrail_unknown_repo", "cloudtrail_pull_request":
				for _, e := range s.CloudTrail {
					repo, ctx := parseSub(e.Subject)
					r := repos[repo]
					switch in.Type {
					case "cloudtrail_unknown_repo":
						if repo != "" && r == nil && len(s.Repos) > 0 {
							add(p, in, repo, fmt.Sprintf("%s assumed %s from %s (sub %s)", e.Time.Format(time.RFC3339), e.RoleARN, e.SourceIP, e.Subject), e.Time)
						}
					case "cloudtrail_pull_request":
						if ctx == "pull_request" {
							add(p, in, repo, fmt.Sprintf("%s assumed %s with a pull_request token (sub %s)", e.Time.Format(time.RFC3339), e.RoleARN, e.Subject), e.Time)
						}
					case "cloudtrail_deleted_branch":
						if r == nil || len(r.Branches) == 0 || !strings.HasPrefix(ctx, "ref:refs/heads/") {
							continue
						}
						b := strings.TrimPrefix(ctx, "ref:refs/heads/")
						if !contains(r.Branches, b) {
							add(p, in, repo, fmt.Sprintf("%s assumed %s from deleted branch %s (sub %s, ip %s)", e.Time.Format(time.RFC3339), e.RoleARN, b, e.Subject, e.SourceIP), e.Time)
						}
					}
				}
			}
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if confRank[hits[i].Confidence] != confRank[hits[j].Confidence] {
			return confRank[hits[i].Confidence] > confRank[hits[j].Confidence]
		}
		if hits[i].Repo != hits[j].Repo {
			return hits[i].Repo < hits[j].Repo
		}
		return hits[i].Evidence < hits[j].Evidence
	})
	return hits
}

type gap struct {
	desc          string
	before, after time.Time
}

// runGaps finds missing run numbers per workflow among collected runs.
func runGaps(runs []model.Run) []gap {
	by := map[string][]model.Run{}
	for _, r := range runs {
		k := r.WorkflowPath
		if k == "" {
			k = fmt.Sprint(r.WorkflowID)
		}
		by[k] = append(by[k], r)
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []gap
	for _, k := range keys {
		rs := by[k]
		sort.Slice(rs, func(i, j int) bool { return rs[i].RunNumber < rs[j].RunNumber })
		for i := 1; i < len(rs); i++ {
			if d := rs[i].RunNumber - rs[i-1].RunNumber; d > 1 {
				out = append(out, gap{
					desc:   fmt.Sprintf("%s: runs #%d–#%d missing (between %s and %s)", k, rs[i-1].RunNumber+1, rs[i].RunNumber-1, rs[i-1].CreatedAt.Format("2006-01-02 15:04"), rs[i].CreatedAt.Format("2006-01-02 15:04")),
					before: rs[i-1].CreatedAt, after: rs[i].CreatedAt,
				})
			}
		}
	}
	return out
}

func parseSub(sub string) (repo, ctx string) {
	if !strings.HasPrefix(sub, "repo:") {
		return "", ""
	}
	rest := sub[len("repo:"):]
	i := strings.IndexByte(rest, ':')
	if i < 0 {
		return rest, ""
	}
	return rest[:i], rest[i+1:]
}

func hasWildcardPrincipal(doc map[string]any) bool {
	sts, _ := doc["Statement"].([]any)
	if st, ok := doc["Statement"].(map[string]any); ok {
		sts = []any{st}
	}
	for _, s := range sts {
		mm, _ := s.(map[string]any)
		if eff, _ := mm["Effect"].(string); !strings.EqualFold(eff, "Allow") {
			continue
		}
		switch p := mm["Principal"].(type) {
		case string:
			if p == "*" {
				return true
			}
		case map[string]any:
			for _, v := range p {
				switch x := v.(type) {
				case string:
					if x == "*" {
						return true
					}
				case []any:
					for _, y := range x {
						if y == "*" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
