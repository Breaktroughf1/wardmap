// Command wardmap maps what a compromised CI credential can reach: which
// GitHub Actions secrets and which AWS, Azure and GCP identities (via GitHub
// OIDC) fall if one write credential or branch is compromised.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/analysis"
	gh "github.com/Breaktroughf1/wardmap/internal/github"
	"github.com/Breaktroughf1/wardmap/internal/hunt"
	"github.com/Breaktroughf1/wardmap/internal/importer"
	"github.com/Breaktroughf1/wardmap/internal/model"
	"github.com/Breaktroughf1/wardmap/internal/report"
	"github.com/Breaktroughf1/wardmap/internal/workflow"
)

// version is set at build time with -ldflags "-X main.version=..."; for
// `go install module@vX.Y.Z` builds it falls back to the module version.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

const usage = `wardmap — map your CI's blast radius

Usage:
  wardmap collect   --org ORG | --repo OWNER/NAME... [--hunt] [-o snapshot.json]
  wardmap import    -s snapshot.json [--aws FILE] [--azure [APPID=]FILE] [--gcp FILE] [--cloudtrail FILE] [--azure-audit FILE]
  wardmap local     [--dir .] [--repo OWNER/NAME] [-o snapshot.json]   (offline: workflows from disk)
  wardmap scan      -s snapshot.json [--format md|json|sarif|mermaid|dot] [--fail-on SEV] [--baseline FILE]
  wardmap baseline  -s snapshot.json [-o wardmap-baseline.json]
  wardmap reach     -s snapshot.json QUERY
  wardmap hunt      -s snapshot.json [--iocs DIR] [--format md|json] [--fail-on low|medium|high]
  wardmap rotate-plan -s snapshot.json [--repo OWNER/NAME...] [--format md|json]
  wardmap run       [--offline --dir .] (collect or local + import + scan in one step)
  wardmap rules | version

Authentication: WARDMAP_GITHUB_TOKEN, GITHUB_TOKEN or GH_TOKEN (read-only).
Wardmap only issues GET requests and never reads secret values.
Exit codes: 0 ok, 1 threshold exceeded or new reach, 2 error.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wardmap:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type common struct {
	fs         *flag.FlagSet
	snapshot   string
	out        string
	format     string
	failOn     string
	baseline   string
	staleDays  int
	repoRel    string
	org        string
	repos      multi
	huntMode   bool
	since      string
	aws, gcp   multi
	azure, ct  multi
	azureAudit multi
	iocs       string
	dir        string
	noProgress bool
	offline    bool
	maxFiles   int
}

func newFlags(name string) *common {
	c := &common{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
	c.fs.StringVar(&c.snapshot, "s", "wardmap-snapshot.json", "snapshot file")
	c.fs.StringVar(&c.snapshot, "snapshot", "wardmap-snapshot.json", "snapshot file")
	c.fs.StringVar(&c.out, "o", "", "output file (default stdout, or wardmap-snapshot.json for collect)")
	c.fs.StringVar(&c.format, "format", "md", "output format")
	c.fs.StringVar(&c.failOn, "fail-on", "none", "exit 1 if a finding (or hunt hit) at or above this severity exists")
	c.fs.StringVar(&c.baseline, "baseline", "", "baseline file: only new findings/reach count towards --fail-on, and new reach fails")
	c.fs.IntVar(&c.staleDays, "stale-days", 180, "secret age that triggers WM010")
	c.fs.StringVar(&c.repoRel, "repo-relative", "", "emit SARIF paths relative to this repository (OWNER/NAME)")
	c.fs.StringVar(&c.org, "org", "", "GitHub organisation or user to collect")
	c.fs.Var(&c.repos, "repo", "repository OWNER/NAME (repeatable)")
	c.fs.BoolVar(&c.huntMode, "hunt", false, "also collect PRs, commits and runs for hunting")
	c.fs.StringVar(&c.since, "since", "45d", "hunting look-back (e.g. 45d, 2026-11-01)")
	c.fs.Var(&c.aws, "aws", "AWS roles export (repeatable)")
	c.fs.Var(&c.azure, "azure", "Azure federated credentials export, [APPID=]FILE (repeatable)")
	c.fs.Var(&c.gcp, "gcp", "GCP providers export (repeatable)")
	c.fs.Var(&c.ct, "cloudtrail", "CloudTrail export (repeatable)")
	c.fs.Var(&c.azureAudit, "azure-audit", "Entra ID directory audit export (repeatable)")
	c.fs.StringVar(&c.iocs, "iocs", "", "directory of extra or replacement IOC packs")
	c.fs.StringVar(&c.dir, "dir", ".", "repository checkout for `local`")
	c.fs.BoolVar(&c.noProgress, "quiet", false, "suppress progress output")
	c.fs.IntVar(&c.maxFiles, "max-commit-files", 60, "hunt: commits per repository whose changed-file lists are fetched")
	c.fs.BoolVar(&c.offline, "offline", false, "run: scan workflows from --dir instead of calling the GitHub API")
	return c
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0, nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "wardmap", version)
		return 0, nil
	case "rules":
		for _, r := range report.Rules {
			fmt.Fprintf(stdout, "%s  %-42s %s\n", r.ID, r.Name, r.Short)
		}
		return 0, nil
	}
	c := newFlags(cmd)
	c.fs.SetOutput(stderr)
	if err := c.fs.Parse(rest); err != nil {
		return 2, err
	}
	switch cmd {
	case "collect":
		s, err := collect(ctx, c, stderr)
		if err != nil {
			return 2, err
		}
		return 0, writeSnapshot(orDefault(c.out, "wardmap-snapshot.json"), s, stderr)
	case "local":
		s, err := local(c)
		if err != nil {
			return 2, err
		}
		return 0, writeSnapshot(orDefault(c.out, "wardmap-snapshot.json"), s, stderr)
	case "import":
		s, err := readSnapshotOrNew(c.snapshot)
		if err != nil {
			return 2, err
		}
		if err := importInto(s, c); err != nil {
			return 2, err
		}
		return 0, writeSnapshot(orDefault(c.out, c.snapshot), s, stderr)
	case "scan", "check":
		s, err := readSnapshot(c.snapshot)
		if err != nil {
			return 2, err
		}
		return scan(s, c, stdout)
	case "run":
		var s *model.Snapshot
		var err error
		if c.offline || (len(c.repos) == 0 && c.org == "") {
			s, err = local(c)
		} else {
			s, err = collect(ctx, c, stderr)
		}
		if err != nil {
			return 2, err
		}
		if err := importInto(s, c); err != nil {
			return 2, err
		}
		return scan(s, c, stdout)
	case "baseline":
		s, err := readSnapshot(c.snapshot)
		if err != nil {
			return 2, err
		}
		res := analysis.Analyze(s, analysis.Options{StaleDays: c.staleDays})
		return 0, writeOut(orDefault(c.out, "wardmap-baseline.json"), stdout, func(w io.Writer) error { return report.JSON(w, makeBaseline(res)) })
	case "reach":
		s, err := readSnapshot(c.snapshot)
		if err != nil {
			return 2, err
		}
		if c.fs.NArg() != 1 {
			return 2, errors.New("reach needs exactly one QUERY (repository, secret name, role ARN, environment, ...)")
		}
		return reach(s, c, c.fs.Arg(0), stdout)
	case "hunt":
		s, err := readSnapshot(c.snapshot)
		if err != nil {
			return 2, err
		}
		if err := importInto(s, c); err != nil {
			return 2, err
		}
		packs, err := hunt.LoadPacks(c.iocs)
		if err != nil {
			return 2, err
		}
		hits := hunt.Run(s, packs)
		err = writeOut(c.out, stdout, func(w io.Writer) error {
			if c.format == "json" {
				return report.JSON(w, map[string]any{"packs": packs, "hits": hits})
			}
			report.HuntMarkdown(w, hits, packs)
			return nil
		})
		if err != nil {
			return 2, err
		}
		if c.failOn != "none" {
			for _, h := range hits {
				if hunt.ConfidenceAtLeast(h.Confidence, c.failOn) {
					return 1, nil
				}
			}
		}
		return 0, nil
	case "rotate-plan":
		s, err := readSnapshot(c.snapshot)
		if err != nil {
			return 2, err
		}
		res := analysis.Analyze(s, analysis.Options{StaleDays: c.staleDays})
		plan := analysis.RotatePlan(res, c.repos)
		return 0, writeOut(c.out, stdout, func(w io.Writer) error {
			if c.format == "json" {
				return report.JSON(w, plan)
			}
			fmt.Fprint(w, "# Rotation runbook\n\nWork top to bottom. Close cloud persistence before rotating, or a new secret can be stolen again.\n\n| # | Phase | Target | Action |\n|---|---|---|---|\n")
			for _, p := range plan {
				fmt.Fprintf(w, "| %d | %s | `%s` | %s |\n", p.Order, p.Phase, p.Target, report.Escape(p.Action))
			}
			if len(plan) == 0 {
				fmt.Fprintln(w, "\nNothing reachable from the selected repositories.")
			}
			return nil
		})
	}
	fmt.Fprint(stderr, usage)
	return 2, fmt.Errorf("unknown command %q", cmd)
}

func collect(ctx context.Context, c *common, stderr io.Writer) (*model.Snapshot, error) {
	token := firstEnv("WARDMAP_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
	if token == "" {
		return nil, errors.New("no GitHub token: set WARDMAP_GITHUB_TOKEN (read-only; see docs/permissions.md) or use `wardmap local` for an offline scan")
	}
	since, err := parseSince(c.since)
	if err != nil {
		return nil, err
	}
	client := &gh.Client{BaseURL: orDefault(os.Getenv("GITHUB_API_URL"), "https://api.github.com"), Token: token,
		HTTP: &http.Client{Timeout: 60 * time.Second}, UserAgent: "wardmap/" + version}
	opts := gh.Options{Owner: c.org, Repos: c.repos, Hunt: c.huntMode, Since: since, MaxCommitFiles: c.maxFiles}
	if !c.noProgress {
		opts.Progress = func(s string) { fmt.Fprintln(stderr, s) }
	}
	if opts.Owner == "" && len(opts.Repos) > 0 {
		opts.Owner = strings.SplitN(opts.Repos[0], "/", 2)[0]
	}
	return gh.Collect(ctx, client, opts)
}

// local builds a snapshot from a checkout on disk: workflows only, no secret
// inventory. Useful in pull requests and air-gapped reviews.
func local(c *common) (*model.Snapshot, error) {
	name := ""
	if len(c.repos) > 0 {
		name = c.repos[0]
	}
	if name == "" {
		name = orDefault(os.Getenv("GITHUB_REPOSITORY"), "local/repository")
	}
	r := model.Repo{FullName: name, Private: true}
	dir := strings.TrimSuffix(c.dir, "/") + "/.github/workflows"
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml")) {
			continue
		}
		b, err := os.ReadFile(dir + "/" + n)
		if err != nil {
			return nil, err
		}
		r.Workflows = append(r.Workflows, workflow.Parse(".github/workflows/"+n, b))
	}
	s := &model.Snapshot{SchemaVersion: model.SchemaVersion, CollectedAt: time.Now().UTC(), Owner: strings.SplitN(name, "/", 2)[0], Repos: []model.Repo{r},
		Gaps: []string{"offline scan of " + name + ": secret inventory, environments and branch protection not collected"}}
	return s, nil
}

func importInto(s *model.Snapshot, c *common) error {
	for _, f := range c.aws {
		r, err := importer.AWS(f)
		if err != nil {
			return err
		}
		s.AWSRoles = append(s.AWSRoles, r...)
	}
	for _, f := range c.azure {
		app, path := "", f
		if i := strings.IndexByte(f, '='); i > 0 {
			app, path = f[:i], f[i+1:]
		}
		r, err := importer.Azure(path, app)
		if err != nil {
			return err
		}
		s.AzureFICs = append(s.AzureFICs, r...)
	}
	for _, f := range c.gcp {
		r, err := importer.GCP(f)
		if err != nil {
			return err
		}
		s.GCPProviders = append(s.GCPProviders, r...)
	}
	for _, f := range c.ct {
		r, other, err := importer.CloudTrail(f)
		if err != nil {
			return err
		}
		s.CloudTrail = append(s.CloudTrail, r...)
		s.CloudTrailEvents = append(s.CloudTrailEvents, other...)
	}
	for _, f := range c.azureAudit {
		r, err := importer.AzureAudit(f)
		if err != nil {
			return err
		}
		s.AzureAudit = append(s.AzureAudit, r...)
	}
	return nil
}

func scan(s *model.Snapshot, c *common, stdout io.Writer) (int, error) {
	res := analysis.Analyze(s, analysis.Options{StaleDays: c.staleDays})
	newReach := 0
	gate := res
	if c.baseline != "" {
		b, err := readBaseline(c.baseline)
		if err != nil {
			return 2, err
		}
		gate, newReach = diffBaseline(res, b)
	}
	err := writeOut(c.out, stdout, func(w io.Writer) error {
		switch c.format {
		case "md", "markdown":
			title := "Wardmap report"
			if s.Owner != "" {
				title += ": " + s.Owner
			}
			report.Markdown(w, res, title)
			if c.baseline != "" {
				fmt.Fprintf(w, "\n**Baseline:** %d new finding(s), %d new reach edge(s) since %s.\n", len(gate.Findings), newReach, c.baseline)
			}
		case "json":
			return report.JSON(w, res)
		case "sarif":
			return report.SARIF(w, res, version, c.repoRel)
		case "mermaid":
			report.Mermaid(w, res)
		case "dot":
			report.DOT(w, res)
		default:
			return fmt.Errorf("unknown format %q", c.format)
		}
		return nil
	})
	if err != nil {
		return 2, err
	}
	if newReach > 0 {
		return 1, nil
	}
	if c.failOn != "none" {
		min, err := analysis.ParseSeverity(c.failOn)
		if err != nil {
			return 2, err
		}
		for _, f := range gate.Findings {
			if f.Severity >= min {
				return 1, nil
			}
		}
	}
	return 0, nil
}

func reach(s *model.Snapshot, c *common, q string, stdout io.Writer) (int, error) {
	res := analysis.Analyze(s, analysis.Options{StaleDays: c.staleDays})
	ql := strings.ToLower(q)
	var hits []analysis.Edge
	for _, e := range res.Edges {
		if strings.Contains(strings.ToLower(e.From), ql) || strings.Contains(strings.ToLower(e.To), ql) || strings.Contains(strings.ToLower(e.Via), ql) {
			hits = append(hits, e)
		}
	}
	return 0, writeOut(c.out, stdout, func(w io.Writer) error {
		if c.format == "json" {
			return report.JSON(w, hits)
		}
		if len(hits) == 0 {
			fmt.Fprintf(w, "Nothing matching %q is reachable.\n", q)
			return nil
		}
		for _, e := range hits {
			fmt.Fprintf(w, "%-12s %s -> %s\n             via %s", e.Verdict, e.From, e.To, e.Via)
			if e.Reason != "" {
				fmt.Fprintf(w, " (%s)", e.Reason)
			}
			fmt.Fprintln(w)
		}
		return nil
	})
}

// Baseline is an approved state.
type Baseline struct {
	Version     int               `json:"version"`
	GeneratedAt time.Time         `json:"generated_at"`
	Findings    map[string]string `json:"findings"` // fingerprint -> rule: message
	Reach       []string          `json:"reach"`
}

func makeBaseline(res analysis.Result) Baseline {
	b := Baseline{Version: 1, GeneratedAt: time.Now().UTC(), Findings: map[string]string{}}
	for _, f := range res.Findings {
		b.Findings[f.Fingerprint] = f.RuleID + ": " + truncate(f.Message, 160)
	}
	for _, e := range res.Edges {
		if e.Verdict == "reachable" {
			b.Reach = append(b.Reach, e.Key())
		}
	}
	sort.Strings(b.Reach)
	return b
}

func readBaseline(path string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(data, &b)
}

func diffBaseline(res analysis.Result, b Baseline) (analysis.Result, int) {
	out := analysis.Result{Gaps: res.Gaps}
	for _, f := range res.Findings {
		if _, ok := b.Findings[f.Fingerprint]; !ok {
			out.Findings = append(out.Findings, f)
		}
	}
	known := map[string]bool{}
	for _, k := range b.Reach {
		known[k] = true
	}
	n := 0
	for _, e := range res.Edges {
		if e.Verdict == "reachable" && !known[e.Key()] {
			n++
		}
	}
	return out, n
}

func readSnapshot(path string) (*model.Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w (create one with `wardmap collect` or `wardmap local`)", err)
	}
	var s model.Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.SchemaVersion > model.SchemaVersion {
		return nil, fmt.Errorf("%s: snapshot schema %d is newer than this wardmap (%d)", path, s.SchemaVersion, model.SchemaVersion)
	}
	return &s, nil
}

func readSnapshotOrNew(path string) (*model.Snapshot, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &model.Snapshot{SchemaVersion: model.SchemaVersion, CollectedAt: time.Now().UTC()}, nil
	}
	return readSnapshot(path)
}

func writeSnapshot(path string, s *model.Snapshot, stderr io.Writer) error {
	var buf bytes.Buffer
	if err := report.JSON(&buf, s); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote %s (%d repositories, %d collection gaps)\n", path, len(s.Repos), len(s.Gaps))
	return nil
}

func writeOut(path string, stdout io.Writer, f func(io.Writer) error) error {
	if path == "" || path == "-" {
		return f(stdout)
	}
	var buf bytes.Buffer
	if err := f(&buf); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func parseSince(s string) (time.Time, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return time.Time{}, fmt.Errorf("bad --since %q", s)
		}
		return time.Now().AddDate(0, 0, -n), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad --since %q (use 45d or YYYY-MM-DD)", s)
	}
	return t, nil
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
