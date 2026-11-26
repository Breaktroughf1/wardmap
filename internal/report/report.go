// Package report renders analysis results as Markdown, SARIF 2.1.0,
// Mermaid, Graphviz DOT and JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Breaktroughf1/wardmap/internal/analysis"
	"github.com/Breaktroughf1/wardmap/internal/hunt"
)

// Rule metadata, shared by SARIF and docs.
type Rule struct {
	ID, Name, Short, Help string
}

// Rules lists every rule Wardmap can emit.
var Rules = []Rule{
	{"WM001", "org-secret-visibility-all", "Organisation secret visible to all repositories", "Restrict org secrets to selected repositories, or move them to environments with required reviewers."},
	{"WM002", "secret-readable-from-any-branch", "Secrets readable from any branch by a write credential", "Repository and organisation secrets are exposed to every workflow on every branch. Store deployment secrets as environment secrets behind required reviewers."},
	{"WM003", "cloud-role-reachable-by-write-credential", "Cloud identity reachable from an unprotected branch, tag, PR or environment", "Bind OIDC trust to a protected branch, or to an environment with required reviewers that admits only protected branches."},
	{"WM004", "trust-admits-whole-owner", "OIDC trust admits every repository of the owner", "Replace repo:<owner>/* subjects and owner-only conditions with exact repository and ref/environment subjects."},
	{"WM005", "trust-missing-audience", "AWS OIDC trust does not check the audience", "Add a StringEquals condition on token.actions.githubusercontent.com:aud = sts.amazonaws.com."},
	{"WM006", "trust-admits-any-github-repository", "Cloud identity assumable from any GitHub repository", "Anyone on GitHub can mint a matching token. Constrain the subject to your repositories immediately."},
	{"WM007", "ungated-environment-with-secrets", "Environment secrets without reviewers or branch restriction", "Add required reviewers or restrict deployment branches to protected branches."},
	{"WM008", "id-token-on-untrusted-trigger", "id-token: write on an untrusted trigger", "Do not mint cloud credentials in pull_request_target, workflow_run or comment-triggered jobs."},
	{"WM009", "secret-to-unpinned-action", "Secret passed to a third-party action not pinned to a SHA", "Pin third-party actions to a full commit SHA."},
	{"WM010", "stale-secret", "Secret not rotated recently", "Rotate secrets periodically, and immediately after any CI credential-theft campaign that touched the repository."},
	{"WM011", "static-cloud-credential", "Long-lived cloud credential stored in GitHub", "Replace stored cloud keys with GitHub OIDC federation."},
	{"WM012", "cloud-persistence-indicator", "Cloud trust matches a known persistence technique", "Wildcard AWS principals and wfx-ci-* Entra credentials are wfx-loot persistence. Investigate and remove."},
	{"WM013", "gcp-provider-without-condition", "GCP workload identity provider without attribute condition", "Add an attribute condition restricting assertion.repository (and ref or environment)."},
	{"WM014", "trust-needs-review", "Trust condition could not be evaluated", "Wardmap never reports unevaluated conditions as safe. Review manually or open an issue with the (redacted) condition."},
	{"WM015", "pull-request-target-checkout", "pull_request_target job executes PR code with secrets", "Use pull_request, or split the job so PR code never runs with secrets or id-token."},
	{"WM016", "collection-gap", "Data could not be collected", "Grant the read permissions listed in docs/permissions.md, or provide an offline export."},
	{"WM017", "secrets-inherit-to-third-party", "All secrets passed to a third-party reusable workflow", "Pass only the secrets the called workflow needs."},
	{"WM018", "workflow-parse-error", "Workflow could not be parsed", "Fix the YAML; Wardmap skips unparsable workflows."},
	{"WM019", "github-token-in-secrets", "GitHub personal access token stored as an Actions secret", "Use GITHUB_TOKEN with scoped permissions or a GitHub App installation token; if a PAT is unavoidable, make it fine-grained, limited to the target repositories, and keep it in a gated environment."},
	{"WM021", "trust-pins-repository-names", "OIDC trust identifies repositories by name only", "Use immutable subjects (repo:OWNER@ID/REPO@ID) or ID conditions so a re-registered name cannot inherit the trust."},
}

// Markdown writes a human-readable report.
func Markdown(w io.Writer, res analysis.Result, title string) {
	fmt.Fprintf(w, "# %s\n\n", title)
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.SeverityStr]++
	}
	fmt.Fprintf(w, "**Findings:** %d critical · %d high · %d medium · %d low · %d info\n\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])
	reach := 0
	for _, e := range res.Edges {
		if e.Verdict == "reachable" {
			reach++
		}
	}
	fmt.Fprintf(w, "**Reach:** %d secret or cloud identities reachable by a single compromised write credential.\n\n", reach)
	if len(res.Gaps) > 0 {
		fmt.Fprintf(w, "> **Incomplete data.** %d collection gap(s); see the end of this report. A clean result does not prove absence of exposure.\n\n", len(res.Gaps))
	}
	fmt.Fprint(w, "## Blast radius per repository\n\n")
	byFrom := map[string][]analysis.Edge{}
	for _, e := range res.Edges {
		byFrom[e.From] = append(byFrom[e.From], e)
	}
	froms := make([]string, 0, len(byFrom))
	for f := range byFrom {
		froms = append(froms, f)
	}
	sort.Strings(froms)
	if len(froms) == 0 {
		fmt.Fprint(w, "No secrets or cloud identities were found reachable in the collected data.\n\n")
	}
	for _, f := range froms {
		fmt.Fprintf(w, "### `%s`\n\n| Reaches | Kind | Via | Verdict |\n|---|---|---|---|\n", f)
		for _, e := range byFrom[f] {
			fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", e.To, e.Kind, esc(e.Via), e.Verdict)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprint(w, "## Findings\n\n")
	shown := 0
	for _, f := range res.Findings {
		if !(f.RuleID == "WM016" && strings.HasPrefix(f.Message, "Collection gap:")) {
			shown++
		}
	}
	if shown == 0 {
		if len(res.Gaps) > 0 {
			fmt.Fprintln(w, "No findings in the data that could be collected; see the collection gaps below.")
		} else {
			fmt.Fprintln(w, "No findings.")
		}
	}
	for _, f := range res.Findings {
		if f.RuleID == "WM016" && strings.HasPrefix(f.Message, "Collection gap:") {
			continue // listed once under "Collection gaps"
		}
		loc := f.Repo
		if f.Path != "" {
			loc += "/" + f.Path
		}
		if loc != "" {
			loc = " — `" + loc + "`"
		}
		fmt.Fprintf(w, "- **%s** `%s`%s: %s\n", strings.ToUpper(f.SeverityStr), f.RuleID, loc, esc(f.Message))
	}
	if len(res.Gaps) > 0 {
		fmt.Fprint(w, "\n## Collection gaps\n\n")
		for _, g := range res.Gaps {
			fmt.Fprintf(w, "- %s\n", esc(g))
		}
	}
	fmt.Fprintln(w, "\n---\nWardmap is read-only and never reads secret values. It reports exposure, not compromise; use `wardmap hunt` for indicators of compromise.")
}

// esc makes free text safe inside Markdown: table pipes and emphasis
// markers (ARNs and policies contain "*") are escaped.
func esc(s string) string {
	return strings.NewReplacer("|", "\\|", "*", "\\*", "_", "\\_").Replace(s)
}

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Mermaid writes the reachable graph as a Mermaid flowchart.
func Mermaid(w io.Writer, res analysis.Result) {
	fmt.Fprintln(w, "flowchart LR")
	ids := map[string]string{}
	id := func(s string) string {
		if v, ok := ids[s]; ok {
			return v
		}
		v := fmt.Sprintf("n%d", len(ids))
		ids[s] = v
		fmt.Fprintf(w, "  %s[\"%s\"]\n", v, strings.ReplaceAll(s, "\"", "'"))
		return v
	}
	for _, e := range res.Edges {
		if e.Verdict == "not-reachable" {
			continue
		}
		style := "-->"
		if e.Verdict != "reachable" {
			style = "-.->"
		}
		fmt.Fprintf(w, "  %s %s|%s| %s\n", id(e.From), style, e.Verdict, id(e.To))
	}
}

// DOT writes the reachable graph in Graphviz format.
func DOT(w io.Writer, res analysis.Result) {
	fmt.Fprintln(w, "digraph wardmap {\n  rankdir=LR;\n  node [shape=box,fontname=\"Helvetica\"];")
	for _, e := range res.Edges {
		style := "solid"
		if e.Verdict != "reachable" {
			style = "dashed"
		}
		fmt.Fprintf(w, "  %q -> %q [label=%q,style=%s];\n", e.From, e.To, e.Verdict, style)
	}
	fmt.Fprintln(w, "}")
}

// HuntMarkdown writes hunting results.
func HuntMarkdown(w io.Writer, hits []hunt.Hit, packs []hunt.Pack, cov hunt.Coverage) {
	fmt.Fprint(w, "# Wardmap hunt\n\n")
	if !cov.Anything {
		fmt.Fprint(w, "> **Nothing to hunt in.** The snapshot holds no branches, workflows, history or cloud exports, so no indicator could be checked. Run `wardmap collect --hunt` and/or import CloudTrail and Entra exports.\n\n")
	} else {
		if !cov.GitHubHistory {
			fmt.Fprint(w, "> **Not checked:** pull requests, commits and workflow runs were not collected (run `wardmap collect --hunt`), so probe PRs, inject-and-revert commits and run-number gaps could not be detected.\n\n")
		}
		if !cov.Cloud {
			fmt.Fprint(w, "> **Not checked:** no CloudTrail, Entra audit or cloud trust exports were imported, so cloud persistence (wildcard trust, `wfx-ci-*` credentials, `wfx-*` sessions) could not be detected.\n\n")
		}
	}
	var names []string
	for _, p := range packs {
		names = append(names, fmt.Sprintf("`%s@%s`", p.ID, p.Version))
	}
	fmt.Fprintf(w, "IOC packs: %s\n\n", strings.Join(names, ", "))
	if len(hits) == 0 {
		fmt.Fprintln(w, "No indicators matched.\n\n> No match does **not** prove the estate was not compromised: wfx-loot deleted runs, logs and commits. Combine with CloudTrail/Entra audit logs (`--cloudtrail`) and rotate any secret that was reachable during the campaign window.")
		return
	}
	fmt.Fprintln(w, "| Confidence | Pack | Indicator | Repository | Evidence | In window |\n|---|---|---|---|---|---|")
	for _, h := range hits {
		win := ""
		if h.InWindow {
			win = "yes"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", h.Confidence, h.Pack, h.Indicator, h.Repo, esc(h.Evidence), win)
	}
	fmt.Fprintln(w, "\nNext steps: run `wardmap rotate-plan --repo <affected>` for an ordered rotation runbook. Indicators are hunting leads; confirm each before acting.")
}

// Escape is esc for callers outside this package.
func Escape(s string) string { return esc(s) }
