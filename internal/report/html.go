package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/analysis"
	"github.com/Breaktroughf1/wardmap/internal/hunt"
)

// HTMLInput is everything the HTML report shows.
type HTMLInput struct {
	Title     string
	Version   string
	Generated time.Time
	Result    analysis.Result
	Hits      []hunt.Hit // optional
	HuntRun   bool
}

type htmlRepo struct {
	Actor string
	Edges []analysis.Edge
}

// HTML writes a single self-contained page (no external assets) suitable for
// sharing with security leads and auditors, and for printing to PDF.
func HTML(w io.Writer, in HTMLInput) error {
	counts := map[string]int{}
	for _, f := range in.Result.Findings {
		counts[f.SeverityStr]++
	}
	reach := 0
	by := map[string][]analysis.Edge{}
	for _, e := range in.Result.Edges {
		if e.Verdict == "reachable" {
			reach++
		}
		by[e.From] = append(by[e.From], e)
	}
	var repos []htmlRepo
	for k, v := range by {
		repos = append(repos, htmlRepo{Actor: k, Edges: v})
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Actor < repos[j].Actor })
	return htmlTmpl.Execute(w, map[string]any{
		"In": in, "Counts": counts, "Reach": reach, "Repos": repos,
		"Sev": []string{"critical", "high", "medium", "low", "info"},
	})
}

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"date":  func(t time.Time) string { return t.Format("2 January 2006, 15:04 MST") },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.In.Title}}</title>
<style>
:root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;--crit:#82071e;--high:#cf222e;--med:#9a6700;--low:#0969da;--info:#59636e;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--card:#151b23;--crit:#ff7b72;--high:#f85149;--med:#d29922;--low:#4493f8;--info:#9198a1;--ok:#3fb950}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--muted);font-size:13px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}.card b{display:block;font-size:24px}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:8px 0 18px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--card)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.nw code,.nw{white-space:nowrap;overflow-wrap:normal}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}.badge{font-weight:600;text-transform:uppercase;font-size:12px}
.reachable{color:var(--high);font-weight:600}.gated{color:var(--ok)}.note{background:var(--card);border-left:4px solid var(--med);padding:10px 12px;border-radius:4px}
@media print{body{font-size:11.5px}main{padding:0}.card{break-inside:avoid}tr{break-inside:avoid}}
</style></head><body><main>
<h1>{{.In.Title}}</h1>
<div class="meta">Generated {{date .In.Generated}} by wardmap {{.In.Version}} · read-only analysis; secret values are never read</div>
<div class="cards">
<div class="card"><b class="high">{{.Reach}}</b>secret or cloud identities reachable by one write credential</div>
{{range .Sev}}<div class="card"><b class="{{.}}">{{index $.Counts .}}</b>{{.}} findings</div>{{end}}
</div>
{{if .In.Result.Gaps}}<p class="note"><b>Incomplete data:</b> {{len .In.Result.Gaps}} collection gap(s), listed at the end. A clean result does not prove absence of exposure.</p>{{end}}
<h2>Findings</h2>
{{if .In.Result.Findings}}<div class="scroll"><table><tr><th>Severity</th><th>Rule</th><th>Where</th><th>Finding</th></tr>
{{range .In.Result.Findings}}{{if not (and (eq .RuleID "WM016") (eq .Repo ""))}}<tr><td class="badge nw {{.SeverityStr}}">{{.SeverityStr}}</td><td class="nw"><code>{{.RuleID}}</code></td><td><code>{{.Repo}}{{if .Path}}/{{.Path}}{{end}}</code></td><td>{{.Message}}</td></tr>{{end}}{{end}}
</table></div>{{else}}<p>No findings.</p>{{end}}
<h2>Blast radius per repository</h2>
{{if not .Repos}}<p>No secrets or cloud identities were found reachable in the collected data.</p>{{end}}
{{range .Repos}}<h3><code>{{.Actor}}</code></h3><div class="scroll"><table><tr><th>Reaches</th><th>Kind</th><th>Via</th><th>Verdict</th></tr>
{{range .Edges}}<tr><td><code>{{.To}}</code></td><td>{{.Kind}}</td><td>{{.Via}}{{if .Reason}}<br><span class="meta">{{.Reason}}</span>{{end}}</td><td class="{{.Verdict}}">{{.Verdict}}</td></tr>{{end}}
</table></div>{{end}}
{{if .In.HuntRun}}<h2>Indicators of compromise</h2>
{{if .In.Hits}}<div class="scroll"><table><tr><th>Confidence</th><th>Pack</th><th>Indicator</th><th>Repository</th><th>Evidence</th><th>In window</th></tr>
{{range .In.Hits}}<tr><td class="badge {{if eq .Confidence "high"}}high{{else if eq .Confidence "medium"}}medium{{else}}low{{end}}">{{.Confidence}}</td><td>{{.Pack}}</td><td><code>{{.Indicator}}</code></td><td>{{.Repo}}</td><td>{{.Evidence}}</td><td>{{if .InWindow}}yes{{end}}</td></tr>{{end}}
</table></div>{{else}}<p>No indicators matched. This does not prove the absence of compromise.</p>{{end}}{{end}}
{{if .In.Result.Gaps}}<h2>Collection gaps</h2><ul>{{range .In.Result.Gaps}}<li>{{.}}</li>{{end}}</ul>{{end}}
<p class="meta">Wardmap reports exposure, not compromise. https://github.com/Breaktroughf1/wardmap</p>
</main></body></html>
`))
