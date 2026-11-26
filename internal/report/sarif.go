package report

import (
	"io"
	"strings"

	"github.com/Breaktroughf1/wardmap/internal/analysis"
)

// SARIF writes findings as SARIF 2.1.0. When repoRelative is set (scanning
// the current repository in CI), locations are paths inside that repository
// so GitHub code scanning can annotate them.
func SARIF(w io.Writer, res analysis.Result, version, repoRelative string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		Help             msg            `json:"help"`
		HelpURI          string         `json:"helpUri"`
		Properties       map[string]any `json:"properties"`
	}
	rules := make([]rule, 0, len(Rules))
	idx := map[string]int{}
	for i, r := range Rules {
		idx[r.ID] = i
		rules = append(rules, rule{ID: r.ID, Name: r.Name, ShortDescription: msg{r.Short}, Help: msg{r.Help},
			HelpURI:    "https://github.com/Breaktroughf1/wardmap/blob/main/docs/rules.md#" + strings.ToLower(r.ID),
			Properties: map[string]any{"tags": []string{"security", "ci", "oidc"}}})
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		RuleIndex           int               `json:"ruleIndex"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []map[string]any  `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
	}
	results := []result{}
	for _, f := range res.Findings {
		uri := ".github/workflows"
		if f.Path != "" {
			uri = f.Path
			if repoRelative == "" && f.Repo != "" {
				uri = f.Repo + "/" + f.Path
			}
		} else if repoRelative == "" && f.Repo != "" {
			uri = f.Repo
		}
		if repoRelative != "" && f.Repo != "" && f.Repo != repoRelative {
			continue
		}
		results = append(results, result{
			RuleID: f.RuleID, RuleIndex: idx[f.RuleID], Level: level(f.Severity), Message: msg{f.Message},
			Locations: []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": uri},
				"region":           map[string]any{"startLine": 1},
			}}},
			PartialFingerprints: map[string]string{"wardmap/v1": f.Fingerprint},
			Properties:          map[string]any{"security-severity": secSev(f.Severity), "wardmap-severity": f.SeverityStr},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "wardmap", "version": version, "informationUri": "https://github.com/Breaktroughf1/wardmap", "rules": rules,
			}},
			"results": results,
		}},
	}
	return JSON(w, doc)
}

func level(s analysis.Severity) string {
	switch {
	case s >= analysis.High:
		return "error"
	case s == analysis.Medium:
		return "warning"
	}
	return "note"
}

func secSev(s analysis.Severity) string {
	return [...]string{"0.0", "3.0", "5.5", "8.0", "9.5"}[s]
}
