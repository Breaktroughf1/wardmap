package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/model"
	"github.com/Breaktroughf1/wardmap/internal/workflow"
)

// Options control collection.
type Options struct {
	Owner string   // organisation or user
	Repos []string // explicit owner/name list; empty means every repo of Owner
	// Hunt also collects branches' history, pull requests, commits and runs.
	Hunt bool
	// Since limits hunting telemetry (default 45 days).
	Since time.Time
	// MaxCommitFiles caps per-repo commit detail requests in hunt mode.
	MaxCommitFiles  int
	Concurrency     int
	IncludeArchived bool
	Progress        func(string)
}

// Collect builds a snapshot.
func Collect(ctx context.Context, c *Client, o Options) (*model.Snapshot, error) {
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Since.IsZero() {
		o.Since = time.Now().AddDate(0, 0, -45)
	}
	if o.MaxCommitFiles == 0 {
		o.MaxCommitFiles = 60
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	s := &model.Snapshot{SchemaVersion: model.SchemaVersion, CollectedAt: time.Now().UTC(), Owner: o.Owner}
	col := &collector{c: c, o: o, s: s}

	repos, err := col.listRepos(ctx)
	if err != nil {
		return nil, err
	}
	if s.Owner == "" && len(repos) > 0 {
		s.Owner = strings.SplitN(repos[0].FullName, "/", 2)[0]
	}
	col.orgSecrets(ctx)

	out := make([]model.Repo, len(repos))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i := range repos {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o.Progress("collecting " + repos[i].FullName)
			out[i] = col.repo(ctx, repos[i])
		}(i)
	}
	wg.Wait()
	s.Repos = out
	sort.Strings(s.Gaps)
	return s, ctx.Err()
}

type collector struct {
	c  *Client
	o  Options
	s  *model.Snapshot
	mu sync.Mutex
}

func (col *collector) gap(format string, a ...any) {
	col.mu.Lock()
	col.s.Gaps = append(col.s.Gaps, fmt.Sprintf(format, a...))
	col.mu.Unlock()
}

type apiRepo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
	Archived      bool   `json:"archived"`
}

func (col *collector) listRepos(ctx context.Context) ([]model.Repo, error) {
	var raw []apiRepo
	if len(col.o.Repos) > 0 {
		for _, r := range col.o.Repos {
			var ar apiRepo
			if _, err := col.c.Get(ctx, "/repos/"+r, &ar); err != nil {
				return nil, fmt.Errorf("repository %s: %w", r, err)
			}
			raw = append(raw, ar)
		}
	} else {
		if col.o.Owner == "" {
			return nil, fmt.Errorf("an owner (--org) or explicit --repo list is required")
		}
		err := paginate(ctx, col.c, "/orgs/"+url.PathEscape(col.o.Owner)+"/repos?type=all&per_page=100", func(p []apiRepo) { raw = append(raw, p...) })
		if IsAccessDenied(err) {
			raw = nil
			err = paginate(ctx, col.c, "/users/"+url.PathEscape(col.o.Owner)+"/repos?type=owner&per_page=100", func(p []apiRepo) { raw = append(raw, p...) })
		}
		if err != nil {
			return nil, err
		}
	}
	var out []model.Repo
	for _, r := range raw {
		if r.Archived && !col.o.IncludeArchived {
			continue
		}
		out = append(out, model.Repo{FullName: r.FullName, DefaultBranch: r.DefaultBranch,
			Private: r.Private || r.Visibility == "internal", Archived: r.Archived})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out, nil
}

func (col *collector) orgSecrets(ctx context.Context) {
	if col.o.Owner == "" {
		return
	}
	var page struct {
		Secrets []struct {
			Name       string    `json:"name"`
			UpdatedAt  time.Time `json:"updated_at"`
			Visibility string    `json:"visibility"`
		} `json:"secrets"`
	}
	path := "/orgs/" + url.PathEscape(col.o.Owner) + "/actions/secrets?per_page=100"
	for path != "" {
		next, err := col.c.Get(ctx, path, &page)
		if err != nil {
			if IsAccessDenied(err) {
				col.gap("organisation secrets for %s not readable (needs org admin or a GitHub App with organization 'Secrets: read'); using per-repository visibility instead", col.o.Owner)
			} else {
				col.gap("organisation secrets for %s: %v", col.o.Owner, err)
			}
			return
		}
		for _, sec := range page.Secrets {
			os := model.OrgSecret{Name: sec.Name, Visibility: sec.Visibility, UpdatedAt: sec.UpdatedAt}
			if sec.Visibility == model.VisibilitySelected {
				var rp struct {
					Repositories []struct {
						FullName string `json:"full_name"`
					} `json:"repositories"`
				}
				p := "/orgs/" + url.PathEscape(col.o.Owner) + "/actions/secrets/" + url.PathEscape(sec.Name) + "/repositories?per_page=100"
				err := paginate(ctx, col.c, p, func(x struct {
					Repositories []struct {
						FullName string `json:"full_name"`
					} `json:"repositories"`
				}) {
					rp.Repositories = append(rp.Repositories, x.Repositories...)
				})
				if err != nil {
					col.gap("selected repositories for org secret %s: %v", sec.Name, err)
				}
				for _, r := range rp.Repositories {
					os.SelectedRepos = append(os.SelectedRepos, r.FullName)
				}
			}
			col.mu.Lock()
			col.s.OrgSecrets = append(col.s.OrgSecrets, os)
			col.mu.Unlock()
		}
		path = next
		page.Secrets = nil
	}
}

type secretsPage struct {
	Secrets []struct {
		Name      string    `json:"name"`
		UpdatedAt time.Time `json:"updated_at"`
	} `json:"secrets"`
}

func (col *collector) secrets(ctx context.Context, path, what string) ([]model.Secret, bool) {
	var out []model.Secret
	err := paginate(ctx, col.c, path, func(p secretsPage) {
		for _, s := range p.Secrets {
			out = append(out, model.Secret{Name: s.Name, UpdatedAt: s.UpdatedAt})
		}
	})
	if err != nil {
		col.gap("%s not readable: %v", what, short(err))
		return nil, false
	}
	return out, true
}

func (col *collector) repo(ctx context.Context, r model.Repo) model.Repo {
	base := "/repos/" + r.FullName
	r.Secrets, _ = col.secrets(ctx, base+"/actions/secrets?per_page=100", r.FullName+" repository secrets")
	if orgVis, ok := col.secrets(ctx, base+"/actions/organization-secrets?per_page=100", r.FullName+" organisation secrets visible to repo"); ok {
		for _, s := range orgVis {
			r.OrgSecretsVisible = append(r.OrgSecretsVisible, s.Name)
		}
	}
	col.environments(ctx, &r)
	col.oidcTemplate(ctx, &r)
	col.branches(ctx, &r)
	col.workflows(ctx, &r)
	if col.o.Hunt {
		col.hunt(ctx, &r)
	}
	return r
}

func (col *collector) environments(ctx context.Context, r *model.Repo) {
	base := "/repos/" + r.FullName
	type envAPI struct {
		Name            string `json:"name"`
		ProtectionRules []struct {
			Type      string `json:"type"`
			WaitTimer int    `json:"wait_timer"`
		} `json:"protection_rules"`
		DeploymentBranchPolicy *struct {
			ProtectedBranches    bool `json:"protected_branches"`
			CustomBranchPolicies bool `json:"custom_branch_policies"`
		} `json:"deployment_branch_policy"`
	}
	var envs []envAPI
	err := paginate(ctx, col.c, base+"/environments?per_page=100", func(p struct {
		Environments []envAPI `json:"environments"`
	}) {
		envs = append(envs, p.Environments...)
	})
	if err != nil {
		col.gap("%s environments not readable: %v", r.FullName, short(err))
		return
	}
	for _, e := range envs {
		env := model.Environment{Name: e.Name, BranchPolicy: model.BranchPolicyAll}
		for _, pr := range e.ProtectionRules {
			switch pr.Type {
			case "required_reviewers":
				env.RequiredReviewers = true
			case "wait_timer":
				env.WaitTimer = pr.WaitTimer
			}
		}
		if p := e.DeploymentBranchPolicy; p != nil {
			if p.ProtectedBranches {
				env.BranchPolicy = model.BranchPolicyProtected
			} else if p.CustomBranchPolicies {
				env.BranchPolicy = model.BranchPolicyCustom
				ep := base + "/environments/" + url.PathEscape(e.Name) + "/deployment-branch-policies?per_page=100"
				err := paginate(ctx, col.c, ep, func(x struct {
					BranchPolicies []struct {
						Name string `json:"name"`
						Type string `json:"type"`
					} `json:"branch_policies"`
				}) {
					for _, bp := range x.BranchPolicies {
						if bp.Type == "" || bp.Type == "branch" {
							env.BranchPatterns = append(env.BranchPatterns, bp.Name)
						} else {
							// Tag policies: tags are attacker-creatable.
							env.BranchPatterns = append(env.BranchPatterns, "*")
						}
					}
				})
				if err != nil {
					col.gap("%s environment %s branch policies: %v", r.FullName, e.Name, short(err))
					env.BranchPolicy = model.BranchPolicyAll
				}
			}
		}
		env.Secrets, _ = col.secrets(ctx, base+"/environments/"+url.PathEscape(e.Name)+"/secrets?per_page=100", r.FullName+" environment "+e.Name+" secrets")
		r.Environments = append(r.Environments, env)
	}
}

func (col *collector) oidcTemplate(ctx context.Context, r *model.Repo) {
	var t struct {
		UseDefault       bool     `json:"use_default"`
		IncludeClaimKeys []string `json:"include_claim_keys"`
	}
	if _, err := col.c.Get(ctx, "/repos/"+r.FullName+"/actions/oidc/customization/sub", &t); err != nil {
		if !IsAccessDenied(err) {
			col.gap("%s OIDC subject template: %v", r.FullName, short(err))
		}
		return
	}
	if !t.UseDefault {
		r.OIDCSubTemplate = t.IncludeClaimKeys
	}
}

func (col *collector) branches(ctx context.Context, r *model.Repo) {
	err := paginate(ctx, col.c, "/repos/"+r.FullName+"/branches?per_page=100", func(p []struct {
		Name      string `json:"name"`
		Protected bool   `json:"protected"`
	}) {
		for _, b := range p {
			r.Branches = append(r.Branches, b.Name)
			if b.Protected {
				r.ProtectedBranches = append(r.ProtectedBranches, b.Name)
			}
		}
	})
	if err != nil {
		col.gap("%s branches: %v", r.FullName, short(err))
	}
}

func (col *collector) workflows(ctx context.Context, r *model.Repo) {
	var entries []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}
	ref := url.QueryEscape(r.DefaultBranch)
	if _, err := col.c.Get(ctx, "/repos/"+r.FullName+"/contents/.github/workflows?ref="+ref, &entries); err != nil {
		if !IsAccessDenied(err) {
			col.gap("%s workflows: %v", r.FullName, short(err))
		}
		return
	}
	for _, e := range entries {
		if e.Type != "file" || !(strings.HasSuffix(e.Path, ".yml") || strings.HasSuffix(e.Path, ".yaml")) {
			continue
		}
		var f struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
			Size     int    `json:"size"`
		}
		path := "/repos/" + r.FullName + "/contents/" + e.Path + "?ref=" + ref
		if _, err := col.c.Get(ctx, path, &f); err != nil {
			col.gap("%s %s: %v", r.FullName, e.Path, short(err))
			continue
		}
		var data []byte
		if f.Encoding == "base64" && (f.Content != "" || f.Size == 0) {
			var err error
			if data, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", "")); err != nil {
				col.gap("%s %s: bad encoding", r.FullName, e.Path)
				continue
			}
		} else {
			// Large files come back with encoding "none" and no content.
			raw, err := col.c.GetRaw(ctx, path)
			if err != nil {
				col.gap("%s %s: %v", r.FullName, e.Path, short(err))
				continue
			}
			data = raw
		}
		r.Workflows = append(r.Workflows, workflow.Parse(e.Path, data))
	}
}

func (col *collector) hunt(ctx context.Context, r *model.Repo) {
	base := "/repos/" + r.FullName
	since := col.o.Since
	// Pull requests (newest first), stop once older than since.
	path := base + "/pulls?state=all&sort=created&direction=desc&per_page=100"
	for path != "" {
		var prs []struct {
			Number    int       `json:"number"`
			Title     string    `json:"title"`
			CreatedAt time.Time `json:"created_at"`
			User      struct {
				Login string `json:"login"`
			} `json:"user"`
			Head struct {
				Ref string `json:"ref"`
			} `json:"head"`
		}
		next, err := col.c.Get(ctx, path, &prs)
		if err != nil {
			col.gap("%s pull requests: %v", r.FullName, short(err))
			break
		}
		old := false
		for _, p := range prs {
			if p.CreatedAt.Before(since) {
				old = true
				break
			}
			r.PullRequests = append(r.PullRequests, model.PullRequest{Number: p.Number, Title: p.Title, Author: p.User.Login, HeadRef: p.Head.Ref, CreatedAt: p.CreatedAt})
		}
		if old {
			break
		}
		path = next
	}
	// Commits on every branch would be expensive; the default branch plus
	// per-commit file lists for the newest MaxCommitFiles commits covers the
	// inject-then-revert pattern.
	type apiCommit struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string    `json:"name"`
				Date time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
		Author *struct {
			Login string `json:"login"`
		} `json:"author"`
		Files []struct {
			Filename string `json:"filename"`
		} `json:"files"`
	}
	var commits []apiCommit
	err := paginate(ctx, col.c, base+"/commits?per_page=100&since="+url.QueryEscape(since.Format(time.RFC3339)), func(p []apiCommit) { commits = append(commits, p...) })
	if IsEmptyRepo(err) {
		return // no commits, so nothing else to hunt in
	}
	if err != nil {
		col.gap("%s commits: %v", r.FullName, short(err))
	}
	for i, c := range commits {
		mc := model.Commit{SHA: c.SHA, Message: c.Commit.Message, Author: c.Commit.Author.Name, Date: c.Commit.Author.Date}
		if c.Author != nil && c.Author.Login != "" {
			mc.Author = c.Author.Login
		}
		if i < col.o.MaxCommitFiles {
			var d apiCommit
			if _, err := col.c.Get(ctx, base+"/commits/"+c.SHA, &d); err == nil {
				for _, f := range d.Files {
					mc.Files = append(mc.Files, f.Filename)
				}
			}
		} else if i == col.o.MaxCommitFiles {
			col.gap("%s: hunt sampled file lists for the newest %d of %d commits since %s (raise with --max-commit-files)", r.FullName, col.o.MaxCommitFiles, len(commits), since.Format("2006-01-02"))
		}
		r.Commits = append(r.Commits, mc)
	}
	path = base + "/actions/runs?per_page=100&created=" + url.QueryEscape(">="+since.Format("2006-01-02"))
	for pages := 0; path != "" && pages < 10; pages++ {
		var page struct {
			WorkflowRuns []struct {
				WorkflowID int64     `json:"workflow_id"`
				Path       string    `json:"path"`
				RunNumber  int       `json:"run_number"`
				Event      string    `json:"event"`
				HeadBranch string    `json:"head_branch"`
				CreatedAt  time.Time `json:"created_at"`
			} `json:"workflow_runs"`
		}
		next, err := col.c.Get(ctx, path, &page)
		if err != nil {
			col.gap("%s workflow runs: %v", r.FullName, short(err))
			break
		}
		for _, w := range page.WorkflowRuns {
			r.Runs = append(r.Runs, model.Run{WorkflowID: w.WorkflowID, WorkflowPath: w.Path, RunNumber: w.RunNumber, Event: w.Event, HeadBranch: w.HeadBranch, CreatedAt: w.CreatedAt})
		}
		path = next
	}
}

// paginate fetches every page of path, decoding each into T.
func paginate[T any](ctx context.Context, c *Client, path string, f func(T)) error {
	for pages := 0; path != "" && pages < 200; pages++ {
		var page T
		next, err := c.Get(ctx, path, &page)
		if err != nil {
			return err
		}
		f(page)
		path = next
	}
	return nil
}

func short(err error) string {
	var se *StatusError
	if e, ok := err.(*StatusError); ok {
		se = e
		return fmt.Sprintf("HTTP %d %s", se.Code, se.Msg)
	}
	return err.Error()
}
