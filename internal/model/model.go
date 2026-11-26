// Package model defines the snapshot format that every Wardmap command reads
// and writes. A snapshot is plain JSON so that it can be produced offline
// (exported by an administrator) and analysed elsewhere without credentials.
package model

import "time"

// SchemaVersion is bumped on any incompatible change to Snapshot.
const SchemaVersion = 1

// Snapshot is the complete, credential-free description of a GitHub estate
// plus the cloud trust that GitHub OIDC tokens can satisfy.
type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	CollectedAt   time.Time `json:"collected_at"`
	Owner         string    `json:"owner,omitempty"`
	// HuntCollected is set when pull requests, commits and workflow runs
	// were collected (collect --hunt).
	HuntCollected bool `json:"hunt_collected,omitempty"`

	OrgSecrets []OrgSecret `json:"org_secrets,omitempty"`
	Repos      []Repo      `json:"repos,omitempty"`

	AWSRoles     []AWSRole     `json:"aws_roles,omitempty"`
	AzureFICs    []AzureFIC    `json:"azure_federated_credentials,omitempty"`
	GCPProviders []GCPProvider `json:"gcp_providers,omitempty"`

	CloudTrail       []OIDCAssumeEvent `json:"cloudtrail_oidc_events,omitempty"`
	CloudTrailEvents []CloudTrailEvent `json:"cloudtrail_events,omitempty"`
	AzureAudit       []AzureAuditEvent `json:"azure_audit_events,omitempty"`

	// Gaps records data that could not be collected (for example because the
	// token lacked a scope). Analysis states these so a clean report is never
	// mistaken for a complete one.
	Gaps []string `json:"collection_gaps,omitempty"`
}

// Visibility values for organisation secrets.
const (
	VisibilityAll      = "all"
	VisibilityPrivate  = "private"
	VisibilitySelected = "selected"
)

// OrgSecret is an organisation-level Actions secret (name only, never value).
type OrgSecret struct {
	Name          string    `json:"name"`
	Visibility    string    `json:"visibility"`
	SelectedRepos []string  `json:"selected_repos,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

// Secret is a repository or environment secret name.
type Secret struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Repo describes one repository.
type Repo struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived,omitempty"`

	Secrets []Secret `json:"secrets,omitempty"`
	// OrgSecretsVisible lists organisation secrets GitHub reports as available
	// to this repository (used when org-level listing is not permitted).
	OrgSecretsVisible []string `json:"org_secrets_visible,omitempty"`

	Environments []Environment `json:"environments,omitempty"`
	Workflows    []Workflow    `json:"workflows,omitempty"`

	// OIDCSubTemplate holds include_claim_keys when the repo customises its
	// OIDC subject; empty means the GitHub default.
	OIDCSubTemplate []string `json:"oidc_sub_template,omitempty"`
	// OwnerID and RepoID are GitHub's immutable numeric IDs (0 when unknown).
	OwnerID int64 `json:"owner_id,omitempty"`
	RepoID  int64 `json:"repo_id,omitempty"`
	// CreatedAt decides the default sub format: repositories created after
	// 15 July 2026 use immutable subjects (repo:OWNER@ID/REPO@ID:...).
	CreatedAt time.Time `json:"created_at,omitempty"`
	// ImmutableSubject is the repository's use_immutable_subject setting
	// (nil when not reported; it then falls back to the organisation).
	ImmutableSubject *bool `json:"use_immutable_subject,omitempty"`
	// SubClaimPrefix is GitHub's reported current sub prefix, when available.
	SubClaimPrefix string `json:"sub_claim_prefix,omitempty"`
	// OIDCSubTemplateUnknown is set when the template could not be read.
	// Trust that might match under some template is then reported as
	// needing review instead of not reachable.
	OIDCSubTemplateUnknown bool `json:"oidc_sub_template_unknown,omitempty"`

	// ProtectedBranches are branches a write credential cannot change on its
	// own: GitHub confirmed that merging needs at least one approving review
	// (ruleset or classic protection). Empty when unknown, which analysis
	// treats conservatively as "nothing is protected".
	ProtectedBranches []string `json:"protected_branches,omitempty"`
	// WeakProtected are branches GitHub marks protected where an approving
	// review is not required, or could not be confirmed. A write credential
	// can merge its own change into them.
	WeakProtected []string `json:"weakly_protected_branches,omitempty"`

	// Hunting telemetry (optional).
	Branches     []string      `json:"branches,omitempty"`
	PullRequests []PullRequest `json:"pull_requests,omitempty"`
	Commits      []Commit      `json:"commits,omitempty"`
	Runs         []Run         `json:"runs,omitempty"`
}

// Environment is a GitHub deployment environment.
type Environment struct {
	Name    string   `json:"name"`
	Secrets []Secret `json:"secrets,omitempty"`
	// RequiredReviewers is true when a human must approve each deployment.
	RequiredReviewers bool `json:"required_reviewers"`
	// WaitTimer in minutes; informational.
	WaitTimer int `json:"wait_timer,omitempty"`
	// BranchPolicy is one of "all" (no restriction), "protected" (protected
	// branches only) or "custom" (see BranchPatterns).
	BranchPolicy   string   `json:"branch_policy"`
	BranchPatterns []string `json:"branch_patterns,omitempty"`
}

// Environment branch policies.
const (
	BranchPolicyAll       = "all"
	BranchPolicyProtected = "protected"
	BranchPolicyCustom    = "custom"
)

// Workflow is a parsed workflow file.
type Workflow struct {
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
	// RunSources are the workflow names listed under on.workflow_run.workflows.
	RunSources []string `json:"workflow_run_sources,omitempty"`
	Triggers   []string `json:"triggers"`
	// PushBranches are the branch filters on the push trigger ("*" if none).
	PushBranches []string `json:"push_branches,omitempty"`
	Jobs         []Job    `json:"jobs"`
	// Endpoints are URLs and IPv4 addresses that appear in the file, used to
	// match exfiltration indicators.
	Endpoints  []string `json:"endpoints,omitempty"`
	ParseError string   `json:"parse_error,omitempty"`
}

// Job is one job inside a workflow.
type Job struct {
	ID           string   `json:"id"`
	Environment  string   `json:"environment,omitempty"`
	IDTokenWrite bool     `json:"id_token_write"`
	SecretsUsed  []string `json:"secrets_used,omitempty"`
	InheritsAll  bool     `json:"secrets_inherit,omitempty"`
	// DumpsSecrets is set when the job serialises the whole secrets or vars
	// context (toJSON(secrets)), which legitimate workflows rarely do.
	DumpsSecrets bool         `json:"dumps_secrets,omitempty"`
	Steps        []StepUse    `json:"uses,omitempty"`
	CloudLogins  []CloudLogin `json:"cloud_logins,omitempty"`
	ChecksOutPR  bool         `json:"checks_out_pr_head,omitempty"`
}

// StepUse is a `uses:` reference and the secrets passed to it.
type StepUse struct {
	Uses        string   `json:"uses"`
	Pinned      bool     `json:"pinned"`
	ThirdParty  bool     `json:"third_party"`
	SecretsPass []string `json:"secrets_passed,omitempty"`
}

// CloudLogin is a recognised cloud login step.
type CloudLogin struct {
	Provider string `json:"provider"` // aws | azure | gcp
	Target   string `json:"target"`   // role ARN, client id, or WIF provider
	UsesOIDC bool   `json:"uses_oidc"`
}

// PullRequest is minimal PR metadata for hunting.
type PullRequest struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	Author    string    `json:"author"`
	HeadRef   string    `json:"head_ref"`
	CreatedAt time.Time `json:"created_at"`
}

// Commit is minimal commit metadata for hunting.
type Commit struct {
	SHA     string    `json:"sha"`
	Message string    `json:"message"`
	Author  string    `json:"author"`
	Date    time.Time `json:"date"`
	Files   []string  `json:"files,omitempty"`
}

// Run is minimal workflow-run metadata for hunting.
type Run struct {
	WorkflowID   int64     `json:"workflow_id"`
	WorkflowPath string    `json:"workflow_path"`
	RunNumber    int       `json:"run_number"`
	Event        string    `json:"event"`
	HeadBranch   string    `json:"head_branch"`
	CreatedAt    time.Time `json:"created_at"`
}

// AWSRole is an IAM role and its trust policy document.
type AWSRole struct {
	ARN         string         `json:"arn"`
	TrustPolicy map[string]any `json:"trust_policy"`
}

// AzureFIC is an Entra application federated identity credential.
type AzureFIC struct {
	AppID          string   `json:"app_id"`
	AppName        string   `json:"app_name,omitempty"`
	Name           string   `json:"name"`
	Issuer         string   `json:"issuer"`
	Subject        string   `json:"subject,omitempty"`
	Audiences      []string `json:"audiences,omitempty"`
	ClaimsMatching string   `json:"claims_matching_expression,omitempty"`
}

// GCPProvider is a workload identity pool provider.
type GCPProvider struct {
	Name               string            `json:"name"`
	IssuerURI          string            `json:"issuer_uri"`
	AttributeCondition string            `json:"attribute_condition,omitempty"`
	AttributeMapping   map[string]string `json:"attribute_mapping,omitempty"`
	Disabled           bool              `json:"disabled,omitempty"`
}

// OIDCAssumeEvent is a CloudTrail AssumeRoleWithWebIdentity event issued from
// a GitHub OIDC token.
type OIDCAssumeEvent struct {
	Time        time.Time `json:"time"`
	RoleARN     string    `json:"role_arn"`
	Subject     string    `json:"subject"`
	SessionName string    `json:"session_name,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// CloudTrailEvent is any other CloudTrail management event relevant to
// hunting (UpdateAssumeRolePolicy, CreateAccessKey, ...).
type CloudTrailEvent struct {
	Time        time.Time `json:"time"`
	EventName   string    `json:"event_name"`
	Principal   string    `json:"principal"`              // caller ARN
	SessionName string    `json:"session_name,omitempty"` // assumed-role session name
	Target      string    `json:"target,omitempty"`       // role or user acted on
	SourceIP    string    `json:"source_ip,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// AzureAuditEvent is an Entra ID directory audit record that touched an
// application's federated identity credentials.
type AzureAuditEvent struct {
	Time      time.Time `json:"time"`
	Activity  string    `json:"activity"`
	Result    string    `json:"result,omitempty"`
	Initiator string    `json:"initiator,omitempty"`
	AppID     string    `json:"app_id,omitempty"`
	AppName   string    `json:"app_name,omitempty"`
	// FICNames are credential names found in the new values of the
	// federated-identity-credential property.
	FICNames []string `json:"fic_names,omitempty"`
}

// GitHubIssuer is the GitHub Actions OIDC issuer host.
const GitHubIssuer = "token.actions.githubusercontent.com"
