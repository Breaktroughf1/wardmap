# Token permissions

Wardmap issues only `GET` requests. Prefer, in order:

1. **Offline mode.** No token at all: `wardmap local`, or the Action's default `mode: offline`. This covers workflow-level rules (WM008, WM009, WM011, WM015, WM017).
2. **A GitHub App** installed on the organisation with the read-only permissions below. App tokens are short-lived and scoped to the installation.
3. **A fine-grained personal access token** with the same read-only permissions, restricted to the repositories you want scanned and given a short expiry.

Never give Wardmap a classic PAT with `repo` or `admin:org` scope. After a token-theft campaign, that is exactly the kind of credential you are trying to get rid of.

## Read-only permissions used

Permission names follow GitHub's fine-grained permission model. Check GitHub's REST documentation for each endpoint if your organisation uses custom roles.

| Data | Endpoint | Permission (read) | Without it |
|---|---|---|---|
| Repositories | `GET /orgs/{org}/repos`, `GET /repos/{r}` | Metadata | required |
| Workflows | `GET /repos/{r}/contents/.github/workflows` | Contents | workflow rules skipped |
| Repository secret names | `GET /repos/{r}/actions/secrets` | Secrets | gap recorded |
| Org secrets visible to a repo | `GET /repos/{r}/actions/organization-secrets` | Secrets | gap recorded |
| Org secret visibility | `GET /orgs/{org}/actions/secrets` | Organization: Secrets | falls back to per-repo visibility |
| Environments, reviewers, branch policies, env secrets | `GET /repos/{r}/environments…` | Environments, Secrets | gap recorded |
| OIDC subject template | `GET /repos/{r}/actions/oidc/customization/sub` | Actions | default template assumed |
| Branches and protection flag | `GET /repos/{r}/branches` | Contents / Metadata | nothing assumed protected |
| Hunt: PRs, commits, runs | `pulls`, `commits`, `actions/runs` | Pull requests, Contents, Actions | hunt indicators skipped |

Anything Wardmap cannot read is recorded as a **collection gap** (WM016) and printed at the top of the report. Missing data is never treated as safe.

## Cloud side

Wardmap never calls cloud APIs. Export the data yourself with read-only roles:

| Cloud | Command | Minimal permission |
|---|---|---|
| AWS | `aws iam list-roles` or `aws iam get-account-authorization-details --filter Role` | `iam:ListRoles` / `iam:GetAccountAuthorizationDetails` |
| AWS CloudTrail | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity` | `cloudtrail:LookupEvents` |
| AWS CloudTrail (persistence) | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy` (repeat for `CreateAccessKey`) | `cloudtrail:LookupEvents` |
| Azure | `az ad app federated-credential list --id <APP_ID>` | `Application.Read.All` |
| Entra audit logs | `az rest --method get --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDisplayName eq 'Update application'"` | `AuditLog.Read.All` |
| GCP | `gcloud iam workload-identity-pools providers list --workload-identity-pool=<POOL> --location=global --format=json` | `iam.workloadIdentityPoolProviders.list` |

`lookup-events` covers the last 90 days of management events. For older activity, export from your trail's S3 bucket and pass the log files with `--cloudtrail`; raw `{"Records": [...]}` files are accepted. Entra audit logs are retained for 30 days on most tenants, so export them early in an investigation.
