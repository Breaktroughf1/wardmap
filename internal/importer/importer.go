// Package importer reads cloud trust configuration exported with the
// providers' own read-only CLIs, so Wardmap never needs cloud credentials.
//
//	aws iam get-account-authorization-details --filter Role > aws.json
//	aws iam list-roles > aws.json
//	az ad app federated-credential list --id <APP_ID> > fic-<APP_ID>.json
//	gcloud iam workload-identity-pools providers list \
//	    --workload-identity-pool=<POOL> --location=global --format=json > gcp.json
//	aws cloudtrail lookup-events --lookup-attributes \
//	    AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity > ct.json
//	aws cloudtrail lookup-events --lookup-attributes \
//	    AttributeKey=EventName,AttributeValue=UpdateAssumeRolePolicy > ct-trust.json
package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Breaktroughf1/wardmap/internal/model"
	"github.com/Breaktroughf1/wardmap/internal/oidc"
)

// AWS imports IAM roles.
func AWS(path string) ([]model.AWSRole, error) {
	var raw struct {
		Roles          []awsRole `json:"Roles"`
		RoleDetailList []awsRole `json:"RoleDetailList"`
	}
	if err := readJSON(path, &raw); err != nil {
		return nil, err
	}
	var out []model.AWSRole
	for _, r := range append(raw.Roles, raw.RoleDetailList...) {
		doc, err := oidc.DecodePolicy(r.AssumeRolePolicyDocument)
		if err != nil {
			return nil, fmt.Errorf("%s: role %s: %w", path, r.Arn, err)
		}
		out = append(out, model.AWSRole{ARN: r.Arn, TrustPolicy: doc})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no roles found (expected output of `aws iam list-roles` or `get-account-authorization-details`)", path)
	}
	return out, nil
}

type awsRole struct {
	Arn                      string `json:"Arn"`
	AssumeRolePolicyDocument any    `json:"AssumeRolePolicyDocument"`
}

var guidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// Azure imports federated credentials. appID may be empty when the file name
// contains the application (client) id, e.g. fic-<APP_ID>.json.
func Azure(path, appID string) ([]model.AzureFIC, error) {
	if appID == "" {
		appID = guidRe.FindString(filepath.Base(path))
	}
	if appID == "" {
		return nil, fmt.Errorf("%s: pass the app id (appid=path) or include it in the file name", path)
	}
	var raw []struct {
		Name      string   `json:"name"`
		Issuer    string   `json:"issuer"`
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
		CME       *struct {
			Value string `json:"value"`
		} `json:"claimsMatchingExpression"`
	}
	if err := readJSON(path, &raw); err != nil {
		return nil, err
	}
	var out []model.AzureFIC
	for _, f := range raw {
		fic := model.AzureFIC{AppID: appID, Name: f.Name, Issuer: f.Issuer, Subject: f.Subject, Audiences: f.Audiences}
		if f.CME != nil {
			fic.ClaimsMatching = f.CME.Value
		}
		out = append(out, fic)
	}
	return out, nil
}

// GCP imports workload identity pool providers.
func GCP(path string) ([]model.GCPProvider, error) {
	var raw []struct {
		Name               string            `json:"name"`
		AttributeCondition string            `json:"attributeCondition"`
		AttributeMapping   map[string]string `json:"attributeMapping"`
		Disabled           bool              `json:"disabled"`
		State              string            `json:"state"`
		OIDC               struct {
			IssuerURI string `json:"issuerUri"`
		} `json:"oidc"`
	}
	if err := readJSON(path, &raw); err != nil {
		return nil, err
	}
	var out []model.GCPProvider
	for _, p := range raw {
		out = append(out, model.GCPProvider{Name: p.Name, IssuerURI: p.OIDC.IssuerURI, AttributeCondition: p.AttributeCondition,
			AttributeMapping: p.AttributeMapping, Disabled: p.Disabled || strings.EqualFold(p.State, "DELETED")})
	}
	return out, nil
}

// persistenceEvents are CloudTrail management events worth keeping for
// hunting: trust and credential changes an attacker uses to stay in.
var persistenceEvents = map[string]bool{
	"UpdateAssumeRolePolicy": true, "CreateAccessKey": true, "CreateRole": true,
	"AttachRolePolicy": true, "PutRolePolicy": true, "CreateLoginProfile": true,
	"UpdateLoginProfile": true, "CreateUser": true, "AddUserToGroup": true,
	"CreateOpenIDConnectProvider": true, "UpdateOpenIDConnectProviderThumbprint": true,
}

// CloudTrail imports AssumeRoleWithWebIdentity events issued to GitHub
// tokens, plus IAM persistence events, from `lookup-events` output or raw
// trail log files.
func CloudTrail(path string) ([]model.OIDCAssumeEvent, []model.CloudTrailEvent, error) {
	var raw struct {
		Events []struct {
			CloudTrailEvent string `json:"CloudTrailEvent"`
		} `json:"Events"`
		Records []json.RawMessage `json:"Records"`
	}
	if err := readJSON(path, &raw); err != nil {
		return nil, nil, err
	}
	var recs []json.RawMessage
	recs = append(recs, raw.Records...)
	for _, e := range raw.Events {
		recs = append(recs, json.RawMessage(e.CloudTrailEvent))
	}
	var oidcEvents []model.OIDCAssumeEvent
	var other []model.CloudTrailEvent
	for _, r := range recs {
		var ev struct {
			EventName    string    `json:"eventName"`
			EventTime    time.Time `json:"eventTime"`
			SourceIP     string    `json:"sourceIPAddress"`
			UserAgent    string    `json:"userAgent"`
			ErrorCode    string    `json:"errorCode"`
			UserIdentity struct {
				Type             string `json:"type"`
				ARN              string `json:"arn"`
				UserName         string `json:"userName"`
				IdentityProvider string `json:"identityProvider"`
			} `json:"userIdentity"`
			RequestParameters struct {
				RoleArn         string `json:"roleArn"`
				RoleName        string `json:"roleName"`
				UserName        string `json:"userName"`
				RoleSessionName string `json:"roleSessionName"`
			} `json:"requestParameters"`
		}
		if err := json.Unmarshal(r, &ev); err != nil {
			continue
		}
		switch {
		case ev.EventName == "AssumeRoleWithWebIdentity" && strings.Contains(ev.UserIdentity.IdentityProvider, model.GitHubIssuer):
			oidcEvents = append(oidcEvents, model.OIDCAssumeEvent{Time: ev.EventTime, RoleARN: ev.RequestParameters.RoleArn,
				Subject: ev.UserIdentity.UserName, SessionName: ev.RequestParameters.RoleSessionName,
				SourceIP: ev.SourceIP, UserAgent: ev.UserAgent, Error: ev.ErrorCode})
		case persistenceEvents[ev.EventName]:
			target := ev.RequestParameters.RoleName
			if target == "" {
				target = ev.RequestParameters.UserName
			}
			other = append(other, model.CloudTrailEvent{Time: ev.EventTime, EventName: ev.EventName,
				Principal: ev.UserIdentity.ARN, SessionName: sessionName(ev.UserIdentity.ARN),
				Target: target, SourceIP: ev.SourceIP, Error: ev.ErrorCode})
		}
	}
	return oidcEvents, other, nil
}

// sessionName returns SESSION from arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION.
func sessionName(arn string) string {
	if !strings.Contains(arn, ":assumed-role/") {
		return ""
	}
	return arn[strings.LastIndexByte(arn, '/')+1:]
}

var ficNameRe = regexp.MustCompile(`(?i)"name"\s*:\s*"([^"]+)"`)

// AzureAudit imports Entra ID directory audit records that changed an
// application's federated identity credentials. It accepts the Microsoft
// Graph response ({"value": [...]}) or a bare array, for example from
//
//	az rest --method get --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Update application'"
//
// Credential names are taken from the new value of any modified property
// whose name mentions federated credentials; names already present in the
// old value are skipped, so only additions are reported.
func AzureAudit(path string) ([]model.AzureAuditEvent, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type prop struct {
		DisplayName string `json:"displayName"`
		OldValue    string `json:"oldValue"`
		NewValue    string `json:"newValue"`
	}
	type record struct {
		ActivityDateTime    time.Time `json:"activityDateTime"`
		ActivityDisplayName string    `json:"activityDisplayName"`
		Result              string    `json:"result"`
		InitiatedBy         struct {
			User *struct {
				UserPrincipalName string `json:"userPrincipalName"`
			} `json:"user"`
			App *struct {
				DisplayName string `json:"displayName"`
			} `json:"app"`
		} `json:"initiatedBy"`
		TargetResources []struct {
			ID                 string `json:"id"`
			DisplayName        string `json:"displayName"`
			Type               string `json:"type"`
			ModifiedProperties []prop `json:"modifiedProperties"`
		} `json:"targetResources"`
	}
	var recs []record
	var wrapped struct {
		Value []record `json:"value"`
	}
	if err := json.Unmarshal(b, &wrapped); err == nil && wrapped.Value != nil {
		recs = wrapped.Value
	} else if err := json.Unmarshal(b, &recs); err != nil {
		return nil, fmt.Errorf("%s: expected a Graph directoryAudits response or array: %w", path, err)
	}
	var out []model.AzureAuditEvent
	for _, r := range recs {
		for _, t := range r.TargetResources {
			var names []string
			touched := strings.Contains(strings.ToLower(r.ActivityDisplayName), "federated")
			for _, p := range t.ModifiedProperties {
				if !strings.Contains(strings.ToLower(p.DisplayName), "federated") {
					continue
				}
				touched = true
				old := map[string]bool{}
				for _, m := range ficNameRe.FindAllStringSubmatch(unquote(p.OldValue), -1) {
					old[m[1]] = true
				}
				for _, m := range ficNameRe.FindAllStringSubmatch(unquote(p.NewValue), -1) {
					if !old[m[1]] {
						names = append(names, m[1])
					}
				}
			}
			if !touched {
				continue
			}
			ev := model.AzureAuditEvent{Time: r.ActivityDateTime, Activity: r.ActivityDisplayName, Result: r.Result,
				AppID: t.ID, AppName: t.DisplayName, FICNames: names}
			if u := r.InitiatedBy.User; u != nil {
				ev.Initiator = u.UserPrincipalName
			} else if a := r.InitiatedBy.App; a != nil {
				ev.Initiator = a.DisplayName
			}
			out = append(out, ev)
		}
	}
	return out, nil
}

// unquote decodes a JSON-encoded string value (Graph audit values are JSON
// strings containing JSON); other input is returned unchanged.
func unquote(s string) string {
	var v string
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		return v
	}
	return s
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
