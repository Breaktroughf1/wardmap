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

// CloudTrail imports AssumeRoleWithWebIdentity events issued to GitHub
// tokens, from `lookup-events` output or raw trail log files.
func CloudTrail(path string) ([]model.OIDCAssumeEvent, error) {
	var raw struct {
		Events []struct {
			CloudTrailEvent string `json:"CloudTrailEvent"`
		} `json:"Events"`
		Records []json.RawMessage `json:"Records"`
	}
	if err := readJSON(path, &raw); err != nil {
		return nil, err
	}
	var recs []json.RawMessage
	recs = append(recs, raw.Records...)
	for _, e := range raw.Events {
		recs = append(recs, json.RawMessage(e.CloudTrailEvent))
	}
	var out []model.OIDCAssumeEvent
	for _, r := range recs {
		var ev struct {
			EventName    string    `json:"eventName"`
			EventTime    time.Time `json:"eventTime"`
			SourceIP     string    `json:"sourceIPAddress"`
			UserAgent    string    `json:"userAgent"`
			ErrorCode    string    `json:"errorCode"`
			UserIdentity struct {
				UserName         string `json:"userName"`
				IdentityProvider string `json:"identityProvider"`
			} `json:"userIdentity"`
			RequestParameters struct {
				RoleArn string `json:"roleArn"`
			} `json:"requestParameters"`
		}
		if err := json.Unmarshal(r, &ev); err != nil {
			continue
		}
		if ev.EventName != "AssumeRoleWithWebIdentity" || !strings.Contains(ev.UserIdentity.IdentityProvider, model.GitHubIssuer) {
			continue
		}
		out = append(out, model.OIDCAssumeEvent{Time: ev.EventTime, RoleARN: ev.RequestParameters.RoleArn, Subject: ev.UserIdentity.UserName,
			SourceIP: ev.SourceIP, UserAgent: ev.UserAgent, Error: ev.ErrorCode})
	}
	return out, nil
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
