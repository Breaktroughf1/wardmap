package importer

import (
	"os"
	"path/filepath"
	"testing"
)

const demo = "../../examples/demo/"

func TestAWS(t *testing.T) {
	roles, err := AWS(demo + "aws-roles.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 4 {
		t.Fatalf("roles %d", len(roles))
	}
	for _, r := range roles {
		if r.TrustPolicy["Statement"] == nil {
			t.Errorf("%s: policy not decoded (URL-encoded input must be handled)", r.ARN)
		}
	}
	empty := filepath.Join(t.TempDir(), "e.json")
	_ = os.WriteFile(empty, []byte(`{"Roles":[]}`), 0o600)
	if _, err := AWS(empty); err == nil {
		t.Error("empty export should be an error")
	}
}

func TestAzure(t *testing.T) {
	f, err := Azure(demo+"fic-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 2 || f[0].AppID != "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0" {
		t.Fatalf("%+v", f)
	}
	p := filepath.Join(t.TempDir(), "creds.json")
	_ = os.WriteFile(p, []byte(`[{"name":"x","issuer":"i","claimsMatchingExpression":{"value":"claims['sub'] matches 'repo:a/b:*'"}}]`), 0o600)
	if _, err := Azure(p, ""); err == nil {
		t.Error("missing app id should be an error")
	}
	f, err = Azure(p, "app")
	if err != nil || f[0].ClaimsMatching == "" {
		t.Fatalf("flexible credential not imported: %v %+v", err, f)
	}
}

func TestGCPAndCloudTrail(t *testing.T) {
	p, err := GCP(demo + "gcp-providers.json")
	if err != nil || len(p) != 1 || p[0].AttributeCondition == "" || p[0].IssuerURI == "" {
		t.Fatalf("gcp: %v %+v", err, p)
	}
	ev, other, err := CloudTrail(demo + "cloudtrail.json")
	if err != nil || len(ev) != 2 || ev[0].Subject == "" || ev[0].RoleARN == "" || ev[0].SessionName != "wfx-5d1c" {
		t.Fatalf("cloudtrail: %v %+v", err, ev)
	}
	if len(other) != 2 || other[0].EventName != "UpdateAssumeRolePolicy" || other[0].SessionName != "wfx-5d1c" || other[0].Target != "legacy-ci-admin" || other[1].Target != "ci-deployer" {
		t.Fatalf("persistence events: %+v", other)
	}
	raw := filepath.Join(t.TempDir(), "trail.json")
	_ = os.WriteFile(raw, []byte(`{"Records":[{"eventName":"AssumeRoleWithWebIdentity","eventTime":"2026-11-10T00:00:00Z","userIdentity":{"userName":"repo:a/b:pull_request","identityProvider":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},"requestParameters":{"roleArn":"r"}},{"eventName":"ConsoleLogin"}]}`), 0o600)
	ev, _, err = CloudTrail(raw)
	if err != nil || len(ev) != 1 {
		t.Fatalf("raw trail: %v %+v", err, ev)
	}
}

func TestAzureAudit(t *testing.T) {
	ev, err := AzureAudit(demo + "entra-audit.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 {
		t.Fatalf("only the federated-credential change should be kept: %+v", ev)
	}
	if len(ev[0].FICNames) != 1 || ev[0].FICNames[0] != "wfx-ci-3b9f" || ev[0].Initiator != "example-org-ci-deployer" {
		t.Fatalf("added credential not extracted: %+v", ev[0])
	}
	arr := filepath.Join(t.TempDir(), "a.json")
	_ = os.WriteFile(arr, []byte(`[{"activityDisplayName":"Add federated identity credential","targetResources":[{"displayName":"app"}]}]`), 0o600)
	ev, err = AzureAudit(arr)
	if err != nil || len(ev) != 1 {
		t.Fatalf("bare array with federated activity: %v %+v", err, ev)
	}
	bad := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(bad, []byte(`"nope"`), 0o600)
	if _, err := AzureAudit(bad); err == nil {
		t.Error("non-audit JSON should be an error")
	}
}
