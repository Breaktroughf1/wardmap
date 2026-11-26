package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Breaktroughf1/wardmap/internal/model"
	"github.com/Breaktroughf1/wardmap/internal/oidc"
)

// Terraform reads `terraform show -json` output, from a plan file or from
// state, and returns the GitHub OIDC trust it declares: aws_iam_role trust
// policies, Entra federated identity credentials (azuread and azurerm
// providers) and GCP workload identity pool providers. Nothing is applied
// and no provider is contacted.
//
//	terraform plan -out tf.plan && terraform show -json tf.plan > tf.json
//	terraform show -json > tf-state.json
func Terraform(path string) ([]model.AWSRole, []model.AzureFIC, []model.GCPProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var doc struct {
		Values        *tfValues `json:"values"`
		PlannedValues *tfValues `json:"planned_values"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	vals := doc.PlannedValues
	if vals == nil {
		vals = doc.Values
	}
	if vals == nil {
		return nil, nil, nil, fmt.Errorf("%s: not `terraform show -json` output (no values or planned_values)", path)
	}
	var resources []tfResource
	var walk func(m tfModule)
	walk = func(m tfModule) {
		resources = append(resources, m.Resources...)
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(vals.RootModule)
	sort.Slice(resources, func(i, j int) bool { return resources[i].Address < resources[j].Address })

	var roles []model.AWSRole
	var fics []model.AzureFIC
	var gcp []model.GCPProvider
	for _, r := range resources {
		if r.Mode != "" && r.Mode != "managed" {
			continue
		}
		v := r.Values
		switch r.Type {
		case "aws_iam_role":
			policy, _ := v["assume_role_policy"].(string)
			if policy == "" {
				continue // unknown until apply: reported by the caller as a gap
			}
			doc, err := oidc.DecodePolicy(policy)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s: %s: %w", path, r.Address, err)
			}
			arn, _ := v["arn"].(string)
			if arn == "" {
				arn = "terraform:" + r.Address
			}
			roles = append(roles, model.AWSRole{ARN: arn, TrustPolicy: doc})
		case "azuread_application_federated_identity_credential", "azurerm_federated_identity_credential":
			name := str(v, "display_name", "name")
			app := str(v, "application_id", "application_object_id", "parent_id")
			if app == "" {
				app = "terraform:" + r.Address
			}
			fic := model.AzureFIC{AppID: app, Name: name, Issuer: str(v, "issuer"), Subject: str(v, "subject")}
			for _, a := range list(v["audiences"]) {
				fic.Audiences = append(fic.Audiences, a)
			}
			fics = append(fics, fic)
		case "google_iam_workload_identity_pool_provider":
			p := model.GCPProvider{Name: str(v, "name"), AttributeCondition: str(v, "attribute_condition")}
			if p.Name == "" {
				p.Name = "terraform:" + r.Address
			}
			if m, ok := v["attribute_mapping"].(map[string]any); ok {
				p.AttributeMapping = map[string]string{}
				for k, x := range m {
					if s, ok := x.(string); ok {
						p.AttributeMapping[k] = s
					}
				}
			}
			if o, ok := v["oidc"].([]any); ok && len(o) > 0 {
				if om, ok := o[0].(map[string]any); ok {
					p.IssuerURI, _ = om["issuer_uri"].(string)
				}
			}
			if d, ok := v["disabled"].(bool); ok {
				p.Disabled = d
			}
			if p.IssuerURI != "" {
				gcp = append(gcp, p)
			}
		}
	}
	return roles, fics, gcp, nil
}

type tfValues struct {
	RootModule tfModule `json:"root_module"`
}

type tfModule struct {
	Resources    []tfResource `json:"resources"`
	ChildModules []tfModule   `json:"child_modules"`
}

type tfResource struct {
	Address string         `json:"address"`
	Mode    string         `json:"mode"`
	Type    string         `json:"type"`
	Values  map[string]any `json:"values"`
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func list(v any) []string {
	var out []string
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
