package pingfederate

import (
	"context"
	"regexp"

	"github.com/hashicorp/go-cty/cty"

	"github.com/iwarapter/pingfederate-sdk-go/services/authenticationPolicyContracts"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	pf "github.com/iwarapter/pingfederate-sdk-go/pingfederate/models"
)

func resourcePingFederateAuthenticationPolicyContractResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Provides configuration for Authentication Policy Contracts within PingFederate.",
		CreateContext: resourcePingFederateAuthenticationPolicyContractResourceCreate,
		ReadContext:   resourcePingFederateAuthenticationPolicyContractResourceRead,
		UpdateContext: resourcePingFederateAuthenticationPolicyContractResourceUpdate,
		DeleteContext: resourcePingFederateAuthenticationPolicyContractResourceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: resourcePingFederateAuthenticationPolicyContractResourceSchema(),
	}
}

func resourcePingFederateAuthenticationPolicyContractResourceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"policy_contract_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			ForceNew:    true,
			Description: "The persistent, unique ID for the authentication policy contract. It can be any combination of [a-zA-Z0-9._-]. This property is system-assigned if not specified.",
			ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
				v := value.(string)
				r, _ := regexp.Compile(`^[a-zA-Z0-9._-]+$`)
				if !r.MatchString(v) {
					return diag.Errorf("the policy_contract_id can only contain alphanumeric characters, dash, dot and underscore.")
				}
				return nil
			},
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The Authentication Policy Contract Name. Name is unique.",
		},
		"core_attributes": {
			Type:        schema.TypeSet,
			Computed:    true,
			Description: "A list of read-only assertion attributes (for example, subject) that are automatically populated by PingFederate.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"extended_attributes": {
			Type:        schema.TypeSet,
			Optional:    true,
			MinItems:    1,
			Description: "A list of additional attributes as needed.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
	}
}

func resourcePingFederateAuthenticationPolicyContractResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationPolicyContracts
	input := authenticationPolicyContracts.CreateAuthenticationPolicyContractInput{
		Body: *resourcePingFederateAuthenticationPolicyContractResourceReadData(d),
	}
	result, _, err := svc.CreateAuthenticationPolicyContractWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to create AuthenticationPolicyContracts: %s", err)
	}
	d.SetId(*result.Id)
	return resourcePingFederateAuthenticationPolicyContractResourceReadResult(d, result)
}

func resourcePingFederateAuthenticationPolicyContractResourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationPolicyContracts
	input := authenticationPolicyContracts.GetAuthenticationPolicyContractInput{
		Id: d.Id(),
	}
	result, _, err := svc.GetAuthenticationPolicyContractWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to read AuthenticationPolicyContracts: %s", err)
	}
	return resourcePingFederateAuthenticationPolicyContractResourceReadResult(d, result)
}

func resourcePingFederateAuthenticationPolicyContractResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationPolicyContracts
	input := authenticationPolicyContracts.UpdateAuthenticationPolicyContractInput{
		Id:   d.Id(),
		Body: *resourcePingFederateAuthenticationPolicyContractResourceReadData(d),
	}
	result, _, err := svc.UpdateAuthenticationPolicyContractWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to update AuthenticationPolicyContracts: %s", err)
	}

	return resourcePingFederateAuthenticationPolicyContractResourceReadResult(d, result)
}

func resourcePingFederateAuthenticationPolicyContractResourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	awsMutexKV.Lock("connection_delete")
	defer awsMutexKV.Unlock("connection_delete")

	svc := m.(pfClient).AuthenticationPolicyContracts
	input := authenticationPolicyContracts.DeleteAuthenticationPolicyContractInput{
		Id: d.Id(),
	}
	_, _, err := svc.DeleteAuthenticationPolicyContractWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to delete AuthenticationPolicyContracts: %s", err)
	}
	return nil
}

func resourcePingFederateAuthenticationPolicyContractResourceReadResult(d *schema.ResourceData, rv *pf.AuthenticationPolicyContract) diag.Diagnostics {
	var diags diag.Diagnostics
	setResourceDataStringWithDiagnostic(d, "name", rv.Name, &diags)
	setResourceDataStringWithDiagnostic(d, "policy_contract_id", rv.Id, &diags)

	if rv.ExtendedAttributes != nil && len(*rv.ExtendedAttributes) > 0 {
		if err := d.Set("extended_attributes", flattenAuthenticationPolicyContractAttribute(*rv.ExtendedAttributes)); err != nil {
			diags = append(diags, diag.FromErr(err)...)

		}
	}
	if rv.CoreAttributes != nil && len(*rv.CoreAttributes) > 0 {
		if err := d.Set("core_attributes", flattenAuthenticationPolicyContractAttribute(*rv.CoreAttributes)); err != nil {
			diags = append(diags, diag.FromErr(err)...)

		}
	}

	return nil
}

func resourcePingFederateAuthenticationPolicyContractResourceReadData(d *schema.ResourceData) *pf.AuthenticationPolicyContract {
	contract := &pf.AuthenticationPolicyContract{
		Name: String(d.Get("name").(string)),
		CoreAttributes: &[]*pf.AuthenticationPolicyContractAttribute{
			{
				Name: String("subject"),
			},
		},
	}
	if v, ok := d.GetOk("policy_contract_id"); ok {
		contract.Id = String(v.(string))
	}
	if _, ok := d.GetOk("extended_attributes"); ok {
		contract.ExtendedAttributes = expandAuthenticationPolicyContractAttribute(d.Get("extended_attributes").(*schema.Set).List())
	}

	return contract
}
