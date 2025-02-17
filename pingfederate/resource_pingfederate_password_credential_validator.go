package pingfederate

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	pf "github.com/iwarapter/pingfederate-sdk-go/pingfederate/models"
	"github.com/iwarapter/pingfederate-sdk-go/services/passwordCredentialValidators"
)

func resourcePingFederatePasswordCredentialValidatorResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Provides configuration for Password Credential Validators within PingFederate.",
		CreateContext: resourcePingFederatePasswordCredentialValidatorResourceCreate,
		ReadContext:   resourcePingFederatePasswordCredentialValidatorResourceRead,
		UpdateContext: resourcePingFederatePasswordCredentialValidatorResourceUpdate,
		DeleteContext: resourcePingFederatePasswordCredentialValidatorResourceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: resourcePingFederatePasswordCredentialValidatorResourceSchema(),
		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
			svc := m.(pfClient).PasswordCredentialValidators
			if className, ok := d.GetOk("plugin_descriptor_ref.0.id"); ok {
				desc, _, err := svc.GetPasswordCredentialValidatorDescriptorWithContext(ctx, &passwordCredentialValidators.GetPasswordCredentialValidatorDescriptorInput{Id: className.(string)})
				if err != nil {
					descs, _, err := svc.GetPasswordCredentialValidatorDescriptorsWithContext(ctx)
					if err == nil && descs != nil {
						list := func(in *[]*pf.PasswordCredentialValidatorDescriptor) string {
							var plugins []string
							for _, descriptor := range *in {
								plugins = append(plugins, *descriptor.ClassName)
							}
							return strings.Join(plugins, "\n\t")
						}
						return fmt.Errorf("unable to find plugin_descriptor for %s available plugins:\n\t%s", className.(string), list(descs.Items))
					}
					return fmt.Errorf("unable to find plugin_descriptor for %s", className.(string))
				}
				return validateConfiguration(d, desc.ConfigDescriptor)
			}
			return nil
		},
	}
}

func resourcePingFederatePasswordCredentialValidatorResourceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The plugin instance name. The name cannot be modified once the instance is created.\nNote: Ignored when specifying a connection's adapter override.",
		},
		"plugin_descriptor_ref": resourcePluginDescriptorRefSchema(),
		"parent_ref": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "The reference to this plugin's parent instance. The parent reference is only accepted if the plugin type supports parent instances.",
			Elem:        resourceLinkResource(),
		},
		"configuration": resourcePluginConfiguration(),
		"attribute_contract": {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			MaxItems:    1,
			Description: "The list of attributes that the password credential validator provides.",
			Elem:        resourcePasswordCredentialValidatorAttributeContract(),
		},
	}
}

func resourcePingFederatePasswordCredentialValidatorResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).PasswordCredentialValidators
	input := passwordCredentialValidators.CreatePasswordCredentialValidatorInput{
		Body: *resourcePingFederatePasswordCredentialValidatorResourceReadData(d),
	}
	input.Body.Id = input.Body.Name
	result, _, err := svc.CreatePasswordCredentialValidatorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to create PasswordCredentialValidators: %s", err)
	}
	d.SetId(*result.Id)
	return resourcePingFederatePasswordCredentialValidatorResourceReadResult(d, result, svc)
}

func resourcePingFederatePasswordCredentialValidatorResourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).PasswordCredentialValidators
	input := passwordCredentialValidators.GetPasswordCredentialValidatorInput{
		Id: d.Id(),
	}
	result, _, err := svc.GetPasswordCredentialValidatorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to read PasswordCredentialValidators: %s", err)
	}
	return resourcePingFederatePasswordCredentialValidatorResourceReadResult(d, result, svc)
}

func resourcePingFederatePasswordCredentialValidatorResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).PasswordCredentialValidators
	input := passwordCredentialValidators.UpdatePasswordCredentialValidatorInput{
		Id:   d.Id(),
		Body: *resourcePingFederatePasswordCredentialValidatorResourceReadData(d),
	}
	result, _, err := svc.UpdatePasswordCredentialValidatorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to update PasswordCredentialValidators: %s", err)
	}

	return resourcePingFederatePasswordCredentialValidatorResourceReadResult(d, result, svc)
}

func resourcePingFederatePasswordCredentialValidatorResourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).PasswordCredentialValidators
	input := passwordCredentialValidators.DeletePasswordCredentialValidatorInput{
		Id: d.Id(),
	}
	_, _, err := svc.DeletePasswordCredentialValidatorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to delete PasswordCredentialValidators: %s", err)
	}
	return nil
}

func resourcePingFederatePasswordCredentialValidatorResourceReadResult(d *schema.ResourceData, rv *pf.PasswordCredentialValidator, svc passwordCredentialValidators.PasswordCredentialValidatorsAPI) diag.Diagnostics {
	desc, _, err := svc.GetPasswordCredentialValidatorDescriptor(&passwordCredentialValidators.GetPasswordCredentialValidatorDescriptorInput{Id: *rv.PluginDescriptorRef.Id})
	if err != nil {
		return diag.Errorf("unable to retrieve PasswordCredentialValidators descriptor: %s", err)
	}
	var diags diag.Diagnostics
	setResourceDataStringWithDiagnostic(d, "name", rv.Name, &diags)
	if rv.PluginDescriptorRef != nil {
		if err = d.Set("plugin_descriptor_ref", flattenResourceLink(rv.PluginDescriptorRef)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}

	if rv.ParentRef != nil {
		if err = d.Set("parent_ref", flattenResourceLink(rv.ParentRef)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}

	if rv.Configuration != nil {
		orig := expandPluginConfiguration(d.Get("configuration").([]interface{}))

		if err = d.Set("configuration", maskPluginConfigurationFromDescriptor(desc.ConfigDescriptor, orig, rv.Configuration)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if rv.AttributeContract != nil {
		if err = d.Set("attribute_contract", flattenPasswordCredentialValidatorAttributeContract(rv.AttributeContract)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	return diags
}

func resourcePingFederatePasswordCredentialValidatorResourceReadData(d *schema.ResourceData) *pf.PasswordCredentialValidator {
	validator := &pf.PasswordCredentialValidator{
		Name:                String(d.Get("name").(string)),
		PluginDescriptorRef: expandResourceLink(d.Get("plugin_descriptor_ref").([]interface{})[0].(map[string]interface{})),
		Configuration:       expandPluginConfiguration(d.Get("configuration").([]interface{})),
	}

	if v, ok := d.GetOk("parent_ref"); ok {
		validator.ParentRef = expandResourceLink(v.(map[string]interface{}))
	}

	if v, ok := d.GetOk("attribute_contract"); ok {
		validator.AttributeContract = expandPasswordCredentialValidatorAttributeContract(v.([]interface{}))
	}

	return validator
}
