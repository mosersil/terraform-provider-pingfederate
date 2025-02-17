package pingfederate

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/iwarapter/pingfederate-sdk-go/services/authenticationSelectors"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	pf "github.com/iwarapter/pingfederate-sdk-go/pingfederate/models"
)

func resourcePingFederateAuthenticationSelectorResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Provides configuration for Authentication Selectors within PingFederate.",
		CreateContext: resourcePingFederateAuthenticationSelectorResourceCreate,
		ReadContext:   resourcePingFederateAuthenticationSelectorResourceRead,
		UpdateContext: resourcePingFederateAuthenticationSelectorResourceUpdate,
		DeleteContext: resourcePingFederateAuthenticationSelectorResourceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: resourcePingFederateAuthenticationSelectorResourceSchema(),
		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
			svc := m.(pfClient).AuthenticationSelectors
			if className, ok := d.GetOk("plugin_descriptor_ref.0.id"); ok {
				desc, resp, err := svc.GetAuthenticationSelectorDescriptorsByIdWithContext(ctx, &authenticationSelectors.GetAuthenticationSelectorDescriptorsByIdInput{Id: className.(string)})
				if resp != nil && resp.StatusCode == http.StatusForbidden {
					log.Printf("[WARN] Unable to query AuthenticationSelectorDescriptor, appropriate IdP/SP role not enabled")
					return nil
				}
				if err != nil {
					descs, _, err := svc.GetAuthenticationSelectorDescriptorsWithContext(ctx)
					if err == nil && descs != nil {
						list := func(in *[]*pf.AuthenticationSelectorDescriptor) string {
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

func resourcePingFederateAuthenticationSelectorResourceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "The plugin instance name. The name cannot be modified once the instance is created.\nNote: Ignored when specifying a connection's adapter override.",
		},
		"plugin_descriptor_ref": resourcePluginDescriptorRefSchema(),
		"configuration":         resourcePluginConfiguration(),
		"attribute_contract": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "The list of attributes that the Authentication Selector provides.",
			Elem:        resourceAuthenticationSelectorAttributeContract(),
		},
	}
}

func resourcePingFederateAuthenticationSelectorResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationSelectors
	input := authenticationSelectors.CreateAuthenticationSelectorInput{
		Body: *resourcePingFederateAuthenticationSelectorResourceReadData(d),
	}
	result, _, err := svc.CreateAuthenticationSelectorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to create AuthenticationSelectors: %s", err)
	}
	d.SetId(*result.Id)
	return resourcePingFederateAuthenticationSelectorResourceReadResult(d, result, svc)
}

func resourcePingFederateAuthenticationSelectorResourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationSelectors
	input := authenticationSelectors.GetAuthenticationSelectorInput{
		Id: d.Id(),
	}
	result, _, err := svc.GetAuthenticationSelectorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to read AuthenticationSelectors: %s", err)
	}
	return resourcePingFederateAuthenticationSelectorResourceReadResult(d, result, svc)
}

func resourcePingFederateAuthenticationSelectorResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationSelectors
	input := authenticationSelectors.UpdateAuthenticationSelectorInput{
		Id:   d.Id(),
		Body: *resourcePingFederateAuthenticationSelectorResourceReadData(d),
	}
	result, _, err := svc.UpdateAuthenticationSelectorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to update AuthenticationSelectors: %s", err)
	}

	return resourcePingFederateAuthenticationSelectorResourceReadResult(d, result, svc)
}

func resourcePingFederateAuthenticationSelectorResourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).AuthenticationSelectors
	input := authenticationSelectors.DeleteAuthenticationSelectorInput{
		Id: d.Id(),
	}
	_, _, err := svc.DeleteAuthenticationSelectorWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to delete AuthenticationSelectors: %s", err)
	}
	return nil
}

func resourcePingFederateAuthenticationSelectorResourceReadResult(d *schema.ResourceData, rv *pf.AuthenticationSelector, svc authenticationSelectors.AuthenticationSelectorsAPI) diag.Diagnostics {
	desc, _, err := svc.GetAuthenticationSelectorDescriptorsById(&authenticationSelectors.GetAuthenticationSelectorDescriptorsByIdInput{Id: *rv.PluginDescriptorRef.Id})
	if err != nil {
		return diag.Errorf("unable to retrieve AuthenticationSelectors descriptor: %s", err)
	}
	var diags diag.Diagnostics
	setResourceDataStringWithDiagnostic(d, "name", rv.Name, &diags)
	if rv.PluginDescriptorRef != nil {
		if err = d.Set("plugin_descriptor_ref", flattenResourceLink(rv.PluginDescriptorRef)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if rv.AttributeContract != nil && rv.AttributeContract.ExtendedAttributes != nil && len(*rv.AttributeContract.ExtendedAttributes) > 0 {
		if err = d.Set("attribute_contract", flattenAuthenticationSelectorAttributeContract(rv.AttributeContract)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if rv.Configuration != nil {
		orig := expandPluginConfiguration(d.Get("configuration").([]interface{}))

		if err = d.Set("configuration", maskPluginConfigurationFromDescriptor(desc.ConfigDescriptor, orig, rv.Configuration)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}

	return nil
}

func resourcePingFederateAuthenticationSelectorResourceReadData(d *schema.ResourceData) *pf.AuthenticationSelector {
	selector := &pf.AuthenticationSelector{
		Name:                String(d.Get("name").(string)),
		Id:                  String(d.Get("name").(string)),
		PluginDescriptorRef: expandResourceLink(d.Get("plugin_descriptor_ref").([]interface{})[0].(map[string]interface{})),
		Configuration:       expandPluginConfiguration(d.Get("configuration").([]interface{})),
	}

	if v, ok := d.GetOk("attribute_contract"); ok {
		selector.AttributeContract = expandAuthenticationSelectorAttributeContract(v.([]interface{}))
	}

	return selector
}
