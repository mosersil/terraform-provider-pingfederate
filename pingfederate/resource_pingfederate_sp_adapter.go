package pingfederate

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/iwarapter/pingfederate-sdk-go/services/spAdapters"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	pf "github.com/iwarapter/pingfederate-sdk-go/pingfederate/models"
)

func resourcePingFederateSpAdapterResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Provides configuration for SP Adapters within PingFederate.",
		CreateContext: resourcePingFederateSpAdapterResourceCreate,
		ReadContext:   resourcePingFederateSpAdapterResourceRead,
		UpdateContext: resourcePingFederateSpAdapterResourceUpdate,
		DeleteContext: resourcePingFederateSpAdapterResourceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: resourcePingFederateSpAdapterResourceSchema(),
		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
			svc := m.(pfClient).SpAdapters
			if className, ok := d.GetOk("plugin_descriptor_ref.0.id"); ok {
				desc, resp, err := svc.GetSpAdapterDescriptorsByIdWithContext(ctx, &spAdapters.GetSpAdapterDescriptorsByIdInput{Id: className.(string)})
				if resp != nil && resp.StatusCode == http.StatusForbidden {
					log.Printf("[WARN] Unable to query SpAdapterDescriptor, SP role not enabled")
					return nil
				}
				if err != nil {
					descs, _, err := svc.GetSpAdapterDescriptorsWithContext(ctx)
					if err == nil && descs != nil {
						list := func(in *[]*pf.SpAdapterDescriptor) string {
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

func resourcePingFederateSpAdapterResourceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"sp_adapter_id": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "The ID of the plugin instance. The ID cannot be modified once the instance is created. Note: Ignored when specifying a connection's adapter override.",
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "The plugin instance name. The name cannot be modified once the instance is created.\nNote: Ignored when specifying a connection's adapter override.",
		},
		"plugin_descriptor_ref": resourcePluginDescriptorRefSchema(),
		"parent_ref": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "The reference to this plugin's parent instance. The parent reference is only accepted if the plugin type supports parent instances.\nNote: This parent reference is required if this plugin instance is used as an overriding plugin (e.g. connection adapter overrides)",
			Elem:        resourceLinkResource(),
		},
		"configuration": resourcePluginConfiguration(),
		"attribute_contract": {
			Type:        schema.TypeList,
			Optional:    true,
			Computed:    true,
			MaxItems:    1,
			Description: "The list of attributes that the SP adapter provides.",
			Elem:        resourceSpAdapterAttributeContract(),
		},
		"target_application_info": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "The target application's name and icon URL",
			Elem:        resourceSpAdapterTargetApplicationInfo(),
		},
	}
}

func resourcePingFederateSpAdapterResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).SpAdapters
	input := spAdapters.CreateSpAdapterInput{
		Body: *resourcePingFederateSpAdapterResourceReadData(d),
	}
	result, _, err := svc.CreateSpAdapterWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to create SpAdapters: %s", err)
	}
	d.SetId(*result.Id)
	return resourcePingFederateSpAdapterResourceReadResult(d, result, svc)
}

func resourcePingFederateSpAdapterResourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).SpAdapters
	input := spAdapters.GetSpAdapterInput{
		Id: d.Id(),
	}
	result, _, err := svc.GetSpAdapterWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to read SpAdapters: %s", err)
	}
	return resourcePingFederateSpAdapterResourceReadResult(d, result, svc)
}

func resourcePingFederateSpAdapterResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).SpAdapters
	input := spAdapters.UpdateSpAdapterInput{
		Id:   d.Id(),
		Body: *resourcePingFederateSpAdapterResourceReadData(d),
	}
	result, _, err := svc.UpdateSpAdapterWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to update SpAdapters: %s", err)
	}

	return resourcePingFederateSpAdapterResourceReadResult(d, result, svc)
}

func resourcePingFederateSpAdapterResourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).SpAdapters
	input := spAdapters.DeleteSpAdapterInput{
		Id: d.Id(),
	}
	_, _, err := svc.DeleteSpAdapterWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to delete SpAdapters: %s", err)
	}
	return nil
}

func resourcePingFederateSpAdapterResourceReadResult(d *schema.ResourceData, rv *pf.SpAdapter, svc spAdapters.SpAdaptersAPI) diag.Diagnostics {
	desc, _, err := svc.GetSpAdapterDescriptorsById(&spAdapters.GetSpAdapterDescriptorsByIdInput{Id: *rv.PluginDescriptorRef.Id})
	if err != nil {
		return diag.Errorf("unable to retrieve SpAdapters descriptor: %s", err)
	}
	var diags diag.Diagnostics
	setResourceDataStringWithDiagnostic(d, "name", rv.Name, &diags)
	setResourceDataStringWithDiagnostic(d, "sp_adapter_id", rv.Id, &diags)
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

	if rv.AttributeContract != nil && spAdapterAttributeContractShouldFlatten(rv.AttributeContract) {
		if err = d.Set("attribute_contract", flattenSpAdapterAttributeContract(rv.AttributeContract)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}

	if rv.TargetApplicationInfo != nil {
		if err = d.Set("target_application_info", flattenSpAdapterTargetApplicationInfo(rv.TargetApplicationInfo)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	return diags
}

func resourcePingFederateSpAdapterResourceReadData(d *schema.ResourceData) *pf.SpAdapter {
	validator := &pf.SpAdapter{
		Id:                  String(d.Get("sp_adapter_id").(string)),
		Name:                String(d.Get("name").(string)),
		PluginDescriptorRef: expandResourceLink(d.Get("plugin_descriptor_ref").([]interface{})[0].(map[string]interface{})),
		Configuration:       expandPluginConfiguration(d.Get("configuration").([]interface{})),
	}

	if v, ok := d.GetOk("parent_ref"); ok {
		validator.ParentRef = expandResourceLink(v.(map[string]interface{}))
	}
	if v, ok := d.GetOk("attribute_contract"); ok && len(v.([]interface{})) > 0 {
		validator.AttributeContract = expandSpAdapterAttributeContract(v.([]interface{})[0].(map[string]interface{}))
	}
	if v, ok := d.GetOk("target_application_info"); ok && len(v.([]interface{})) > 0 {
		validator.TargetApplicationInfo = expandSpAdapterTargetApplicationInfo(v.([]interface{})[0].(map[string]interface{}))
	}

	return validator
}
