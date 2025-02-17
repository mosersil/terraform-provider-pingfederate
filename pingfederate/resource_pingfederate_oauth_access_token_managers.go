package pingfederate

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/go-cty/cty"

	"github.com/iwarapter/pingfederate-sdk-go/services/oauthAccessTokenManagers"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	pf "github.com/iwarapter/pingfederate-sdk-go/pingfederate/models"
)

func resourcePingFederateOauthAccessTokenManagersResource() *schema.Resource {
	return &schema.Resource{
		Description:   "Provides configuration for OAuth Access Token Managers within PingFederate.",
		CreateContext: resourcePingFederateOauthAccessTokenManagersResourceCreate,
		ReadContext:   resourcePingFederateOauthAccessTokenManagersResourceRead,
		UpdateContext: resourcePingFederateOauthAccessTokenManagersResourceUpdate,
		DeleteContext: resourcePingFederateOauthAccessTokenManagersResourceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: resourcePingFederateOauthAccessTokenManagersResourceSchema(),
		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, m interface{}) error {
			svc := m.(pfClient).OauthAccessTokenManagers
			if className, ok := d.GetOk("plugin_descriptor_ref.0.id"); ok {
				desc, resp, err := svc.GetTokenManagerDescriptorWithContext(ctx, &oauthAccessTokenManagers.GetTokenManagerDescriptorInput{Id: className.(string)})
				if resp != nil && resp.StatusCode == http.StatusForbidden {
					log.Printf("[WARN] Unable to query OAuthTokenManagerDescriptor, OAuth 2.0 authorization server role enabled")
					return nil
				}
				if err != nil {
					descs, _, err := svc.GetTokenManagerDescriptorsWithContext(ctx)
					if err == nil && descs != nil {
						list := func(in *[]*pf.AccessTokenManagerDescriptor) string {
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

func resourcePingFederateOauthAccessTokenManagersResourceSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"instance_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			ForceNew:    true,
			Description: "The ID of the plugin instance. The ID cannot be modified once the instance is created.\nNote: Ignored when specifying a connection's adapter override.",
			ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
				v := value.(string)
				r, _ := regexp.Compile(`^[a-zA-Z0-9._-]+$`)
				if !r.MatchString(v) || len(v) >= 33 {
					return diag.Errorf("The plugin ID must be less than 33 characters, contain no spaces, and be alphanumeric.")
				}
				return nil
			},
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The plugin instance name. The name cannot be modified once the instance is created.\nNote: Ignored when specifying a connection's adapter override.",
		},
		"plugin_descriptor_ref": resourcePluginDescriptorRefSchema(),
		"configuration":         resourcePluginConfiguration(),
		"parent_ref": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "The reference to this plugin's parent instance. The parent reference is only accepted if the plugin type supports parent instances.\nNote: This parent reference is required if this plugin instance is used as an overriding plugin (e.g. connection adapter overrides)",
			Elem:        resourceLinkResource(),
		},
		"attribute_contract": {
			Type:        schema.TypeList,
			Required:    true,
			MaxItems:    1,
			Description: "The list of attributes that will be added to an access token.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"core_attributes": {
						Type:        schema.TypeList,
						Computed:    true,
						Description: "A list of core token attributes that are associated with the access token management plugin type. This field is read-only and is ignored on POST/PUT.",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"extended_attributes": {
						Type:        schema.TypeSet,
						Optional:    true,
						MinItems:    1,
						Description: "A list of additional token attributes that are associated with this access token management plugin instance.",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
			},
		},
		"selection_settings": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "Settings which determine how this token manager can be selected for use by an OAuth request.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"inherited": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "If this token manager has a parent, this flag determines whether selection settings, such as resource URI's, are inherited from the parent. When set to true, the other fields in this model become read-only. The default value is false.",
					},
					"resource_uris": {
						Type:        schema.TypeList,
						Optional:    true,
						Description: "The list of base resource URI's which map to this token manager. A resource URI, specified via the 'aud' parameter, can be used to select a specific token manager for an OAuth request.",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
			},
		},
		"access_control_settings": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "Settings which determine which clients may access this token manager.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"inherited": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "If this token manager has a parent, this flag determines whether access control settings are inherited from the parent. When set to true, the other fields in this model become read-only. The default value is false.",
					},
					"restrict_clients": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "Determines whether access to this token manager is restricted to specific OAuth clients. If false, the 'allowedClients' field is ignored. The default value is false.",
					},
					"allowed_clients": {
						Type:        schema.TypeList,
						Optional:    true,
						Description: "If 'restrictClients' is true, this field defines the list of OAuth clients that are allowed to access the token manager.",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
			},
		},
		"session_validation_settings": {
			Type:        schema.TypeList,
			Optional:    true,
			MaxItems:    1,
			Description: "Settings which determine how the user session is associated with the access token.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"inherited": {
						Type:        schema.TypeBool,
						Optional:    true,
						Default:     false,
						Description: "If this token manager has a parent, this flag determines whether session validation settings, such as checkValidAuthnSession, are inherited from the parent. When set to true, the other fields in this model become read-only. The default value is false.",
					},
					"include_session_id": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Include the session identifier in the access token. Note that if any of the session validation features is enabled, the session identifier will already be included in the access tokens.",
					},
					"check_valid_authn_session": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Check for a valid authentication session when validating the access token.",
					},
					"check_session_revocation_status": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Check the session revocation status when validating the access token.",
					},
					"update_authn_session_activity": {
						Type:        schema.TypeBool,
						Optional:    true,
						Description: "Update authentication session activity when validating the access token.",
					},
				},
			},
		},
	}
}

func resourcePingFederateOauthAccessTokenManagersResourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).OauthAccessTokenManagers
	input := oauthAccessTokenManagers.CreateTokenManagerInput{
		Body: *resourcePingFederateOauthAccessTokenManagersResourceReadData(d, svc),
	}
	result, _, err := svc.CreateTokenManagerWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to read OauthAccessTokenManagers: %s", err)
	}
	d.SetId(*result.Id)
	return resourcePingFederateOauthAccessTokenManagersResourceReadResult(d, result, svc)
}

func resourcePingFederateOauthAccessTokenManagersResourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).OauthAccessTokenManagers
	input := oauthAccessTokenManagers.GetTokenManagerInput{
		Id: d.Id(),
	}
	result, _, err := svc.GetTokenManagerWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to read OauthAccessTokenManagers: %s", err)
	}
	return resourcePingFederateOauthAccessTokenManagersResourceReadResult(d, result, svc)
}

func resourcePingFederateOauthAccessTokenManagersResourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).OauthAccessTokenManagers
	input := oauthAccessTokenManagers.UpdateTokenManagerInput{
		Id:   d.Id(),
		Body: *resourcePingFederateOauthAccessTokenManagersResourceReadData(d, svc),
	}
	result, _, err := svc.UpdateTokenManagerWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to update OauthAccessTokenManagers: %s", err)
	}

	return resourcePingFederateOauthAccessTokenManagersResourceReadResult(d, result, svc)
}

func resourcePingFederateOauthAccessTokenManagersResourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	svc := m.(pfClient).OauthAccessTokenManagers
	input := oauthAccessTokenManagers.DeleteTokenManagerInput{
		Id: d.Id(),
	}
	_, _, err := svc.DeleteTokenManagerWithContext(ctx, &input)
	if err != nil {
		return diag.Errorf("unable to delete OauthAccessTokenManagers: %s", err)
	}
	return nil
}

func resourcePingFederateOauthAccessTokenManagersResourceReadResult(d *schema.ResourceData, rv *pf.AccessTokenManager, svc oauthAccessTokenManagers.OauthAccessTokenManagersAPI) diag.Diagnostics {
	desc, _, err := svc.GetTokenManagerDescriptor(&oauthAccessTokenManagers.GetTokenManagerDescriptorInput{Id: *rv.PluginDescriptorRef.Id})
	if err != nil {
		return diag.Errorf("unable to retrieve oauthAccessTokenManagers descriptor: %s", err)

	}
	var diags diag.Diagnostics
	setResourceDataStringWithDiagnostic(d, "name", rv.Name, &diags)
	setResourceDataStringWithDiagnostic(d, "instance_id", rv.Id, &diags)
	if rv.PluginDescriptorRef != nil {
		if err := d.Set("plugin_descriptor_ref", flattenResourceLink(rv.PluginDescriptorRef)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if rv.Configuration != nil {
		orig := expandPluginConfiguration(d.Get("configuration").([]interface{}))

		if err := d.Set("configuration", maskPluginConfigurationFromDescriptor(desc.ConfigDescriptor, orig, rv.Configuration)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if rv.AttributeContract != nil {
		if err := d.Set("attribute_contract", flattenAccessTokenAttributeContract(rv.AttributeContract)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if rv.ParentRef != nil {
		if err := d.Set("parent_ref", flattenResourceLink(rv.ParentRef)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if selectionSettingsShouldFlatten(rv.SelectionSettings) {
		if err := d.Set("selection_settings", flattenSelectionSettings(rv.SelectionSettings)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if sessionValidationSettingsShouldFlatten(rv.SessionValidationSettings) {
		if err := d.Set("session_validation_settings", flattenSessionValidationSettings(rv.SessionValidationSettings)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	if accessControlSettingsShouldFlatten(rv.AccessControlSettings) {
		if err := d.Set("access_control_settings", flattenAccessControlSettings(rv.AccessControlSettings)); err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	}
	return diags
}

func resourcePingFederateOauthAccessTokenManagersResourceReadData(d *schema.ResourceData, svc oauthAccessTokenManagers.OauthAccessTokenManagersAPI) *pf.AccessTokenManager {
	//desc, _, err := svc.GetTokenManagerDescriptor(&pf.GetTokenManagerDescriptorInput{Id: *expandResourceLink(d.Get("plugin_descriptor_ref").([]interface{})).Id})
	//if err != nil {
	//	//TODO
	//}
	atm := &pf.AccessTokenManager{
		Name:                String(d.Get("name").(string)),
		Id:                  String(d.Get("instance_id").(string)),
		PluginDescriptorRef: expandResourceLink(d.Get("plugin_descriptor_ref").([]interface{})[0].(map[string]interface{})),
		Configuration:       expandPluginConfiguration(d.Get("configuration").([]interface{})),
		AttributeContract:   expandAccessTokenAttributeContract(d.Get("attribute_contract").([]interface{})),
	}
	if v, ok := d.GetOk("parent_ref"); ok {
		atm.ParentRef = expandResourceLink(v.([]interface{})[0].(map[string]interface{}))
	}
	if v, ok := d.GetOk("selection_settings"); ok {
		atm.SelectionSettings = expandSelectionSettings(v.([]interface{}))
	}
	if v, ok := d.GetOk("session_validation_settings"); ok {
		atm.SessionValidationSettings = expandSessionValidationSettings(v.([]interface{}))
	}
	if v, ok := d.GetOk("access_control_settings"); ok {
		atm.AccessControlSettings = expandAccessControlSettings(v.([]interface{}))
	}
	return atm
}
