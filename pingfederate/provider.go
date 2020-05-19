package pingfederate

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

//Provider does stuff
//
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["username"],
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"PINGFEDERATE_USERNAME"}, "Administrator"),
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["password"],
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"PINGFEDERATE_PASSWORD"}, "2Federate"),
			},
			"context": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["context"],
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"PINGFEDERATE_CONTEXT"}, "/pf-admin-api/v1"),
			},
			"base_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: descriptions["base_url"],
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{"PINGFEDERATE_BASEURL"}, "https://localhost:9999"),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"pingfederate_authentication_policy_contract": resourcePingFederateAuthenticationPolicyContractResource(),
			"pingfederate_authentication_selector":        resourcePingFederateAuthenticationSelectorResource(),
			"pingfederate_data_store":                     resourcePingFederateDataStoreResource(),
			"pingfederate_idp_adapter":                    resourcePingFederateIdpAdapterResource(),
			"pingfederate_oauth_auth_server_settings":     resourcePingFederateOauthAuthServerSettingsResource(),
			"pingfederate_oauth_client":                   resourcePingFederateOauthClientResource(),
			"pingfederate_oauth_access_token_manager":     resourcePingFederateOauthAccessTokenManagersResource(),
			"pingfederate_sp_adapter":                     resourcePingFederateSpAdapterResource(),
			"pingfederate_password_credential_validator":  resourcePingFederatePasswordCredentialValidatorResource(),
		},
		ConfigureFunc: providerConfigure,
	}
}

var descriptions map[string]string

func init() {
	descriptions = map[string]string{
		"username": "The username for pingfederate API.",
		"password": "The password for pingfederate API.",
		"base_url": "The base url of the pingfederate API.",
		"context":  "The context path of the pingfederate API.",
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := &Config{
		Username: d.Get("username").(string),
		Password: d.Get("password").(string),
		BaseURL:  d.Get("base_url").(string),
		Context:  d.Get("context").(string),
	}

	return config.Client()
}

// Takes the result of flatmap.Expand for an array of strings
// and returns a []*string
func expandStringList(configured []interface{}) []*string {
	vs := make([]*string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, String(v.(string)))
		}
	}
	return vs
}

// Takes the result of flatmap.Expand for an array of strings
// and returns a []*int
func expandIntList(configured []interface{}) []*int {
	vs := make([]*int, 0, len(configured))
	for _, v := range configured {
		_, ok := v.(int)
		if ok {
			val := v.(int)
			vs = append(vs, &val)
		}
	}
	return vs
}

// Bool is a helper routine that allocates a new bool value
// to store v and returns a pointer to it.
func Bool(v bool) *bool { return &v }

// Int is a helper routine that allocates a new int value
// to store v and returns a pointer to it.
func Int(v int) *int { return &v }

// Int64 is a helper routine that allocates a new int64 value
// to store v and returns a pointer to it.
func Int64(v int64) *int64 { return &v }

// String is a helper routine that allocates a new string value
// to store v and returns a pointer to it.
func String(v string) *string { return &v }

func setResourceDataString(d *schema.ResourceData, name string, data *string) error {
	if data != nil {
		if err := d.Set(name, *data); err != nil {
			return err
		}
	}
	return nil
}

func setResourceDataInt(d *schema.ResourceData, name string, data *int) error {
	if data != nil {
		if err := d.Set(name, *data); err != nil {
			return err
		}
	}
	return nil
}

func setResourceDataBool(d *schema.ResourceData, name string, data *bool) error {
	if data != nil {
		if err := d.Set(name, *data); err != nil {
			return err
		}
	}
	return nil
}
