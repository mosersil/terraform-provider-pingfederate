package pingfederate

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	pf "github.com/iwarapter/pingfederate-sdk-go/pingfederate/models"

	"github.com/iwarapter/pingfederate-sdk-go/services/passwordCredentialValidators"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func init() {
	resource.AddTestSweepers("password_credential_validator", &resource.Sweeper{
		Name:         "password_credential_validator",
		Dependencies: []string{},
		F: func(r string) error {
			svc := passwordCredentialValidators.New(cfg)
			results, _, err := svc.GetPasswordCredentialValidators()
			if err != nil {
				return fmt.Errorf("unable to list password credential validator %s", err)
			}
			for _, item := range *results.Items {
				if strings.Contains(*item.Name, "acctest") {
					_, _, err := svc.DeletePasswordCredentialValidator(&passwordCredentialValidators.DeletePasswordCredentialValidatorInput{Id: *item.Id})
					if err != nil {
						return fmt.Errorf("unable to sweep password credential validator %s because %s", *item.Id, err)
					}
				}
			}
			return nil
		},
	})
}

func TestAccPingFederatePasswordCredentialValidatorResource(t *testing.T) {
	resourceName := "pingfederate_password_credential_validator.demo"
	resource.ParallelTest(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPingFederatePasswordCredentialValidatorResourceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccPingFederatePasswordCredentialValidatorResourceConfig("demo1"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPingFederatePasswordCredentialValidatorResourceExists(resourceName),
					// testAccCheckPingFederatePasswordCredentialValidatorResourceAttributes(),
				),
			},
			{
				Config: testAccPingFederatePasswordCredentialValidatorResourceConfig("demo2"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckPingFederatePasswordCredentialValidatorResourceExists(resourceName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"configuration.0.tables.0.rows.0.sensitive_fields.0.value",
					"configuration.0.tables.0.rows.0.sensitive_fields.1.value",
				},
			},
			{
				Config:      testAccPingFederatePasswordCredentialValidatorResourceConfigWrongPlugin(),
				ExpectError: regexp.MustCompile(`unable to find plugin_descriptor for org\.sourceid\.saml20\.domain\.wrong available plugins:`),
			},
		},
	})
}

func testAccCheckPingFederatePasswordCredentialValidatorResourceDestroy(s *terraform.State) error {
	return nil
}

func testAccPingFederatePasswordCredentialValidatorResourceConfig(configUpdate string) string {
	return fmt.Sprintf(`resource "pingfederate_password_credential_validator" "demo" {
	  name = "acctestfoo"
	  plugin_descriptor_ref {
		id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
	  }

	  configuration {
		tables {
		  name = "Users"
		  rows {
			fields {
			  name  = "Username"
			  value = "%s"
			}

			sensitive_fields {
			  name  = "Password"
			  value = "demo"
			}

			sensitive_fields {
			  name  = "Confirm Password"
			  value = "demo"
			}

			fields {
			  name  = "Relax Password Requirements"
			  value = "true"
			}
		  }
		}
	  }
	}`, configUpdate)
}

func testAccPingFederatePasswordCredentialValidatorResourceConfigWrongPlugin() string {
	return `
resource "pingfederate_password_credential_validator" "demo" {
  name = "acctestfoo"
  plugin_descriptor_ref {
	id = "org.sourceid.saml20.domain.wrong"
  }

  configuration {
	tables {
	  name = "Users"
	  rows {
		fields {
		  name  = "Username"
		  value = "%s"
		}

		sensitive_fields {
		  name  = "Password"
		  value = "demo"
		}

		sensitive_fields {
		  name  = "Confirm Password"
		  value = "demo"
		}

		fields {
		  name  = "Relax Password Requirements"
		  value = "true"
		}
	  }
	}
  }
}`
}

func testAccCheckPingFederatePasswordCredentialValidatorResourceExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" || rs.Primary.ID == "0" {
			return fmt.Errorf("No rule ID is set")
		}

		conn := testAccProvider.Meta().(pfClient).PasswordCredentialValidators
		result, _, err := conn.GetPasswordCredentialValidator(&passwordCredentialValidators.GetPasswordCredentialValidatorInput{Id: rs.Primary.ID})

		if err != nil {
			return fmt.Errorf("Error: PasswordCredentialValidator (%s) not found", n)
		}

		if *result.Name != rs.Primary.Attributes["name"] {
			return fmt.Errorf("Error: PasswordCredentialValidator response (%s) didnt match state (%s)", *result.Name, rs.Primary.Attributes["name"])
		}

		return nil
	}
}

type pcvMock struct {
	passwordCredentialValidators.PasswordCredentialValidatorsAPI
}

func (m pcvMock) GetPasswordCredentialValidatorDescriptor(_ *passwordCredentialValidators.GetPasswordCredentialValidatorDescriptorInput) (output *pf.PasswordCredentialValidatorDescriptor, resp *http.Response, err error) {
	return &pf.PasswordCredentialValidatorDescriptor{
		AttributeContract: nil,
		ClassName:         String("org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"),
		ConfigDescriptor: &pf.PluginConfigDescriptor{
			ActionDescriptors: nil,
			Description:       nil,
			Fields: &[]*pf.FieldDescriptor{
				{
					Type:         String("TEXT"),
					Name:         String("Example"),
					Required:     Bool(true),
					DefaultValue: String("foo"),
				},
			},
			Tables: &[]*pf.TableDescriptor{
				{
					Columns: &[]*pf.FieldDescriptor{
						{
							Type: String("TEXT"),
							Name: String("Username"),
						},
						{
							Type: String("HASHED_TEXT"),
							Name: String("Password"),
						},
					},
					Description:       nil,
					Label:             nil,
					Name:              nil,
					RequireDefaultRow: nil,
				},
			},
		},
		Id:                       String("org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"),
		Name:                     String("Simple Username Password Credential Validator"),
		SupportsExtendedContract: nil,
	}, nil, nil
}

func Test_resourcePingFederatePasswordCredentialValidatorResourceReadData(t *testing.T) {
	m := pcvMock{}

	cases := []struct {
		Resource pf.PasswordCredentialValidator
	}{
		{
			Resource: pf.PasswordCredentialValidator{
				Name: String("foo"),
				PluginDescriptorRef: &pf.ResourceLink{
					Id: String("org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"),
				},
				Configuration: &pf.PluginConfiguration{
					Tables: &[]*pf.ConfigTable{
						{
							Name: String("Users"),
							Rows: &[]*pf.ConfigRow{
								{
									Fields: &[]*pf.ConfigField{
										{
											Name:      String("Password"),
											Value:     String("secret"),
											Inherited: Bool(false),
										},
										{
											Name:      String("Username"),
											Value:     String("test"),
											Inherited: Bool(false),
										},
									},
									DefaultRow: Bool(true),
								},
							},
							Inherited: Bool(false),
						},
					},
					Fields: nil,
				},
				AttributeContract: &pf.PasswordCredentialValidatorAttributeContract{
					Inherited: Bool(false),
					CoreAttributes: &[]*pf.PasswordCredentialValidatorAttribute{
						{
							Name: String("username"),
						},
					},
				},
			},
		},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("tc:%v", i), func(t *testing.T) {

			resourceSchema := resourcePingFederatePasswordCredentialValidatorResourceSchema()
			resourceLocalData := schema.TestResourceDataRaw(t, resourceSchema, map[string]interface{}{})
			require.Nil(t, resourceLocalData.Set("configuration", flattenPluginConfiguration(tc.Resource.Configuration)))
			resourcePingFederatePasswordCredentialValidatorResourceReadResult(resourceLocalData, &tc.Resource, m)

			assert.Equal(t, tc.Resource, *resourcePingFederatePasswordCredentialValidatorResourceReadData(resourceLocalData))
		})
	}
}
