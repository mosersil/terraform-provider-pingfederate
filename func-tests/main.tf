provider "pingfederate" {
  password = "2Federate"
  base_url = "https://localhost:9998"
}


# module "simple_ref_token_example" {
#   source  = "git@github.com:iwarapter/pingfederate-terraform-modules//modules/oauth_token_mgr_reference_bearer?ref=module_token_mgr_ref"

#   instance_id = "reftokenmgrsimple"
#   name        = "reftokenmgrsimple"
#   extended_attributes = ["sub", "fname", "lname"]

# }






















resource "pingfederate_oauth_access_token_manager" "reftokenmgr" {
  instance_id = "reftokenmgr"
  name        = "reftokenmgr"

  plugin_descriptor_ref {
    id = "org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin"
  }

  configuration {
    fields {
      name  = "Token Length"
      value = "28"
    }

    fields {
      name  = "Token Lifetime"
      value = "120"
    }

    fields {
      name  = "Lifetime Extension Policy"
      value = "ALL"
    }

    fields {
      name  = "Maximum Token Lifetime"
      value = ""
    }

    fields {
      name  = "Lifetime Extension Threshold Percentage"
      value = "30"
    }

    fields {
      name  = "Mode for Synchronous RPC"
      value = "3"
    }

    fields {
      name  = "RPC Timeout"
      value = "500"
    }

    fields {
      name  = "Expand Scope Groups"
      value = "false"
    }
  }

  attribute_contract {
    extended_attributes = ["sub", ]
  }
}

resource "pingfederate_oauth_access_token_manager" "reftokenmgrcode" {
  instance_id = "reftokenmgrcode"
  name        = "reftokenmgrcode"

  plugin_descriptor_ref {
    id = "org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin"
  }

  configuration {
    fields {
      name  = "Token Length"
      value = "28"
    }

    fields {
      name  = "Token Lifetime"
      value = "120"
    }

    fields {
      name  = "Lifetime Extension Policy"
      value = "ALL"
    }

    fields {
      name  = "Maximum Token Lifetime"
      value = ""
    }

    fields {
      name  = "Lifetime Extension Threshold Percentage"
      value = "30"
    }

    fields {
      name  = "Mode for Synchronous RPC"
      value = "3"
    }

    fields {
      name  = "RPC Timeout"
      value = "500"
    }

    fields {
      name  = "Expand Scope Groups"
      value = "false"
    }
  }

  attribute_contract {
    extended_attributes = ["sub", "email", "email_verified", "family_name", "given_name"]
  }
}



resource "pingfederate_oauth_access_token_mappings" "reftokenmgrcc" {
  access_token_manager_ref {
    id = pingfederate_oauth_access_token_manager.reftokenmgr.id
  }

  context {
    type = "CLIENT_CREDENTIALS"
  }
  attribute_contract_fulfillment {
    key_name = "sub"
    source {
      type = "CONTEXT"
    }
    value = "ClientId"
  }
}

resource "pingfederate_oauth_access_token_mappings" "reftokenmgrcode" {

  access_token_manager_ref {
    id = pingfederate_oauth_access_token_manager.reftokenmgrcode.id
  }
  context {
    type = "AUTHENTICATION_POLICY_CONTRACT"
    context_ref {
      id = pingfederate_authentication_policy_contract.apc_simple.id
    }
  }
  attribute_contract_fulfillment {
    key_name = "sub"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "subject"
  }
  attribute_contract_fulfillment {
    key_name = "email"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "subject"
  }
  attribute_contract_fulfillment {
    key_name = "email_verified"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "email_verified"
  }
  attribute_contract_fulfillment {
    key_name = "family_name"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "family_name"
  }
  attribute_contract_fulfillment {
    key_name = "given_name"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "given_name"
  }

}


resource "pingfederate_oauth_client" "myoauthclientid" {
  client_id = "myoauthclientid"
  name      = "myoauthclientid"

  grant_types = [
    "CLIENT_CREDENTIALS",
  ]

  exclusive_scopes = ["acc_no", ]


  client_auth {
    // type                      = "CERTIFICATE"
    // client_cert_issuer_dn     = ""
    // client_cert_subject_dn    = ""
    enforce_replay_prevention = false

    secret = "abc123"
    type   = "SECRET"
  }

  // jwks_settings {
  //   jwks = "https://stuff"
  // }
  default_access_token_manager_ref {
    id = pingfederate_oauth_access_token_manager.reftokenmgr.id
  }

  oidc_policy {
    grant_access_session_revocation_api = false

    logout_uris = [
      "https://logout",
      "https://foo",
    ]

    ping_access_logout_capable = true
  }
}

resource "pingfederate_oauth_client" "myoauthcodeclientid" {
  client_id     = "myoauthcodeclientid"
  name          = "myoauthcodeclientid"
  redirect_uris = ["https://app.getpostman.com/oauth2/callback", ]

  grant_types = [
    "CLIENT_CREDENTIALS", "AUTHORIZATION_CODE", "ACCESS_TOKEN_VALIDATION",
  ]

  restricted_response_types = ["code", ]


  client_auth {
    // type                      = "CERTIFICATE"
    // client_cert_issuer_dn     = ""
    // client_cert_subject_dn    = ""
    enforce_replay_prevention = false

    secret = "abc123"
    type   = "SECRET"
  }

  // jwks_settings {
  //   jwks = "https://stuff"
  // }
  default_access_token_manager_ref {
    id = pingfederate_oauth_access_token_manager.reftokenmgr.id
  }

  oidc_policy {
    grant_access_session_revocation_api = false

    logout_uris = [
      "https://logout",
      "https://foo",
    ]

    ping_access_logout_capable = true
  }
}



resource "pingfederate_oauth_auth_server_settings" "settings" {
  scopes {
    name        = "openid"
    description = "openid"
  }
  scopes {
    name        = "profile"
    description = "profile"
  }
  scopes {
    name        = "email"
    description = "email"
  }
  scopes {
    name        = "address"
    description = "address"
  }
  scopes {
    name        = "phone"
    description = "phone"
  }
  scopes {
    name        = "email"
    description = "email"
  }
  scopes {
    name        = "idp"
    description = "idp"
  }




  #   persistent_grant_contract {
  #     extended_attributes = ["woot"]
  #   }

  #   allowed_origins = [
  #     "http://localhost",
  #   ]


  exclusive_scopes {
    description = "Account Number"
    name        = "acc_no"
  }

  # persistent_grant_contract {
  #   extended_attributes = []
  # }

  default_scope_description  = ""
  authorization_code_timeout = 60
  authorization_code_entropy = 30
  refresh_token_length       = 42
  refresh_rolling_interval   = 0
}


resource "pingfederate_password_credential_validator" "simplepcv" {
  name = "simplepcv"
  plugin_descriptor_ref {
    id = "org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator"
  }

  configuration {
    tables {
      name = "Users"
      rows {
        fields {
          name  = "Username"
          value = "homer"
        }

        sensitive_fields {
          name  = "Password"
          value = "abc123"
        }

        sensitive_fields {
          name  = "Confirm Password"
          value = "abc123"
        }

        fields {
          name  = "Relax Password Requirements"
          value = "true"
        }
      }
    }
  }
  attribute_contract {
    core_attributes = ["username"]
  }
}


resource "pingfederate_idp_adapter" "basicadptr" {
  name = "basicadptr"
  plugin_descriptor_ref {
    id = "com.pingidentity.adapters.httpbasic.idp.HttpBasicIdpAuthnAdapter"
  }

  configuration {
    tables {
      name = "Credential Validators"
      rows {
        fields {
          name  = "Password Credential Validator Instance"
          value = pingfederate_password_credential_validator.simplepcv.name
        }
      }
    }
    fields {
      name  = "Realm"
      value = "foo"
    }

    fields {
      name  = "Challenge Retries"
      value = "3"
    }

  }

  attribute_contract {
    core_attributes {
      name      = "username"
      pseudonym = true
    }
    extended_attributes {
      name = "given_name"
    }
    extended_attributes {
      name = "family_name"
    }
    extended_attributes {
      name = "email"
    }
    extended_attributes {
      name = "email_verified"
    }
  }
  attribute_mapping {
    attribute_contract_fulfillment {
      key_name = "username"
      source {
        type = "ADAPTER"
      }
      value = "username"
    }
    attribute_contract_fulfillment {
      key_name = "given_name"
      source {
        type = "TEXT"
      }
      value = "Homer"
    }
    attribute_contract_fulfillment {
      key_name = "family_name"
      source {
        type = "TEXT"
      }
      value = "Simpson"
    }
    attribute_contract_fulfillment {
      key_name = "email"
      source {
        type = "TEXT"
      }
      value = "homer.simpson@springfield.net"
    }
    attribute_contract_fulfillment {
      key_name = "email_verified"
      source {
        type = "TEXT"
      }
      value = "homer.simpson@springfield.net"
    }
    # jdbc_attribute_source {
    #   filter      = "\"\""
    #   description = "foo"
    #   schema      = "INFORMATION_SCHEMA"
    #   table       = "ADMINISTRABLE_ROLE_AUTHORIZATIONS"
    #   data_store_ref {
    #     id = "ProvisionerDS"
    #   }
    #}
  }
}

resource "pingfederate_authentication_policy_contract" "apc_simple" {
  name = "apc_simple"
  // no longer need to set core attributes
  //core_attributes = ["subject"]
  extended_attributes = ["given_name", "family_name", "email", "email_verified"]
}

# resource "pingfederate_oauth_openid_connect_policy" "demo" {
#   policy_id = "foo"
#   name      = "foo"
#   access_token_manager_ref {
#     id = pingfederate_oauth_access_token_manager.reftokenmgrcode.id
#   }
#   attribute_contract {
#     # core_attributes {
#     #   name = "sub"
#     # }
#     extended_attributes {
#       name                 = "sub"
#       include_in_user_info = true
#     }
#   }
#   attribute_mapping {
#     attribute_contract_fulfillment {
#       key_name = "sub"
#       source {
#         type = "access_token"
#       }
#     }
#   }

# //  scope_attribute_mappings = { //TODO hoping the new TF 2.0.0 SDK will finally support sensible maps
# //    address = ["foo", "bar"]
# // 
# }


resource "pingfederate_oauth_authentication_policy_contract_mapping" "apc_mappings" {
  authentication_policy_contract_ref {
    id = pingfederate_authentication_policy_contract.apc_simple.id
  }
  attribute_contract_fulfillment {
    key_name = "USER_NAME"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "email"
  }
  attribute_contract_fulfillment {
    key_name = "USER_KEY"
    source {
      type = "AUTHENTICATION_POLICY_CONTRACT"
    }
    value = "email"
  }
}

resource "pingfederate_oauth_openid_connect_policy" "demo_oidc_policy" {
  policy_id = "demo_oidc_policy"
  name      = "demo_oidc_policy"
  access_token_manager_ref {
    id = pingfederate_oauth_access_token_manager.reftokenmgrcode.id
  }
  attribute_contract {
    #   core_attributes {
    #     name = "sub"
    #   }
    extended_attributes {
      name                 = "email"
      include_in_user_info = true
    }
    extended_attributes {
      name                 = "email_verified"
      include_in_user_info = true
    }
    extended_attributes {
      name                 = "family_name"
      include_in_user_info = true
    }
    extended_attributes {
      name                 = "given_name"
      include_in_user_info = true
    }
  }
  attribute_mapping {
    attribute_contract_fulfillment {
      key_name = "sub"
      value    = "sub"
      source {
        type = "TOKEN"
      }
    }
    attribute_contract_fulfillment {
      key_name = "email"
      value    = "email"
      source {
        type = "TOKEN"
      }
    }
    attribute_contract_fulfillment {
      key_name = "email_verified"
      value    = "email_verified"
      source {
        type = "TOKEN"
      }
    }
    attribute_contract_fulfillment {
      key_name = "family_name"
      value    = "family_name"
      source {
        type = "TOKEN"
      }
    }
    attribute_contract_fulfillment {
      key_name = "given_name"
      value    = "given_name"
      source {
        type = "TOKEN"
      }
    }
  }

  //  scope_attribute_mappings = { //TODO hoping the new TF 2.0.0 SDK will finally support sensible maps
  //    address = ["foo", "bar"]
  //  }
}

resource "pingfederate_authentication_policies" "demo" {
  fail_if_no_selection    = false
  # tracked_http_parameters = ["foo"]
  default_authentication_sources {
    type = "IDP_ADAPTER"
    source_ref {
      id = pingfederate_idp_adapter.basicadptr.id
    }
  }
  authn_selection_trees {
    name = "bar"
    root_node {
      action {
        type = "AUTHN_SOURCE"
        authentication_source {
          type = "IDP_ADAPTER"
          source_ref {
            id = pingfederate_idp_adapter.basicadptr.id
          }
        }
      }
      children {
        action {
          type    = "DONE"
          context = "Fail"
        }
      }
      children {
        action {
          type    = "APC_MAPPING"
          context = "Success"
          authentication_policy_contract_ref {
          id = pingfederate_authentication_policy_contract.apc_simple.id
          }
          attribute_mapping {
            attribute_contract_fulfillment{
              key_name = "email"
              value = "email"
            }
            attribute_contract_fulfillment{
              key_name = "email_verified"
              value = "email_verified"
            }
            attribute_contract_fulfillment{
              key_name = "given_name"
              value = "given_name"
            }
            attribute_contract_fulfillment{
              key_name = "family_name"
              value = "family_name"
            }
            attribute_contract_fulfillment{
              key_name = "subject"
              value = "username"
            }
          } 


        
             

        }
      }
    }
  }
}