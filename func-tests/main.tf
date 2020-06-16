provider "pingfederate" {
  password = "2Federate"
  base_url = "https://localhost:9998"
}

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
    extended_attributes = ["sub", "attr1"]
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
  attribute_contract_fulfillment {
    key_name = "attr1"
    source {
      type = "TEXT"
    }
    value = "Homer"
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
  client_id = "myoauthcodeclientid"
  name      = "myoauthcodeclientid"
  redirect_uris = ["https://www.bob.com",]

  grant_types = [
    "CLIENT_CREDENTIALS","AUTHORIZATION_CODE",
  ]

  exclusive_scopes = ["acc_no", ]

  restricted_response_types = ["code",]


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
    name        = "oidc"
    description = "oidc"
  }
    scopes {
    name        = "profile"
    description = "profile"
  }
    scopes {
    name        = "email"
    description = "email"
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


resource "pingfederate_idp_adapter" "htmladptr" {
  name = "htmladptr"
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
      name = "sub"
    }
  }
  attribute_mapping {
    attribute_contract_fulfillment {
      key_name = "sub"
      source {
        type = "ADAPTER"
      }
      value = "sub"
    }
    attribute_contract_fulfillment {
      key_name = "username"
      source {
        type = "ADAPTER"
      }
      value = "username"
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
  core_attributes = ["subject"]
  # extended_attributes = ["foo", "bar"]
}

resource "pingfederate_oauth_openid_connect_policy" "demo" {
  policy_id = "foo"
  name      = "foo"
  access_token_manager_ref {
    id = pingfederate_oauth_access_token_manager.reftokenmgr.id
  }
  attribute_contract {
    # core_attributes {
    #   name = "sub"
    # }
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
      name                 = "name"
      include_in_user_info = true
    }
  }
  attribute_mapping {
    attribute_contract_fulfillment {
      key_name = "sub"
      source {
        type = "NO_MAPPING"
      }
    }
    attribute_contract_fulfillment {
      key_name = "email"
      source {
        type = "NO_MAPPING"
      }
    }
    attribute_contract_fulfillment {
      key_name = "email_verified"
      source {
        type = "NO_MAPPING"
      }
    }
    attribute_contract_fulfillment {
      key_name = "family_name"
      source {
        type = "NO_MAPPING"
      }
    }
    attribute_contract_fulfillment {
      key_name = "name"
      source {
        type = "NO_MAPPING"
      }
    }
  }

//  scope_attribute_mappings = { //TODO hoping the new TF 2.0.0 SDK will finally support sensible maps
//    address = ["foo", "bar"]
// 
}


