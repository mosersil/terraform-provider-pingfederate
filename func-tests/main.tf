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
    extended_attributes = ["sub", "attr1", "attr2"]
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
  attribute_contract_fulfillment {
    key_name = "attr2"
    source {
      type = "TEXT"
    }
    value = "Simpson"
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


resource "pingfederate_oauth_auth_server_settings" "settings" {
  # scopes {
  #   name        = "acc_no"
  #   description = "Accout Number"
  # }

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

  persistent_grant_contract {
    extended_attributes = []
  }

  default_scope_description  = ""
  authorization_code_timeout = 60
  authorization_code_entropy = 30
  refresh_token_length       = 42
  refresh_rolling_interval   = 0
}