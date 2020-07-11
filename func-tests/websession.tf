resource "pingaccess_websession" "simplewebsession" {
  name = "simple_webSession"
  audience = "simple_app"
  client_credentials {
    client_id = "myoauthcodeclientid"

    client_secret {
      value = "abc123"
    }
  }
