---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pingfederate_authentication_api_settings Resource - terraform-provider-pingfederate"
subcategory: ""
description: |-
  Manages Authentication API Settings.
  -> This resource manages a singleton within PingFederate and as such you should ONLY ever declare one of this resource type. Deleting this resource simply stops tracking changes.
---

# pingfederate_authentication_api_settings (Resource)

Manages Authentication API Settings.

-> This resource manages a singleton within PingFederate and as such you should ONLY ever declare one of this resource type. Deleting this resource simply stops tracking changes.

## Example Usage

```terraform
resource "pingfederate_authentication_api_settings" "settings" {
  api_enabled             = true
  enable_api_descriptions = false
  default_application_ref {
    id = pingfederate_authentication_api_application.example.id
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **api_enabled** (Boolean) Specifies whether the authentication API is enabled. The default value is false.
- **default_application_ref** (Block List, Max: 1) Application for non authentication policy use cases. (see [below for nested schema](#nestedblock--default_application_ref))
- **enable_api_descriptions** (Boolean) Enable the API Descriptions endpoint.

### Read-Only

- **id** (String) The ID of this resource.

<a id="nestedblock--default_application_ref"></a>
### Nested Schema for `default_application_ref`

Required:

- **id** (String) The ID of the resource.

Read-Only:

- **location** (String) A read-only URL that references the resource. If the resource is not currently URL-accessible, this property will be null.

## Import

Import is supported using the following syntax:

```shell
# singleton resource with fixed id.
terraform import pingfederate_authentication_api_settings.settings default_authentication_api_settings
```
