---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pingfederate_authentication_policy_contract Resource - terraform-provider-pingfederate"
subcategory: ""
description: |-
  Provides configuration for Authentication Policy Contracts within PingFederate.
---

# pingfederate_authentication_policy_contract (Resource)

Provides configuration for Authentication Policy Contracts within PingFederate.

## Example Usage

```terraform
resource "pingfederate_authentication_policy_contract" "example" {
  name                = "example"
  extended_attributes = ["foo", "bar"]
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **name** (String) The Authentication Policy Contract Name. Name is unique.

### Optional

- **extended_attributes** (Set of String) A list of additional attributes as needed.
- **policy_contract_id** (String) The persistent, unique ID for the authentication policy contract. It can be any combination of [a-zA-Z0-9._-]. This property is system-assigned if not specified.

### Read-Only

- **core_attributes** (Set of String) A list of read-only assertion attributes (for example, subject) that are automatically populated by PingFederate.
- **id** (String) The ID of this resource.

## Import

Import is supported using the following syntax:

```shell
terraform import pingfederate_authentication_policy_contract.example 123
```
