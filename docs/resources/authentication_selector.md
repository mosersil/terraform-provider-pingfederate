---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "pingfederate_authentication_selector Resource - terraform-provider-pingfederate"
subcategory: ""
description: |-
  Provides configuration for Authentication Selectors within PingFederate.
---

# pingfederate_authentication_selector (Resource)

Provides configuration for Authentication Selectors within PingFederate.

## Example Usage

```terraform
resource "pingfederate_authentication_selector" "example" {
  name = "example"
  plugin_descriptor_ref {
    id = "com.pingidentity.pf.selectors.cidr.CIDRAdapterSelector"
  }

  configuration {
    fields {
      name  = "Result Attribute Name"
      value = ""
    }
    tables {
      name = "Networks"
      rows {
        fields {
          name  = "Network Range (CIDR notation)"
          value = "127.0.0.1/32"
        }
      }
    }
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **configuration** (Block List, Min: 1, Max: 1) Plugin instance configuration. (see [below for nested schema](#nestedblock--configuration))
- **name** (String) The plugin instance name. The name cannot be modified once the instance is created.
Note: Ignored when specifying a connection's adapter override.
- **plugin_descriptor_ref** (Block List, Min: 1, Max: 1) Reference to the plugin descriptor for this instance. The plugin descriptor cannot be modified once the instance is created.
Note: Ignored when specifying a connection's adapter override. (see [below for nested schema](#nestedblock--plugin_descriptor_ref))

### Optional

- **attribute_contract** (Block List, Max: 1) The list of attributes that the Authentication Selector provides. (see [below for nested schema](#nestedblock--attribute_contract))

### Read-Only

- **id** (String) The ID of this resource.

<a id="nestedblock--configuration"></a>
### Nested Schema for `configuration`

Optional:

- **fields** (Block Set) List of configuration fields. (see [below for nested schema](#nestedblock--configuration--fields))
- **sensitive_fields** (Block Set) List of sensitive configuration fields. (see [below for nested schema](#nestedblock--configuration--sensitive_fields))
- **tables** (Block List) List of configuration tables. (see [below for nested schema](#nestedblock--configuration--tables))

<a id="nestedblock--configuration--fields"></a>
### Nested Schema for `configuration.fields`

Required:

- **name** (String) The name of the configuration field.

Optional:

- **inherited** (Boolean) Whether this field is inherited from its parent instance. If true, the value/encrypted value properties become read-only. The default value is false.
- **value** (String) The value for the configuration field.


<a id="nestedblock--configuration--sensitive_fields"></a>
### Nested Schema for `configuration.sensitive_fields`

Required:

- **name** (String) The name of the configuration field.

Optional:

- **inherited** (Boolean) Whether this field is inherited from its parent instance. If true, the value/encrypted value properties become read-only. The default value is false.
- **value** (String, Sensitive) The value for the configuration field. For encrypted or hashed fields, GETs will not return this attribute. To update an encrypted or hashed field, specify the new value in this attribute.


<a id="nestedblock--configuration--tables"></a>
### Nested Schema for `configuration.tables`

Required:

- **name** (String) The name of the table.

Optional:

- **inherited** (Boolean) Whether this table is inherited from its parent instance. If true, the rows become read-only. The default value is false.
- **rows** (Block List) List of table rows. (see [below for nested schema](#nestedblock--configuration--tables--rows))

<a id="nestedblock--configuration--tables--rows"></a>
### Nested Schema for `configuration.tables.rows`

Optional:

- **default_row** (Boolean) Whether this row is the default.
- **fields** (Block Set) List of configuration fields. (see [below for nested schema](#nestedblock--configuration--tables--rows--fields))
- **sensitive_fields** (Block Set) List of sensitive configuration fields. (see [below for nested schema](#nestedblock--configuration--tables--rows--sensitive_fields))

<a id="nestedblock--configuration--tables--rows--fields"></a>
### Nested Schema for `configuration.tables.rows.fields`

Required:

- **name** (String) The name of the configuration field.

Optional:

- **inherited** (Boolean) Whether this field is inherited from its parent instance. If true, the value/encrypted value properties become read-only. The default value is false.
- **value** (String) The value for the configuration field.


<a id="nestedblock--configuration--tables--rows--sensitive_fields"></a>
### Nested Schema for `configuration.tables.rows.sensitive_fields`

Required:

- **name** (String) The name of the configuration field.

Optional:

- **inherited** (Boolean) Whether this field is inherited from its parent instance. If true, the value/encrypted value properties become read-only. The default value is false.
- **value** (String, Sensitive) The value for the configuration field. For encrypted or hashed fields, GETs will not return this attribute. To update an encrypted or hashed field, specify the new value in this attribute.





<a id="nestedblock--plugin_descriptor_ref"></a>
### Nested Schema for `plugin_descriptor_ref`

Required:

- **id** (String) The ID of the resource.

Read-Only:

- **location** (String) A read-only URL that references the resource. If the resource is not currently URL-accessible, this property will be null.


<a id="nestedblock--attribute_contract"></a>
### Nested Schema for `attribute_contract`

Optional:

- **extended_attributes** (Set of String) A list of additional attributes that can be returned by the Authentication Selector. The extended attributes are only used if the Authentication Selector supports them.

## Import

Import is supported using the following syntax:

```shell
terraform import pingfederate_authentication_selector.example 123
```
