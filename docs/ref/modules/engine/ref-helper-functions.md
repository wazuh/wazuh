# Summary

This documentation provides an overview of the auxiliary functions available. Auxiliary functions are modular components designed to perform specific operations on decoders or rules. Depending on their purpose, they are categorized into transformation, filter, or mapping functions.

## Index

### Filter

- [array_contains](#array_contains)
- [array_contains_any](#array_contains_any)
- [array_not_contains](#array_not_contains)
- [array_not_contains_any](#array_not_contains_any)
- [binary_and](#binary_and)
- [contains](#contains)
- [ends_with](#ends_with)
- [exists](#exists)
- [exists_key_in](#exists_key_in)
- [int_equal](#int_equal)
- [int_greater](#int_greater)
- [int_greater_or_equal](#int_greater_or_equal)
- [int_less](#int_less)
- [int_less_or_equal](#int_less_or_equal)
- [int_not_equal](#int_not_equal)
- [ip_cidr_match](#ip_cidr_match)
- [is_array](#is_array)
- [is_boolean](#is_boolean)
- [is_ipv4](#is_ipv4)
- [is_ipv6](#is_ipv6)
- [is_not_array](#is_not_array)
- [is_not_boolean](#is_not_boolean)
- [is_not_null](#is_not_null)
- [is_not_number](#is_not_number)
- [is_not_object](#is_not_object)
- [is_not_string](#is_not_string)
- [is_null](#is_null)
- [is_number](#is_number)
- [is_object](#is_object)
- [is_public_ip](#is_public_ip)
- [is_string](#is_string)
- [is_test_session](#is_test_session)
- [keys_exist_in_list](#keys_exist_in_list)
- [kvdb_match](#kvdb_match)
- [kvdb_not_match](#kvdb_not_match)
- [match_value](#match_value)
- [not_exists](#not_exists)
- [number_equal](#number_equal)
- [number_greater](#number_greater)
- [number_greater_or_equal](#number_greater_or_equal)
- [number_less](#number_less)
- [number_less_or_equal](#number_less_or_equal)
- [number_not_equal](#number_not_equal)
- [regex_match](#regex_match)
- [regex_not_match](#regex_not_match)
- [starts_with](#starts_with)
- [string_equal](#string_equal)
- [string_greater](#string_greater)
- [string_greater_or_equal](#string_greater_or_equal)
- [string_less](#string_less)
- [string_less_or_equal](#string_less_or_equal)
- [string_not_equal](#string_not_equal)

### Map

- [array_extract_key_obj](#array_extract_key_obj)
- [array_obj_to_mapkv](#array_obj_to_mapkv)
- [as](#as)
- [concat](#concat)
- [concat_any](#concat_any)
- [date_from_epoch](#date_from_epoch)
- [date_to_epoch](#date_to_epoch)
- [decode_base16](#decode_base16)
- [downcase](#downcase)
- [float_calculate](#float_calculate)
- [geoip](#geoip)
- [get_date](#get_date)
- [hex_to_number](#hex_to_number)
- [iana_protocol_name_to_number](#iana_protocol_name_to_number)
- [iana_protocol_number_to_name](#iana_protocol_number_to_name)
- [int_calculate](#int_calculate)
- [ip_version](#ip_version)
- [join](#join)
- [network_community_id](#network_community_id)
- [regex_extract](#regex_extract)
- [sha1](#sha1)
- [syslog_extract_facility](#syslog_extract_facility)
- [syslog_extract_severity](#syslog_extract_severity)
- [system_epoch](#system_epoch)
- [to_bool](#to_bool)
- [to_int](#to_int)
- [to_string](#to_string)
- [upcase](#upcase)

### Transformation

- [array_append](#array_append)
- [array_append_any](#array_append_any)
- [array_append_unique](#array_append_unique)
- [array_append_unique_any](#array_append_unique_any)
- [delete](#delete)
- [delete_fields_with_value](#delete_fields_with_value)
- [erase_custom_fields](#erase_custom_fields)
- [get_key_in](#get_key_in)
- [kvdb_decode_bitmask](#kvdb_decode_bitmask)
- [kvdb_get](#kvdb_get)
- [kvdb_get_array](#kvdb_get_array)
- [kvdb_get_merge](#kvdb_get_merge)
- [kvdb_get_merge_recursive](#kvdb_get_merge_recursive)
- [merge](#merge)
- [merge_key_in](#merge_key_in)
- [merge_recursive_key_in](#merge_recursive_key_in)
- [parse_alphanumeric](#parse_alphanumeric)
- [parse_between](#parse_between)
- [parse_binary](#parse_binary)
- [parse_bool](#parse_bool)
- [parse_byte](#parse_byte)
- [parse_csv](#parse_csv)
- [parse_date](#parse_date)
- [parse_double](#parse_double)
- [parse_dsv](#parse_dsv)
- [parse_file](#parse_file)
- [parse_float](#parse_float)
- [parse_fqdn](#parse_fqdn)
- [parse_ip](#parse_ip)
- [parse_json](#parse_json)
- [parse_key_value](#parse_key_value)
- [parse_long](#parse_long)
- [parse_quoted](#parse_quoted)
- [parse_uri](#parse_uri)
- [parse_useragent](#parse_useragent)
- [parse_xml](#parse_xml)
- [rename](#rename)
- [replace](#replace)
- [sanitize_fields](#sanitize_fields)
- [split](#split)
- [trim](#trim)

# array_contains

## Signature

```

field: array_contains(element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks if all elements are present in a given array.
It supports multiple data types, including objects, arrays, numbers, strings, and boolean values.
As a variadic function, it accepts multiple elements as search arguments.
A test passes if all provided elements exist in the target array.
If at least one element is missing, the validation fails.
This behavior makes it useful for filtering lists based on the presence of specific values.


## Keywords

- `array` 

## Examples

### Example 1

All specified elements are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains('dracut', 'vz-start', 'thin-provisioning-tools')
```

#### Input Event

```json
{
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was successful*

### Example 2

At least one specified element ("iscsi") is missing from the target array.

#### Asset

```yaml
check:
  - target_field: array_contains($element, 'vz-start', 'iscsi')
```

#### Input Event

```json
{
  "element": "dracut",
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was performed with errors*

### Example 3

All specified numbers are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains(2, 1, 5)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The check was successful*

### Example 4

All specified objects are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains($element, {'key1': 'value1'}, {'key2': 'value2'})
```

#### Input Event

```json
{
  "element": {
    "key": "value"
  },
  "target_field": [
    {
      "key": "value"
    },
    {
      "key1": "value1"
    },
    {
      "key2": "value2"
    }
  ]
}
```

*The check was successful*

### Example 5

At least one specified object is missing from the target array.

#### Asset

```yaml
check:
  - target_field: array_contains({'key': 'value'}, {'key-non-exists': 'value-non-exists'}, {'keyn': 'valuen'})
```

#### Input Event

```json
{
  "target_field": [
    {
      "key": "value"
    },
    {
      "key1": "value1"
    },
    {
      "key2": "value2"
    }
  ]
}
```

*The check was performed with errors*

### Example 6

The specified object, number, and string are all present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains($element, 1, 'value')
```

#### Input Event

```json
{
  "element": {
    "key": "value"
  },
  "target_field": [
    {
      "key": "value"
    },
    1,
    "value"
  ]
}
```

*The check was successful*



---
# array_contains_any

## Signature

```

field: array_contains_any(element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether at least one of the provided elements is present in a given array.
It supports multiple data types, including objects, arrays, numbers, strings, and boolean values.
As a variadic function, it accepts multiple elements as search arguments.
A test passes if at least one provided element exists in the target array.
If none of the elements are found, the validation fails.
This behavior makes it useful for filtering lists based on partial matches.


## Keywords

- `array` 

## Examples

### Example 1

All specified elements are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains_any('dracut', 'vz-start', 'thin-provisioning-tools')
```

#### Input Event

```json
{
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was successful*

### Example 2

At least one specified element ("dracut") is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains_any($element, 'hello', 'wazuh')
```

#### Input Event

```json
{
  "element": "dracut",
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was successful*

### Example 3

At least one specified number (1) is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains_any(7, 1, 8)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The check was successful*

### Example 4

At least one specified object is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains_any($element, {'key-non-exists': 'value-non-exists'}, {'keyn': 'valuen'})
```

#### Input Event

```json
{
  "element": {
    "key": "value"
  },
  "target_field": [
    {
      "key": "value"
    },
    {
      "key1": "value1"
    },
    {
      "key2": "value2"
    }
  ]
}
```

*The check was successful*

### Example 5

At least one specified element (1000) is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_contains_any({'keyn': 'valuen'}, 1000, 'valuen')
```

#### Input Event

```json
{
  "target_field": [
    {
      "key": "value"
    },
    1000,
    "value"
  ]
}
```

*The check was successful*



---
# array_not_contains

## Signature

```

field: array_not_contains(element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Determines whether one or more elements are absent from a given array.
It supports multiple data types, including objects, arrays, numbers, strings, and boolean values.
As a variadic function, it accepts multiple elements as search arguments.
A test passes if none of the provided elements exist in the target array.
If all elements in the array are found, validation fails.
This behavior is useful for filtering lists by excluding specific values.


## Keywords

- `array` 

## Examples

### Example 1

All specified elements are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains('dracut', 'vz-start', 'thin-provisioning-tools')
```

#### Input Event

```json
{
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was performed with errors*

### Example 2

At least one specified element ("iscsi") is missing from the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains($element, 'vz-start', 'iscsi')
```

#### Input Event

```json
{
  "element": "dracut",
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was successful*

### Example 3

All specified numbers are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains(2, 1, 5)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The check was performed with errors*

### Example 4

All specified objects are present in the target array, causing the test to fail.

#### Asset

```yaml
check:
  - target_field: array_not_contains($element, {'key1': 'value1'}, {'key2': 'value2'})
```

#### Input Event

```json
{
  "element": {
    "key": "value"
  },
  "target_field": [
    {
      "key": "value"
    },
    {
      "key1": "value1"
    },
    {
      "key2": "value2"
    }
  ]
}
```

*The check was performed with errors*

### Example 5

At least one specified object is missing from the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains({'key': 'value'}, {'key-non-exists': 'value-non-exists'}, {'keyn': 'valuen'})
```

#### Input Event

```json
{
  "target_field": [
    {
      "key": "value"
    },
    {
      "key1": "value1"
    },
    {
      "key2": "value2"
    }
  ]
}
```

*The check was successful*

### Example 6

The specified object, number, and string are all present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains($element, 1, 'value')
```

#### Input Event

```json
{
  "element": {
    "key": "value"
  },
  "target_field": [
    {
      "key": "value"
    },
    1,
    "value"
  ]
}
```

*The check was performed with errors*



---
# array_not_contains_any

## Signature

```

field: array_not_contains_any(element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether none of the provided elements are present in a given array.
It supports multiple data types, including objects, arrays, numbers, strings, and boolean values.
As a variadic function, it accepts multiple elements as search arguments.
A test passes if none of the provided elements exist in the target array.
If at least one element is found, the validation fails.
This behavior makes it useful for filtering lists to exclude specific values.


## Keywords

- `array` 

## Examples

### Example 1

All specified elements are present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains_any('dracut', 'vz-start', 'thin-provisioning-tools')
```

#### Input Event

```json
{
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was performed with errors*

### Example 2

At least one specified element ("dracut") is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains_any($element, 'hello', 'wazuh')
```

#### Input Event

```json
{
  "element": "dracut",
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "framebuffer",
    "dracut",
    "thin-provisioning-tools",
    "lvm2",
    "vz-start"
  ]
}
```

*The check was performed with errors*

### Example 3

At least one specified number (1) is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains_any(7, 1, 8)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The check was performed with errors*

### Example 4

At least one specified object is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains_any($element, {'key-non-exists': 'value-non-exists'}, {'keyn': 'valuen'})
```

#### Input Event

```json
{
  "element": {
    "key": "value"
  },
  "target_field": [
    {
      "key": "value"
    },
    {
      "key1": "value1"
    },
    {
      "key2": "value2"
    }
  ]
}
```

*The check was performed with errors*

### Example 5

At least one specified element (1000) is present in the target array.

#### Asset

```yaml
check:
  - target_field: array_not_contains_any({'keyn': 'valuen'}, 1000, 'valuen')
```

#### Input Event

```json
{
  "target_field": [
    {
      "key": "value"
    },
    1000,
    "value"
  ]
}
```

*The check was performed with errors*

### Example 6

No elements are present in the array.

#### Asset

```yaml
check:
  - target_field: array_not_contains_any($element, 10, 'valuen')
```

#### Input Event

```json
{
  "element": {
    "key1": "value1"
  },
  "target_field": [
    {
      "key": "value"
    },
    1000,
    "value"
  ]
}
```

*The check was successful*



---
# binary_and

## Signature

```

field: binary_and(hexadecimal)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| hexadecimal | string | value | Any hexadecimal |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any hexadecimal |


## Description

Transforms the hexadecimal value into an unsigned integer and performs the AND bit by bit with the field hexadecimal
transformed to unsigned int. If it is other than 0x0 then the operation evaluates to true.


## Keywords

- `undefined` 

## Examples

### Example 1

Success binary and

#### Asset

```yaml
check:
  - target_field: binary_and('0x4F1')
```

#### Input Event

```json
{
  "target_field": "0x1"
}
```

*The check was successful*



---
# contains

## Signature

```

field: contains(searched_value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| searched_value | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if the value stored in the field contains the value provided.
If they're not, the function evaluates to false.
In case of error, the function will evaluate to false.


## Keywords

- `undefined` 

## Examples

### Example 1

Success contains

#### Asset

```yaml
check:
  - target_field: contains('hello')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was successful*

### Example 2

Failure contains

#### Asset

```yaml
check:
  - target_field: contains($searched_value)
```

#### Input Event

```json
{
  "searched_value": "hello!",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 3

Failure contains

#### Asset

```yaml
check:
  - target_field: contains('world')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*



---
# ends_with

## Signature

```

field: ends_with(conteined)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| conteined | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if the string stored in the field ends with the value provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.


## Keywords

- `string` 

## Examples

### Example 1

Success ends with

#### Asset

```yaml
check:
  - target_field: ends_with('wazuh!!')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!!"
}
```

*The check was successful*

### Example 2

Failure ends with

#### Asset

```yaml
check:
  - target_field: ends_with($conteined)
```

#### Input Event

```json
{
  "conteined": "wazuh",
  "target_field": "hello wazuh!!!"
}
```

*The check was performed with errors*

### Example 3

Failure ends with

#### Asset

```yaml
check:
  - target_field: ends_with('hello')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*



---
# exists

## Signature

```

field: exists()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the key named “field” exists in the event.
If it does, the function will evaluate to true, otherwise it will be false.
This helper function is used in the check stage.


## Keywords

- `undefined` 

## Examples

### Example 1

Target Field exist

#### Asset

```yaml
check:
  - target_field: exists()
```

#### Input Event

```json
{
  "target_field": 1234
}
```

*The check was successful*



---
# exists_key_in

## Signature

```

field: exists_key_in(object)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| object | object | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if the target field value is present as a key in the specified object.
This parameter must be a definition object or a reference to a field containing the object.
If the object contains the key, then the function will evaluate to true, otherwise it will be false.
This helper function is typically used in the check stage.


## Keywords

- `undefined` 

## Examples

### Example 1

Compare two different integers

#### Asset

```yaml
check:
  - target_field: exists_key_in({'key': 'value'})
```

#### Input Event

```json
{
  "target_field": "key-not-exist"
}
```

*The check was performed with errors*

### Example 2

Compare two equals integers

#### Asset

```yaml
check:
  - target_field: exists_key_in($object)
```

#### Input Event

```json
{
  "object": {
    "key": "value"
  },
  "target_field": "key"
}
```

*The check was successful*



---
# int_equal

## Signature

```

field: int_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checkers whether the integer number stored in field is equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `integer` 

- `comparison` 

## Examples

### Example 1

Compare two different integers

#### Asset

```yaml
check:
  - target_field: int_equal(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

Compare two equals integers

#### Asset

```yaml
check:
  - target_field: int_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 22,
  "target_field": 22
}
```

*The check was successful*



---
# int_greater

## Signature

```

field: int_greater(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checkers whether the integer number stored in field is greater than to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `integer` 

- `comparison` 

## Examples

### Example 1

Success int greater

#### Asset

```yaml
check:
  - target_field: int_greater(1)
```

#### Input Event

```json
{
  "target_field": 100
}
```

*The check was successful*

### Example 2

Failure int greater

#### Asset

```yaml
check:
  - target_field: int_greater($any_number)
```

#### Input Event

```json
{
  "any_number": 50,
  "target_field": 20
}
```

*The check was performed with errors*

### Example 3

Failure int greater

#### Asset

```yaml
check:
  - target_field: int_greater(1000)
```

#### Input Event

```json
{
  "target_field": 1000
}
```

*The check was performed with errors*



---
# int_greater_or_equal

## Signature

```

field: int_greater_or_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checkers whether the integer number stored in field is greater than or equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `integer` 

- `comparison` 

## Examples

### Example 1

Failure int greater or equal

#### Asset

```yaml
check:
  - target_field: int_greater_or_equal(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

Success int greater or equal

#### Asset

```yaml
check:
  - target_field: int_greater_or_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 22,
  "target_field": 22
}
```

*The check was successful*

### Example 3

Success int greater or equal

#### Asset

```yaml
check:
  - target_field: int_greater_or_equal(2)
```

#### Input Event

```json
{
  "target_field": 22
}
```

*The check was successful*



---
# int_less

## Signature

```

field: int_less(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checkers whether the integer number stored in field is less than to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `integer` 

- `comparison` 

## Examples

### Example 1

Success int less

#### Asset

```yaml
check:
  - target_field: int_less(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Failure int less

#### Asset

```yaml
check:
  - target_field: int_less($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 22
}
```

*The check was performed with errors*

### Example 3

Failure int less

#### Asset

```yaml
check:
  - target_field: int_less(100)
```

#### Input Event

```json
{
  "target_field": 100
}
```

*The check was performed with errors*



---
# int_less_or_equal

## Signature

```

field: int_less_or_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checkers whether the integer number stored in field is less than or equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `integer` 

- `comparison` 

## Examples

### Example 1

Success int less or equal

#### Asset

```yaml
check:
  - target_field: int_less_or_equal(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Success int less or equal

#### Asset

```yaml
check:
  - target_field: int_less_or_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 22,
  "target_field": 22
}
```

*The check was successful*

### Example 3

Failure int less or equal

#### Asset

```yaml
check:
  - target_field: int_less_or_equal(2)
```

#### Input Event

```json
{
  "target_field": 22
}
```

*The check was performed with errors*



---
# int_not_equal

## Signature

```

field: int_not_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checkers whether the integer number stored in field is not equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `integer` 

- `comparison` 

## Examples

### Example 1

Success int not equal

#### Asset

```yaml
check:
  - target_field: int_not_equal(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Failure int not equal

#### Asset

```yaml
check:
  - target_field: int_not_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 22,
  "target_field": 22
}
```

*The check was performed with errors*



---
# ip_cidr_match

## Signature

```

field: ip_cidr_match(subnet, mask)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| subnet | string | value | Any IP |
| mask | string | value | Any IP |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks if the IP address stored in field belongs to a given CIDR notation range.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
IPv4: support address in dotted-decimal format, "ddd.ddd.ddd.ddd" where ddd is a decimal number of up
to three digits in the range  0  to  255.
Mask: Support “dd”  where ddd is a decimal number of up to 2 digits in the range  0  to  32 or “ddd.ddd.ddd.ddd"
where ddd is a decimal number of up to three digits in the range  0  to  255.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Match IP CIDR

#### Asset

```yaml
check:
  - target_field: ip_cidr_match('192.168.0.0', '192.168.0.11')
```

#### Input Event

```json
{
  "target_field": "192.168.1.5"
}
```

*The check was successful*

### Example 2

Don't match IP CIDR

#### Asset

```yaml
check:
  - target_field: ip_cidr_match('192.168.0.0', '192.168.0.11')
```

#### Input Event

```json
{
  "target_field": "111.111.1.11"
}
```

*The check was performed with errors*



---
# is_array

## Signature

```

field: is_array()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | Integers between `-2^63` and `2^63-1` |


## Description

Checks if the value stored in field is of type array.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is array

#### Asset

```yaml
check:
  - target_field: is_array()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was successful*

### Example 2

Not is array

#### Asset

```yaml
check:
  - target_field: is_array()
```

#### Input Event

```json
{}
```

*The check was performed with errors*

### Example 3

Not is array

#### Asset

```yaml
check:
  - target_field: is_array()
```

#### Input Event

```json
{
  "target_field": "false"
}
```

*The check was performed with errors*



---
# is_boolean

## Signature

```

field: is_boolean()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Checks if the value stored in field is of type boolean.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is boolean

#### Asset

```yaml
check:
  - target_field: is_boolean()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was successful*

### Example 2

Is boolean

#### Asset

```yaml
check:
  - target_field: is_boolean()
```

#### Input Event

```json
{}
```

*The check was successful*

### Example 3

Not is boolean

#### Asset

```yaml
check:
  - target_field: is_boolean()
```

#### Input Event

```json
{
  "target_field": "false"
}
```

*The check was performed with errors*



---
# is_ipv4

## Signature

```

field: is_ipv4()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks if the IP address stored in the field is an IPv4.
IPv4:
  - 10.0.0.0
  - 172.16.0.0
  - 192.168.0.0
  - 127.0.0.0
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Invalid IPv4. It's an IPv6

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": "3002:0bd6:0000:0000:0000:ee00:0033:6778"
}
```

*The check was performed with errors*

### Example 2

Valid special IPv4

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": "127.0.0.1"
}
```

*The check was successful*

### Example 3

Valid special IPv4

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": "192.168.0.0"
}
```

*The check was successful*

### Example 4

Valid public IPv4

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": "8.8.8.8"
}
```

*The check was successful*



---
# is_ipv6

## Signature

```

field: is_ipv6()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks if the IP address stored in the field is an IPv6.
IPv6:
  - ::1
  - fd00:abcd::1234
  - a03:2880:f10c:83:face:b00c::25de
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Invalid IPv6. It's an IPv4

#### Asset

```yaml
check:
  - target_field: is_ipv6()
```

#### Input Event

```json
{
  "target_field": "127.0.0.1"
}
```

*The check was performed with errors*

### Example 2

Valid special IPv6

#### Asset

```yaml
check:
  - target_field: is_ipv6()
```

#### Input Event

```json
{
  "target_field": "::1"
}
```

*The check was successful*

### Example 3

Valid special IPv6

#### Asset

```yaml
check:
  - target_field: is_ipv6()
```

#### Input Event

```json
{
  "target_field": "fd00:abcd::1234"
}
```

*The check was successful*

### Example 4

Valid public IPv6

#### Asset

```yaml
check:
  - target_field: is_ipv6()
```

#### Input Event

```json
{
  "target_field": "a03:2880:f10c:83:face:b00c::25de"
}
```

*The check was successful*



---
# is_not_array

## Signature

```

field: is_not_array()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, boolean, object, string] | - |


## Description

Checks if the value stored in field is not of type array.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is array

#### Asset

```yaml
check:
  - target_field: is_not_array()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was performed with errors*

### Example 2

Not is array

#### Asset

```yaml
check:
  - target_field: is_not_array()
```

#### Input Event

```json
{
  "target_field": 234
}
```

*The check was successful*

### Example 3

Not is array

#### Asset

```yaml
check:
  - target_field: is_not_array()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*



---
# is_not_boolean

## Signature

```

field: is_not_boolean()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, array, object, string] | - |


## Description

Checks if the value stored in field is not of type boolean.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is boolean

#### Asset

```yaml
check:
  - target_field: is_not_boolean()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was performed with errors*

### Example 2

Not is boolean

#### Asset

```yaml
check:
  - target_field: is_not_boolean()
```

#### Input Event

```json
{
  "target_field": 234
}
```

*The check was successful*

### Example 3

Not is boolean

#### Asset

```yaml
check:
  - target_field: is_not_boolean()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*



---
# is_not_null

## Signature

```

field: is_not_null()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks if the value stored in field is not null.
If it is null, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Not null (string)

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 2

Not null (number)

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{}
```

*The check was successful*

### Example 3

Not null (boolean)

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was successful*

### Example 4

Not null (array, non-empty)

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{
  "target_field": [
    1
  ]
}
```

*The check was successful*

### Example 5

Not null (object, non-empty)

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*

### Example 6

Missing (empty object is unmapped)

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{}
```

*The check was performed with errors*



---
# is_not_number

## Signature

```

field: is_not_number()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks if the value stored in field is not a number.
If it is a number, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Not number (string)

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 2

Not number (boolean)

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was successful*

### Example 3

number (array not empty)

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{
  "target_field": [
    1
  ]
}
```

*The check was successful*

### Example 4

Not number (object)

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*

### Example 5

Is number

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{}
```

*The check was performed with errors*



---
# is_not_object

## Signature

```

field: is_not_object()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, array, string, boolean] | - |


## Description

Checks if the value stored in field is not of type object.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is object

#### Asset

```yaml
check:
  - target_field: is_not_object()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was performed with errors*

### Example 2

Not is object

#### Asset

```yaml
check:
  - target_field: is_not_object()
```

#### Input Event

```json
{
  "target_field": 234
}
```

*The check was successful*

### Example 3

Not is object

#### Asset

```yaml
check:
  - target_field: is_not_object()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was successful*



---
# is_not_string

## Signature

```

field: is_not_string()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, array, object, boolean] | - |


## Description

Checks if the value stored in field is not of type string.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Not is string

#### Asset

```yaml
check:
  - target_field: is_not_string()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*

### Example 2

Not is string

#### Asset

```yaml
check:
  - target_field: is_not_string()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was successful*

### Example 3

Is string

#### Asset

```yaml
check:
  - target_field: is_not_string()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*



---
# is_null

## Signature

```

field: is_null()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks if the value stored in field is null.
If it's not null, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is null

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{}
```

*The check was performed with errors*

### Example 2

Not null (string)

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*

### Example 3

Not null (number)

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{}
```

*The check was performed with errors*

### Example 4

Not null (array)

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{}
```

*The check was performed with errors*

### Example 5

Not null (object)

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was performed with errors*



---
# is_number

## Signature

```

field: is_number()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks if the value stored in field is of type numeric.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is object

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was performed with errors*

### Example 2

Is array

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was performed with errors*

### Example 3

Not is string

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*

### Example 4

Not is boolean

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was performed with errors*

### Example 5

Is number

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": 23
}
```

*The check was successful*

### Example 6

Is number

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": 23.23
}
```

*The check was successful*



---
# is_object

## Signature

```

field: is_object()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Checks if the value stored in field is of type object.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is object

#### Asset

```yaml
check:
  - target_field: is_object()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*

### Example 2

Is object

#### Asset

```yaml
check:
  - target_field: is_object()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was performed with errors*

### Example 3

Not is object

#### Asset

```yaml
check:
  - target_field: is_object()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*



---
# is_public_ip

## Signature

```

field: is_public_ip()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks if the IP address stored in the field is a public ip.
Assumes that the ip is public if it is not within the following networks:
IPv4:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 127.0.0.0/8
IPv6:
  - fe80::/10
  - fc00::/7
  - ::1/128
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Check IP valid

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "111.111.1.11"
}
```

*The check was successful*

### Example 2

Check IP valid

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "3002:0bd6:0000:0000:0000:ee00:0033:6778"
}
```

*The check was successful*

### Example 3

Check IP invalid

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": 6778
}
```

*The check was performed with errors*



---
# is_string

## Signature

```

field: is_string()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if the value stored in field is of type string.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Not is string

#### Asset

```yaml
check:
  - target_field: is_string()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was performed with errors*

### Example 2

Not is string

#### Asset

```yaml
check:
  - target_field: is_string()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The check was performed with errors*

### Example 3

Is string

#### Asset

```yaml
check:
  - target_field: is_string()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*



---
# is_test_session

## Signature

```

field: is_test_session()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Check if the environment in use is testing or production.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Is test session

#### Asset

```yaml
check:
  - target_field: is_test_session()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*



---
# keys_exist_in_list

## Signature

```

field: keys_exist_in_list(elements)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| elements | array | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Checks if all the specified keys from the target field (an object) are present in the given list.
It verifies whether the elements in the list are included as keys in the target object.
If any key from the target object is missing in the list, the validation fails.
The function does not require that all keys in the list be present in the target field,
but all keys from the target field must be in the list.
If any element in the list is not a string, or if the target object is missing any keys from the list, the validation fails.
This helper is particularly useful for ensuring that all required keys are present in the object and
are strictly enforced in the list.


## Keywords

- `array` 

- `object` 

## Examples

### Example 1

Success keys in list

#### Asset

```yaml
check:
  - target_field: keys_exist_in_list(['ts', 'host'])
```

#### Input Event

```json
{
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z",
    "host": "192.168.4.43"
  }
}
```

*The check was successful*

### Example 2

There are elements in the list that are missing from the target field

#### Asset

```yaml
check:
  - target_field: keys_exist_in_list($elements)
```

#### Input Event

```json
{
  "elements": [
    "ts",
    "host",
    "other"
  ],
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z",
    "host": "192.168.4.43"
  }
}
```

*The check was successful*

### Example 3

There are keys in the target field that are missing from the list

#### Asset

```yaml
check:
  - target_field: keys_exist_in_list(['ts', 'host'])
```

#### Input Event

```json
{
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z",
    "host": "192.168.4.43",
    "other_key": "some_value"
  }
}
```

*The check was performed with errors*

### Example 4

Element in array is not a string

#### Asset

```yaml
check:
  - target_field: keys_exist_in_list($elements)
```

#### Input Event

```json
{
  "elements": [
    "ts",
    9999,
    "other"
  ],
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z",
    "host": "192.168.4.43"
  }
}
```

*The check was performed with errors*



---
# kvdb_match

## Signature

```

field: kvdb_match(db-name)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | testing |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if a given key exist in the DB named db-name. This helper function is typically used in the check stage.


## Keywords

- `kvdb` 

## Examples

### Example 1

Key found in kvdb

#### Asset

```yaml
check:
  - target_field: kvdb_match('testing')
```

#### Input Event

```json
{
  "target_field": "test"
}
```

*The check was successful*

### Example 2

Key not found in kvdb

#### Asset

```yaml
check:
  - target_field: kvdb_match('testing')
```

#### Input Event

```json
{
  "target_field": "k"
}
```

*The check was performed with errors*



---
# kvdb_not_match

## Signature

```

field: kvdb_not_match(db-name)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | testing |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if a given key does not exist in the DB named db-name. This helper function is typically used in the check stage.


## Keywords

- `kvdb` 

## Examples

### Example 1

Key found in kvdb

#### Asset

```yaml
check:
  - target_field: kvdb_not_match('testing')
```

#### Input Event

```json
{
  "target_field": "test"
}
```

*The check was performed with errors*

### Example 2

Key not found in kvdb

#### Asset

```yaml
check:
  - target_field: kvdb_not_match('testing')
```

#### Input Event

```json
{
  "target_field": "k"
}
```

*The check was successful*



---
# match_value

## Signature

```

field: match_value(array)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| array | array | value or reference | [number, string, boolean, object, array] |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks if the target field value is present in the specified array.
This parameter must be a definition array or a reference to a field containing the array.
If the array contains the value, then the function will evaluate to true, otherwise it will be false.
This helper function is typically used in the check stage.


## Keywords

- `undefined` 

## Examples

### Example 1

Value is in array

#### Asset

```yaml
check:
  - target_field: match_value([1, 2, 3, 4])
```

#### Input Event

```json
{
  "target_field": 10
}
```

*The check was performed with errors*

### Example 2

Value not is in array

#### Asset

```yaml
check:
  - target_field: match_value($array)
```

#### Input Event

```json
{
  "array": [
    "hello"
  ],
  "target_field": "wazuh"
}
```

*The check was performed with errors*

### Example 3

Value is in array

#### Asset

```yaml
check:
  - target_field: match_value([{'key': 'value'}])
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*

### Example 4

Value is in array

#### Asset

```yaml
check:
  - target_field: match_value($array)
```

#### Input Event

```json
{
  "array": [
    [
      true,
      "hello",
      2
    ]
  ],
  "target_field": [
    true,
    "hello",
    2
  ]
}
```

*The check was successful*



---
# not_exists

## Signature

```

field: not_exists()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks that the field does not exist.
If the field exists (with any value), the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `undefined` 

## Examples

### Example 1

Field exists (string)

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*

### Example 2

Field exists (number)

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{}
```

*The check was performed with errors*

### Example 3

Field exists (array non-empty)

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{
  "target_field": [
    1
  ]
}
```

*The check was performed with errors*

### Example 4

Field exists (object non-empty)

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

*The check was performed with errors*

### Example 5

Field exists (boolean)

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was performed with errors*

### Example 6

Field absent via empty array

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{}
```

*The check was successful*

### Example 7

Field absent via empty object

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{}
```

*The check was successful*



---
# number_equal

## Signature

```

field: number_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

Checkers whether the number stored in field is equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `number` 

- `comparison` 

## Examples

### Example 1

Compare two different numbers

#### Asset

```yaml
check:
  - target_field: number_equal(2.6)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

Compare two different numbers

#### Asset

```yaml
check:
  - target_field: number_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 6,
  "target_field": 5.5
}
```

*The check was performed with errors*

### Example 3

Compare two equals numbers

#### Asset

```yaml
check:
  - target_field: number_equal(2.3)
```

#### Input Event

```json
{
  "target_field": 2.3
}
```

*The check was successful*

### Example 4

Compare two equals numbers

#### Asset

```yaml
check:
  - target_field: number_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 2.0
}
```

*The check was successful*



---
# number_greater

## Signature

```

field: number_greater(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

Checkers whether the number stored in field is greater than to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `comparison` 

## Examples

### Example 1

Success number greater

#### Asset

```yaml
check:
  - target_field: number_greater(1.5)
```

#### Input Event

```json
{
  "target_field": 4.6
}
```

*The check was successful*

### Example 2

Success number greater

#### Asset

```yaml
check:
  - target_field: number_greater($any_number)
```

#### Input Event

```json
{
  "any_number": 1,
  "target_field": 2.2
}
```

*The check was successful*

### Example 3

Failure number greater

#### Asset

```yaml
check:
  - target_field: number_greater(3.8)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was performed with errors*

### Example 4

Failure number greater

#### Asset

```yaml
check:
  - target_field: number_greater($any_number)
```

#### Input Event

```json
{
  "any_number": 3,
  "target_field": 2.2
}
```

*The check was performed with errors*



---
# number_greater_or_equal

## Signature

```

field: number_greater_or_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

Checkers whether the number stored in field is greater than or equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `number` 

- `comparison` 

## Examples

### Example 1

Failure int greater or equal

#### Asset

```yaml
check:
  - target_field: number_greater_or_equal(2.6)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

Failure int greater or equal

#### Asset

```yaml
check:
  - target_field: number_greater_or_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 1.5
}
```

*The check was performed with errors*

### Example 3

Success int greater or equal

#### Asset

```yaml
check:
  - target_field: number_greater_or_equal(2.2)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was successful*

### Example 4

Success int greater or equal

#### Asset

```yaml
check:
  - target_field: number_greater_or_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 2
}
```

*The check was successful*



---
# number_less

## Signature

```

field: number_less(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

Checkers whether the number stored in field is less than to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `number` 

- `comparison` 

## Examples

### Example 1

Success number less

#### Asset

```yaml
check:
  - target_field: number_less(2.2)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Success number less

#### Asset

```yaml
check:
  - target_field: number_less($any_number)
```

#### Input Event

```json
{
  "any_number": 2.1,
  "target_field": 1.6
}
```

*The check was successful*

### Example 3

Failure number less

#### Asset

```yaml
check:
  - target_field: number_less(2)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was performed with errors*

### Example 4

Failure number less

#### Asset

```yaml
check:
  - target_field: number_less($any_number)
```

#### Input Event

```json
{
  "any_number": 10,
  "target_field": 10
}
```

*The check was performed with errors*



---
# number_less_or_equal

## Signature

```

field: number_less_or_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

Checkers whether the number stored in field is less than or equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `number` 

- `comparison` 

## Examples

### Example 1

Success number less or equal

#### Asset

```yaml
check:
  - target_field: number_less_or_equal(2.2)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Success number less or equal

#### Asset

```yaml
check:
  - target_field: number_less_or_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 1.2
}
```

*The check was successful*

### Example 3

Failure number less or equal

#### Asset

```yaml
check:
  - target_field: number_less_or_equal(1.8)
```

#### Input Event

```json
{
  "target_field": 2.6
}
```

*The check was performed with errors*

### Example 4

Failure number less or equal

#### Asset

```yaml
check:
  - target_field: number_less_or_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 22
}
```

*The check was performed with errors*



---
# number_not_equal

## Signature

```

field: number_not_equal(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | value or reference |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

Checkers whether the number stored in field is not equal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `number` 

- `comparison` 

## Examples

### Example 1

Success number not equal

#### Asset

```yaml
check:
  - target_field: number_not_equal(2.2)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Success number not equal

#### Asset

```yaml
check:
  - target_field: number_not_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 1,
  "target_field": 2.3
}
```

*The check was successful*

### Example 3

Failure number not equal

#### Asset

```yaml
check:
  - target_field: number_not_equal(2.2)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was performed with errors*

### Example 4

Failure number not equal

#### Asset

```yaml
check:
  - target_field: number_not_equal($any_number)
```

#### Input Event

```json
{
  "any_number": 2,
  "target_field": 2
}
```

*The check was performed with errors*



---
# regex_match

## Signature

```

field: regex_match(regxp)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| regxp | string | value | Any regex |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if the given target field contains a string that matches the regex passed.
Evaluates to true if the regex matches, otherwise if it does not match or the target field
does not exist or the target field is not of type string, evaluates to false.
Keep in mind that we need to escape reserved Yaml characters depending on the string input mode of Yaml.
RE2 syntax: https://github.com/google/re2/wiki/Syntax
This helper function is typically used in the check stage.


## Keywords

- `undefined` 

## Examples

### Example 1

Match regular expression

#### Asset

```yaml
check:
  - target_field: regex_match('^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "target_field": "bye pcre2"
}
```

*The check was successful*

### Example 2

Don't match regular expression

#### Asset

```yaml
check:
  - target_field: regex_match('^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "target_field": "ye pcre2"
}
```

*The check was performed with errors*



---
# regex_not_match

## Signature

```

field: regex_not_match(regxp)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| regxp | string | value | Any regex |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks that the target field (string) does NOT match the given regular expression (RE2).
If it matches, evaluates to false. If the field is missing or not a string, evaluates to false.
Keep in mind YAML escaping rules. RE2 syntax: https://github.com/google/re2/wiki/Syntax
Typically used in the check stage.


## Keywords

- `undefined` 

## Examples

### Example 1

Does not match (no 'abc' prefix)

#### Asset

```yaml
check:
  - target_field: regex_not_match('^abc')
```

#### Input Event

```json
{
  "target_field": "hello world"
}
```

*The check was successful*

### Example 2

Matches (prefix 'abc')

#### Asset

```yaml
check:
  - target_field: regex_not_match('^abc')
```

#### Input Event

```json
{
  "target_field": "abc123"
}
```

*The check was performed with errors*

### Example 3

Not a string -> fails

#### Asset

```yaml
check:
  - target_field: regex_not_match('^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "target_field": 123
}
```

*The check was performed with errors*



---
# starts_with

## Signature

```

field: starts_with(conteined)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| conteined | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks if the value stored in the field starts with the value provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.


## Keywords

- `undefined` 

## Examples

### Example 1

Success start with

#### Asset

```yaml
check:
  - target_field: starts_with('hello')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was successful*

### Example 2

Failure start with

#### Asset

```yaml
check:
  - target_field: starts_with($conteined)
```

#### Input Event

```json
{
  "conteined": "hello!",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 3

Failure start with

#### Asset

```yaml
check:
  - target_field: starts_with('wazuh!')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*



---
# string_equal

## Signature

```

field: string_equal(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checkers whether the value stored in field is equal to the one provided, byte for byte.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `string` 

- `comparison` 

## Examples

### Example 1

Compare two different strings

#### Asset

```yaml
check:
  - target_field: string_equal('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*

### Example 2

Compare two equals strings

#### Asset

```yaml
check:
  - target_field: string_equal($any_string)
```

#### Input Event

```json
{
  "any_string": "hello world!",
  "target_field": "hello world!"
}
```

*The check was successful*



---
# string_greater

## Signature

```

field: string_greater(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the value stored in field is lexicographically greater than to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `string` 

- `comparison` 

## Examples

### Example 1

Success string greater

#### Asset

```yaml
check:
  - target_field: string_greater('hello world!')
```

#### Input Event

```json
{
  "target_field": "wazuh"
}
```

*The check was successful*

### Example 2

Failure string greater

#### Asset

```yaml
check:
  - target_field: string_greater($any_string)
```

#### Input Event

```json
{
  "any_string": "wazuh",
  "target_field": "hello world!"
}
```

*The check was performed with errors*

### Example 3

Failure string greater

#### Asset

```yaml
check:
  - target_field: string_greater('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was performed with errors*



---
# string_greater_or_equal

## Signature

```

field: string_greater_or_equal(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the string stored in field is lexicographically greater than or equal
to the provided value. If it is less, evaluates to false. On error, evaluates to false.
Typically used in the check stage.


## Keywords

- `string` 

- `comparison` 

## Examples

### Example 1

Equal strings → passes

#### Asset

```yaml
check:
  - target_field: string_greater_or_equal('hello')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 2

Target >= argument (world >= hello) → passes

#### Asset

```yaml
check:
  - target_field: string_greater_or_equal($any_string)
```

#### Input Event

```json
{
  "any_string": "hello",
  "target_field": "world"
}
```

*The check was successful*

### Example 3

Target < argument (abc < def) → fails

#### Asset

```yaml
check:
  - target_field: string_greater_or_equal('def')
```

#### Input Event

```json
{
  "target_field": "abc"
}
```

*The check was performed with errors*

### Example 4

Not a string → fails

#### Asset

```yaml
check:
  - target_field: string_greater_or_equal($any_string)
```

#### Input Event

```json
{
  "any_string": "abc",
  "target_field": 123
}
```

*The check was performed with errors*



---
# string_less

## Signature

```

field: string_less(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checkers whether the value stored in field is lexicographically less than to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `string` 

- `comparison` 

## Examples

### Example 1

Success string less

#### Asset

```yaml
check:
  - target_field: string_less('wazuh')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was successful*

### Example 2

Failure string less

#### Asset

```yaml
check:
  - target_field: string_less($any_string)
```

#### Input Event

```json
{
  "any_string": "hello world!",
  "target_field": "wazuh"
}
```

*The check was performed with errors*

### Example 3

Failure string less

#### Asset

```yaml
check:
  - target_field: string_less('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was performed with errors*



---
# string_less_or_equal

## Signature

```

field: string_less_or_equal(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checkers whether the value stored in field is lexicographically less than or equeal to the one provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `string` 

- `comparison` 

## Examples

### Example 1

Success string less or equal

#### Asset

```yaml
check:
  - target_field: string_less_or_equal('wazuh')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was successful*

### Example 2

Failure string less or equal

#### Asset

```yaml
check:
  - target_field: string_less_or_equal($any_string)
```

#### Input Event

```json
{
  "any_string": "hello world!",
  "target_field": "wazuh"
}
```

*The check was performed with errors*

### Example 3

Success string less or equal

#### Asset

```yaml
check:
  - target_field: string_less_or_equal('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was successful*



---
# string_not_equal

## Signature

```

field: string_not_equal(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checkers whether the two provided strings are equal, byte for byte.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


## Keywords

- `string` 

- `comparison` 

## Examples

### Example 1

Success string not equal

#### Asset

```yaml
check:
  - target_field: string_not_equal('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 2

Failure string not equal

#### Asset

```yaml
check:
  - target_field: string_not_equal($any_string)
```

#### Input Event

```json
{
  "any_string": "hello world!",
  "target_field": "hello world!"
}
```

*The check was performed with errors*



---
# array_extract_key_obj

## Signature

```

field: array_extract_key_obj(source_array, key_pointer, new_value_pointer, old_value_pointer, skip_serializer)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source_array | array | reference | Any string |
| key_pointer | string | value | Any string |
| new_value_pointer | string | value | Any string |
| old_value_pointer | string | value | Any string |
| skip_serializer | boolean | value | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Builds a map of extracted key objects from an array. Each element provides the key
(via a JSON pointer) and both the new and old values (as JSON pointers, `/` for the full object).
Keys are normalized to lowercase snake_case unless `skipSerializer` is true, in which
case keys are kept verbatim. Entries missing a key or new value, or producing an empty key, are skipped.
Old values that resolve to empty strings are omitted from the result.
The helper returns an error when no entries are inserted.


## Keywords

- `array` 

- `map` 

- `extract` 

- `changes` 

## Examples

### Example 1

Builds map with normalized keys and both new/old values

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_extract_key_obj($source_array, '/Name', '/NewValue', '/OldValue', False)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "RequiredResourceAccess",
      "NewValue": "new-data",
      "OldValue": "old-data"
    },
    {
      "Name": "Included Updated Properties",
      "NewValue": "RequiredResourceAccess",
      "OldValue": ""
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "RequiredResourceAccess",
      "NewValue": "new-data",
      "OldValue": "old-data"
    },
    {
      "Name": "Included Updated Properties",
      "NewValue": "RequiredResourceAccess",
      "OldValue": ""
    }
  ],
  "target_field": {
    "requiredresourceaccess": {
      "NewValue": "new-data",
      "OldValue": "old-data"
    },
    "included_updated_properties": {
      "NewValue": "RequiredResourceAccess"
    }
  }
}
```

*The operation was successful*

### Example 2

Keeps keys verbatim when `skipSerializer` is true

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_extract_key_obj($source_array, '/Name', '/NewValue', '/OldValue', True)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "RequiredResourceAccess",
      "NewValue": "new-data",
      "OldValue": "old-data"
    },
    {
      "Name": "Included Updated Properties",
      "NewValue": "RequiredResourceAccess",
      "OldValue": ""
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "RequiredResourceAccess",
      "NewValue": "new-data",
      "OldValue": "old-data"
    },
    {
      "Name": "Included Updated Properties",
      "NewValue": "RequiredResourceAccess",
      "OldValue": ""
    }
  ],
  "target_field": {
    "RequiredResourceAccess": {
      "NewValue": "new-data",
      "OldValue": "old-data"
    },
    "Included Updated Properties": {
      "NewValue": "RequiredResourceAccess"
    }
  }
}
```

*The operation was successful*

### Example 3

Keeps entries that only provide a new value

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_extract_key_obj($source_array, '/Name', '/NewValue', '/OldValue', False)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "AzurePolicyChange",
      "NewValue": "Enabled"
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "AzurePolicyChange",
      "NewValue": "Enabled"
    }
  ],
  "target_field": {
    "azurepolicychange": {
      "NewValue": "Enabled"
    }
  }
}
```

*The operation was successful*

### Example 4

Discards old value when it resolves to blanks

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_extract_key_obj($source_array, '/Name', '/NewValue', '/OldValue', False)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "AlertThreshold",
      "NewValue": 10,
      "OldValue": "  "
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "AlertThreshold",
      "NewValue": 10,
      "OldValue": "  "
    }
  ],
  "target_field": {
    "alertthreshold": {
      "NewValue": 10
    }
  }
}
```

*The operation was successful*

### Example 5

Fails when new value is missing

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_extract_key_obj($source_array, '/Name', '/NewValue', '/OldValue', False)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "RequiredResourceAccess",
      "OldValue": "old-data"
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "RequiredResourceAccess",
      "OldValue": "old-data"
    }
  ]
}
```

*The operation was performed with errors*

### Example 6

Fails when array does not exist in the context

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_extract_key_obj($source_array, '/Name', '/NewValue', '/OldValue', False)
```

#### Input Event

```json
{
  "source_array": "$.Missing"
}
```

#### Outcome Event

```json
{
  "source_array": "$.Missing"
}
```

*The operation was performed with errors*



---
# array_obj_to_mapkv

## Signature

```

field: array_obj_to_mapkv(source_array, key_pointer, value_pointer, skip_serializer)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source_array | array | reference | Any string |
| key_pointer | string | value | Any string |
| value_pointer | string | value | Any string |
| skip_serializer | boolean | value | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Builds a map (object) from an array of objects. Each element provides the key
(via a JSON pointer) and the value (another pointer, optionally `/` for the full object).
Keys are normalized to lowercase snake_case unless `skipSerializer` is true, in which
case keys are kept verbatim. Entries missing a key/value or producing an empty key
are skipped. The helper returns an error when no entries are inserted.


## Keywords

- `array` 

- `map` 

- `key-value` 

## Examples

### Example 1

Normalizes keys and extracts values using `/Value` pointer

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_obj_to_mapkv($source_array, '/Name', '/Value', False)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "UserAgent",
      "Value": "Mozilla/5.0"
    },
    {
      "Name": "Request.Type",
      "Value": "OAuth2:Authorize"
    },
    {
      "Name": "Included Updated Properties",
      "Value": "RequiredResourceAccess"
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "UserAgent",
      "Value": "Mozilla/5.0"
    },
    {
      "Name": "Request.Type",
      "Value": "OAuth2:Authorize"
    },
    {
      "Name": "Included Updated Properties",
      "Value": "RequiredResourceAccess"
    }
  ],
  "target_field": {
    "useragent": "Mozilla/5.0",
    "request_type": "OAuth2:Authorize",
    "included_updated_properties": "RequiredResourceAccess"
  }
}
```

*The operation was successful*

### Example 2

Keeps keys verbatim when `skipSerializer` is true

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_obj_to_mapkv($source_array, '/Name', '/Value', True)
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "UserAgent",
      "Value": "Mozilla/5.0"
    },
    {
      "Name": "KeepMeSignedIn",
      "Value": true
    },
    {
      "Name": "OptionalField",
      "Value": null
    },
    {
      "Name": "Roles",
      "Value": [
        "admin",
        "user"
      ]
    },
    {
      "Name": "Meta",
      "Value": {
        "os": "linux",
        "arch": "x64"
      }
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "UserAgent",
      "Value": "Mozilla/5.0"
    },
    {
      "Name": "KeepMeSignedIn",
      "Value": true
    },
    {
      "Name": "OptionalField",
      "Value": null
    },
    {
      "Name": "Roles",
      "Value": [
        "admin",
        "user"
      ]
    },
    {
      "Name": "Meta",
      "Value": {
        "os": "linux",
        "arch": "x64"
      }
    }
  ],
  "target_field": {
    "UserAgent": "Mozilla/5.0",
    "KeepMeSignedIn": true,
    "OptionalField": null,
    "Roles": [
      "admin",
      "user"
    ],
    "Meta": {
      "os": "linux",
      "arch": "x64"
    }
  }
}
```

*The operation was successful*

### Example 3

Fails when array does not exist in the context

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_obj_to_mapkv($source_array, '/Name', '/Value', False)
```

#### Input Event

```json
{
  "source_array": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*



---
# as

## Signature

```

field: as(ip, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Performs a query to the maxmind GeoLite2-ASN database (provided by Maxmind Inc.   https://www.maxmind.com ).
In case of errors the target field will not be modified.
In case of success it will return an object with the following fields:
  - number: mapping of the 'autonomous_system_number' field of the mmdb entry.
  - organization.name: mapping of the 'autonomous_system_organization' field of the mmdb entry.


## Keywords

- `max_min_db` 

## Examples

### Example 1

Get as of public ip

#### Asset

```yaml
normalize:
  - map:
      - target_field: as($ip)
```

#### Input Event

```json
{
  "ip": "1.2.3.4"
}
```

#### Outcome Event

```json
{
  "ip": "1.2.3.4",
  "target_field": {
    "number": 1234,
    "organization": {
      "name": " Wazuh Organization"
    }
  }
}
```

*The operation was successful*



---
# concat

## Signature

```

field: concat(operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operand_left | string, number, object | value or reference | Any object |
| operand_right | string, number, object | value or reference | Any object |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

The function `concat` concatenates various types of data including strings, numbers, and objects.
The function receives two or more operands and concatenates them in the order they are provided.
The result of the concatenation is stored in the field `field`.


## Keywords

- `different_types` 

## Examples

### Example 1

Concatenate a string with another empty one

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat('yes', ' ', 'no', 'hello', 'yes')
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": "hello noyesyes"
}
```

*The operation was successful*

### Example 2

Trying to concatenate a value with a reference does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat($operand_left, 'hello')
```

#### Input Event

```json
{
  "operand_left": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 3

Concat object, number and string

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat($operand_left, 2, $operand_right_1)
```

#### Input Event

```json
{
  "operand_left": {
    "key": "value"
  },
  "operand_right_1": "hello"
}
```

#### Outcome Event

```json
{
  "operand_left": {
    "key": "value"
  },
  "operand_right_1": "hello",
  "target_field": "{\"key\":\"value\"}2hello"
}
```

*The operation was successful*



---
# concat_any

## Signature

```

field: concat_any(operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operand_left | string, number, object | value or reference | Any object |
| operand_right | string, number, object | value or reference | Any object |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

The function `concat` concatenates various types of data including strings, numbers, and objects.
The function receives two or more operands and concatenates them in the order they are provided.
The result of the concatenation is stored in the field `field`.


## Keywords

- `different_types` 

## Examples

### Example 1

Concatenate a string with another empty one

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any('hello', ' ', 'yes')
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": "hello yes"
}
```

*The operation was successful*

### Example 2

Try to concatenate an existing reference with a non-existing reference

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any($operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": null,
  "operand_right": "hello"
}
```

#### Outcome Event

```json
{
  "operand_left": null,
  "operand_right": "hello",
  "target_field": "hello"
}
```

*The operation was successful*

### Example 3

Trying to concatenate a value with a reference does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any($operand_left, 'hello')
```

#### Input Event

```json
{
  "operand_left": null
}
```

#### Outcome Event

```json
{
  "operand_left": null,
  "target_field": "hello"
}
```

*The operation was successful*



---
# date_from_epoch

## Signature

```

field: date_from_epoch(epoch)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| epoch | number | reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Date from epoch will convert the input value, can be a reference or a value representing the epoch time to a human readable date time.
Transforms UNIX epoch time to a human readable date time in the format of 'YYYY-MM-DDTHH:MM:SSZ'.


## Keywords

- `undefined` 

## Examples

### Example 1

Get date using initial epoch

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_from_epoch($epoch)
```

#### Input Event

```json
{
  "epoch": 0
}
```

#### Outcome Event

```json
{
  "epoch": 0,
  "target_field": "1970-01-01T00:00:00.000000Z"
}
```

*The operation was successful*

### Example 2

Get date using any epoch

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_from_epoch($epoch)
```

#### Input Event

```json
{
  "epoch": 1715958658
}
```

#### Outcome Event

```json
{
  "epoch": 1715958658,
  "target_field": "2024-05-17T15:10:58.000000Z"
}
```

*The operation was successful*



---
# date_to_epoch

## Signature

```

field: date_to_epoch(date, format)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| date | string | reference | Any string |
| format | string | value | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| double |


## Description

Converts a date/time string to its UNIX epoch (seconds since 1970-01-01T00:00:00Z), returned as a double.
Parsing is strict and driven entirely by a format:
  - If a second argument `format` is provided (string literal), it is used verbatim by the parser.
  - If `format` is omitted, the default format "%Y-%m-%dT%H:%M:%SZ" (ISO 8601, UTC with trailing 'Z') is used.
To support other ISO-8601 variants (offsets, basic format, space instead of 'T', etc.), pass the appropriate format.


## Keywords

- `date` 

- `time` 

- `epoch` 

- `timestamp` 

## Examples

### Example 1

Default format → epoch start

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "1970-01-01T00:00:00Z"
}
```

#### Outcome Event

```json
{
  "date": "1970-01-01T00:00:00Z",
  "target_field": 0.0
}
```

*The operation was successful*

### Example 2

Default format → UTC with trailing Z

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58Z",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 3

Default format → fractional seconds preserved

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-09-24T23:03:00.597629Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-09-24T23:03:00.597629Z",
  "target_field": 1727218980.597629
}
```

*The operation was successful*

### Example 4

Default format → negative epoch

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "1969-12-31T23:59:59Z"
}
```

#### Outcome Event

```json
{
  "date": "1969-12-31T23:59:59Z",
  "target_field": -1.0
}
```

*The operation was successful*

### Example 5

Default format requires 'Z' → fails without timezone

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58"
}
```

*The operation was performed with errors*

### Example 6

Offset with colon (−03:00)

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%FT%T%Ez')
```

#### Input Event

```json
{
  "date": "2024-05-17T12:10:58-03:00"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T12:10:58-03:00",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 7

Offset without colon (−0300)

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%FT%T%z')
```

#### Input Event

```json
{
  "date": "2024-05-17T12:10:58-0300"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T12:10:58-0300",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 8

Space instead of 'T' + offset

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%F %T%Ez')
```

#### Input Event

```json
{
  "date": "2024-05-17 15:10:58+00:00"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17 15:10:58+00:00",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 9

Basic (no-extended) format with 'Z'

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y%m%dT%H%M%SZ')
```

#### Input Event

```json
{
  "date": "20240517T151058Z"
}
```

#### Outcome Event

```json
{
  "date": "20240517T151058Z",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 10

Basic format with offset (−0300)

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y%m%dT%H%M%S%z')
```

#### Input Event

```json
{
  "date": "20240517T121058-0300"
}
```

#### Outcome Event

```json
{
  "date": "20240517T121058-0300",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 11

No timezone in input; format without timezone

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%FT%T')
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 12

IANA zone America/Argentina/Buenos_Aires, UTC−03) → 2024-05-17T15:10:58Z

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%F %T %Z')
```

#### Input Event

```json
{
  "date": "2024-05-17 12:10:58 America/Argentina/Buenos_Aires"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17 12:10:58 America/Argentina/Buenos_Aires",
  "target_field": 1715958658.0
}
```

*The operation was successful*

### Example 13

IANA zone (Europe/Berlin, CEST UTC+02) → 2024-07-01T08:00:00Z

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%F %T %Z')
```

#### Input Event

```json
{
  "date": "2024-07-01 10:00:00 Europe/Berlin"
}
```

#### Outcome Event

```json
{
  "date": "2024-07-01 10:00:00 Europe/Berlin",
  "target_field": 1719820800.0
}
```

*The operation was successful*

### Example 14

Unknown IANA zone → tzdb lookup fails

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%F %T %Z')
```

#### Input Event

```json
{
  "date": "2024-05-17 15:10:58 Mars/Phobos"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17 15:10:58 Mars/Phobos"
}
```

*The operation was performed with errors*

### Example 15

DST spring-forward gap (nonexistent local time in New York)

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%F %T %Z')
```

#### Input Event

```json
{
  "date": "2024-03-10 02:30:00 America/New_York"
}
```

#### Outcome Event

```json
{
  "date": "2024-03-10 02:30:00 America/New_York"
}
```

*The operation was performed with errors*

### Example 16

Reject non-string input for 'date'

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": 123456789
}
```

#### Outcome Event

```json
{
  "date": 123456789
}
```

*The operation was performed with errors*

### Example 17

Reject null input for 'date'

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 18

Invalid format format with unknown specifier

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%invalid_format')
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 19

Empty format format

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '')
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 20

Null format format

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, null)
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 21

Non-string format format

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, 123)
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 22

Date string doesn't match format (has time, format expects only date)

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%d')
```

#### Input Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 23

format expects time, date string has only date

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-05-17"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-17"
}
```

*The operation was performed with errors*

### Example 24

Completely malformed date string

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "not-a-date"
}
```

#### Outcome Event

```json
{
  "date": "not-a-date"
}
```

*The operation was performed with errors*

### Example 25

Empty date string

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": ""
}
```

#### Outcome Event

```json
{
  "date": ""
}
```

*The operation was performed with errors*

### Example 26

Invalid date - February 30th doesn't exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-02-30T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-02-30T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 27

Invalid date - 13th month doesn't exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-13-17T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-13-17T15:10:58Z"
}
```

*The operation was performed with errors*

### Example 28

Invalid date - 32nd day doesn't exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-05-32T15:10:58Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-05-32T15:10:58Z"
}
```

*The operation was performed with errors*



---
# decode_base16

## Signature

```

field: decode_base16(hex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| hex | string | reference | Any hexadecimal |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

The operation transforms a string of hexa digits into an ASCII string. The result of the operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.


## Keywords

- `undefined` 

## Examples

### Example 1

Convert base 16 to decimal

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_base16($hex)
```

#### Input Event

```json
{
  "hex": "48656C6C6F20776F726C6421"
}
```

#### Outcome Event

```json
{
  "hex": "48656C6C6F20776F726C6421",
  "target_field": "Hello world!"
}
```

*The operation was successful*



---
# downcase

## Signature

```

field: downcase(upper_characters)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| upper_characters | string | value or reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

The operation converts any uppercase character to an lowercase character.
The result of the lowercase (+downcase) operation is mapped to “field”.
If the field field already exists, then it will be replaced. In case of errors “field” will not be modified.


## Keywords

- `string` 

## Examples

### Example 1

Change string to downcase

#### Asset

```yaml
normalize:
  - map:
      - target_field: downcase('ABCD')
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": "abcd"
}
```

*The operation was successful*

### Example 2

Change string to downcase

#### Asset

```yaml
normalize:
  - map:
      - target_field: downcase($upper_characters)
```

#### Input Event

```json
{
  "upper_characters": "AbcD"
}
```

#### Outcome Event

```json
{
  "upper_characters": "AbcD",
  "target_field": "abcd"
}
```

*The operation was successful*

### Example 3

Change string to downcase

#### Asset

```yaml
normalize:
  - map:
      - target_field: downcase('aBcDECF')
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": "abcdecf"
}
```

*The operation was successful*



---
# float_calculate

## Signature

```

field: float_calculate(operator, operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operator | string | value | mul, div, sub, sum |
| operand_left | number | value or reference |
| operand_right | number | value or reference |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| number |


## Description

The function `float_calculate` performs basic arithmetic operations on floats and integers.
The function receives an operator and two or more operands.
The function applies the operator to the first two operands and then applies the result to the next operand.
The result of the operation is stored in the field `field`.
The function supports the following operators: `sum` (addition), `sub` (subtraction), `mul` (multiplication), and `div` (division).


## Keywords

- `math` 

## Notes

- Division by zero is not allowed (the function will fail).

- The limit for a float is 3.402823466e+38

## Examples

### Example 1

Sum that produces overflow. The limit for a double is exceeded.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sum', 1.7976931348623157e+308, 1.7976931348623157e+308)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 2

Sum that produces overflow. The limit for a double is exceeded.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sum', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -1.7976931348623157e+308,
  "operand_right": -1.7976931348623157e+308
}
```

#### Outcome Event

```json
{
  "operand_left": -1.7976931348623157e+308,
  "operand_right": -1.7976931348623157e+308
}
```

*The operation was performed with errors*

### Example 3

Subtraction that produces overflow. The limit for a double is exceeded.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sub', 1.7976931348623157e+308, -1.7976931348623157e+308)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 4

Subtraction that produces overflow. The limit for a double is exceeded.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sub', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -1.7976931348623157e+308,
  "operand_right": 1.7976931348623157e+308
}
```

#### Outcome Event

```json
{
  "operand_left": -1.7976931348623157e+308,
  "operand_right": 1.7976931348623157e+308
}
```

*The operation was performed with errors*

### Example 5

Multiplication that produces overflow. The limit for a double is exceeded.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('mul', 1.7976931348623157e+308, 2.0)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 6

Multiplication that produces overflow. The limit for a double is exceeded.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('mul', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 1.7976931348623157e+308,
  "operand_right": -2.0
}
```

#### Outcome Event

```json
{
  "operand_left": 1.7976931348623157e+308,
  "operand_right": -2.0
}
```

*The operation was performed with errors*

### Example 7

Any division with a numerator equal to zero results in zero as long as the denominator is different from 0.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('div', 0.0, 8)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": 0.0
}
```

*The operation was successful*

### Example 8

Any division with a denominator equal to zero is an indeterminate operation.

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('div', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 5,
  "operand_right": 0.0
}
```

#### Outcome Event

```json
{
  "operand_left": 5,
  "operand_right": 0.0
}
```

*The operation was performed with errors*

### Example 9

Sum float with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sum', -1.53, 1)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": -0.53
}
```

*The operation was successful*

### Example 10

Sum integer with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sum', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 1,
  "operand_right": 1
}
```

#### Outcome Event

```json
{
  "operand_left": 1,
  "operand_right": 1,
  "target_field": 2.0
}
```

*The operation was successful*

### Example 11

Sum float with float

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sum', 2.676, 3.756)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": 6.432
}
```

*The operation was successful*

### Example 12

Sub float with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sub', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 1.53,
  "operand_right": -1
}
```

#### Outcome Event

```json
{
  "operand_left": 1.53,
  "operand_right": -1,
  "target_field": 2.5300000000000002
}
```

*The operation was successful*

### Example 13

Sub integer with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sub', -1, -1)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": 0.0
}
```

*The operation was successful*

### Example 14

Sub float with float

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('sub', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -2.676,
  "operand_right": -3.756
}
```

#### Outcome Event

```json
{
  "operand_left": -2.676,
  "operand_right": -3.756,
  "target_field": 1.0799999999999996
}
```

*The operation was successful*

### Example 15

Mul float with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('mul', 12.53, -3)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": -37.589999999999996
}
```

*The operation was successful*

### Example 16

Mul integer with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('mul', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -45,
  "operand_right": 2
}
```

#### Outcome Event

```json
{
  "operand_left": -45,
  "operand_right": 2,
  "target_field": -90
}
```

*The operation was successful*

### Example 17

Mul float with float

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('mul', -2.676, -3.756)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": 10.051056
}
```

*The operation was successful*

### Example 18

Div float with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('div', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 12.53,
  "operand_right": -3
}
```

#### Outcome Event

```json
{
  "operand_left": 12.53,
  "operand_right": -3,
  "target_field": -4.176666666666667
}
```

*The operation was successful*

### Example 19

Div integer with integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('div', -45, 2)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": -22.5
}
```

*The operation was successful*

### Example 20

Div float with float

#### Asset

```yaml
normalize:
  - map:
      - target_field: float_calculate('div', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -2.676,
  "operand_right": -3.756
}
```

#### Outcome Event

```json
{
  "operand_left": -2.676,
  "operand_right": -3.756,
  "target_field": 0.7124600638977636
}
```

*The operation was successful*



---
# geoip

## Signature

```

field: geoip(ip, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Performs a query to the maxmind GeoLite2-City database (provided by Maxmind Inc.   https://www.maxmind.com ).
In case of errors the target field will not be modified.
In case of success it will return an object with the following fields:
  - city_name: mapping of the 'city.names.en' field of the mmdb entry.
  - continent_code: mapping of the 'continent.code' field of the mmdb entry.
  - continent_name: mapping of the 'continent.names.en' field of the mmdb entry.
  - country_iso_code: mapping of the 'country.iso_code' field of the mmdb entry.
  - country_name: mapping of the 'country.names.en' field of the mmdb entry.
  - postal_code: mapping of the 'postal.code' field of the mmdb entry.
  - location.lat: mapping of the 'location.latitude' field of the mmdb entry.
  - location.lon: mapping of the 'location.longitude' field of the mmdb entry.
  - timezone: mapping of the 'location.time_zone' field of the mmdb entry.
  - region_iso_code: mapping of the 'subdivisions.0.iso_code' field of the mmdb entry.
  - region_name: mapping of the 'subdivisions.0.names.en' field of the mmdb entry.


## Keywords

- `max_min_db` 

## Examples

### Example 1

Get geo of public ip

#### Asset

```yaml
normalize:
  - map:
      - target_field: geoip($ip)
```

#### Input Event

```json
{
  "ip": "1.2.3.4"
}
```

#### Outcome Event

```json
{
  "ip": "1.2.3.4",
  "target_field": {
    "city_name": "Wazuh city",
    "timezone": "Wazuh/Timezone",
    "country_name": "Wazuh Country",
    "continent_code": "WC",
    "continent_name": "Wazuh Continent",
    "country_iso_code": "WCtry",
    "postal_code": "7777",
    "location": {
      "lon": 88.4293,
      "lat": 41.7776
    }
  }
}
```

*The operation was successful*



---
# get_date

## Signature

```

field: get_date()
```

## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Get the current date in the format "%Y-%m-%dT%H:%M:%SZ". The date is generated in UTC time zone.


## Keywords

- `time` 

---
# hex_to_number

## Signature

```

field: hex_to_number(hex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| hex | string | reference | Any hexadecimal |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

The peration transforms a number in hexadecimal format (0x...) to a base 10 number.
The result of the operation is mapped to “field”. If the “field” already exists, then it will be replaced.
In case of errors “field” will not be modified.


## Keywords

- `undefined` 

## Examples

### Example 1

Convert hexadecimal to decimal

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_number($hex)
```

#### Input Event

```json
{
  "hex": "2A"
}
```

#### Outcome Event

```json
{
  "hex": "2A",
  "target_field": 42
}
```

*The operation was successful*

### Example 2

Converts hexadecimal to int64

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_number($hex)
```

#### Input Event

```json
{
  "hex": "0xBC763516"
}
```

#### Outcome Event

```json
{
  "hex": "0xBC763516",
  "target_field": 3161863446
}
```

*The operation was successful*



---
# iana_protocol_name_to_number

## Signature

```

field: iana_protocol_name_to_number(protocol_name)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| protocol_name | string | reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Resolves an IANA IP protocol keyword to its numeric code, returned as a string (e.g., "6").
Normalization rules:
  - Lowercased.
  - Spaces/underscores converted to '-'.
  - Aliases recognized:
      * "icmpv6" → "ipv6-icmp"
      * "udp-lite" / "udp_lite" → "udplite"
      * "ip-in-ip" → "ipip"
The helper rejects generic/unspecific categories and returns failure.


## Keywords

- `iana` 

- `protocol` 

## Examples

### Example 1

canonical keyword

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "tcp"
}
```

#### Outcome Event

```json
{
  "protocol_name": "tcp",
  "target_field": "6"
}
```

*The operation was successful*

### Example 2

case-insensitive

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "UDP"
}
```

#### Outcome Event

```json
{
  "protocol_name": "UDP",
  "target_field": "17"
}
```

*The operation was successful*

### Example 3

canonical hyphenated form

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "ipv6-icmp"
}
```

#### Outcome Event

```json
{
  "protocol_name": "ipv6-icmp",
  "target_field": "58"
}
```

*The operation was successful*

### Example 4

underscore alias normalized → "udplite"

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "udp_lite"
}
```

#### Outcome Event

```json
{
  "protocol_name": "udp_lite",
  "target_field": "136"
}
```

*The operation was successful*

### Example 5

alias normalized → "ipip"

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "ip-in-ip"
}
```

#### Outcome Event

```json
{
  "protocol_name": "ip-in-ip",
  "target_field": "94"
}
```

*The operation was successful*

### Example 6

alias normalized → "ipv6-icmp"

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "ICMPv6"
}
```

#### Outcome Event

```json
{
  "protocol_name": "ICMPv6",
  "target_field": "58"
}
```

*The operation was successful*

### Example 7

reject generic/unspecific categories

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "any-host-internal-protocol"
}
```

#### Outcome Event

```json
{
  "protocol_name": "any-host-internal-protocol"
}
```

*The operation was performed with errors*

### Example 8

application-layer name → not an IANA IP protocol keyword

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "smtp"
}
```

#### Outcome Event

```json
{
  "protocol_name": "smtp"
}
```

*The operation was performed with errors*

### Example 9

empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": ""
}
```

#### Outcome Event

```json
{
  "protocol_name": ""
}
```

*The operation was performed with errors*

### Example 10

non-string input rejected (must be a reference to string)

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name_to_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": 123
}
```

#### Outcome Event

```json
{
  "protocol_name": 123
}
```

*The operation was performed with errors*



---
# iana_protocol_number_to_name

## Signature

```

field: iana_protocol_number_to_name(protocol_code)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| protocol_code | string, number | reference | Any object |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Resolves an IANA IP protocol numeric code (0..255) to its canonical keyword.
The helper accepts either a number or a base-10 numeric string (same argument, by reference).
The helper returns failure for experimental, reserved, unassigned codes and for generic/unspecific categories.


## Keywords

- `iana` 

- `protocol` 

## Examples

### Example 1

6 → "tcp"

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 6
}
```

#### Outcome Event

```json
{
  "protocol_code": 6,
  "target_field": "tcp"
}
```

*The operation was successful*

### Example 2

58 → "ipv6-icmp"

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 58
}
```

#### Outcome Event

```json
{
  "protocol_code": 58,
  "target_field": "ipv6-icmp"
}
```

*The operation was successful*

### Example 3

147 → "bit-emu"

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 147
}
```

#### Outcome Event

```json
{
  "protocol_code": 147,
  "target_field": "bit-emu"
}
```

*The operation was successful*

### Example 4

string numeric accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "6"
}
```

#### Outcome Event

```json
{
  "protocol_code": "6",
  "target_field": "tcp"
}
```

*The operation was successful*

### Example 5

string numeric accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "58"
}
```

#### Outcome Event

```json
{
  "protocol_code": "58",
  "target_field": "ipv6-icmp"
}
```

*The operation was successful*

### Example 6

string numeric accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "147"
}
```

#### Outcome Event

```json
{
  "protocol_code": "147",
  "target_field": "bit-emu"
}
```

*The operation was successful*

### Example 7

rejects non-integer numeric string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "6.0"
}
```

#### Outcome Event

```json
{
  "protocol_code": "6.0"
}
```

*The operation was performed with errors*

### Example 8

out of range (negative)

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "-1"
}
```

#### Outcome Event

```json
{
  "protocol_code": "-1"
}
```

*The operation was performed with errors*

### Example 9

out of range (>255)

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "256"
}
```

#### Outcome Event

```json
{
  "protocol_code": "256"
}
```

*The operation was performed with errors*

### Example 10

non-numeric string rejected

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": "abc"
}
```

#### Outcome Event

```json
{
  "protocol_code": "abc"
}
```

*The operation was performed with errors*

### Example 11

reject generic/unspecific category

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 61
}
```

#### Outcome Event

```json
{
  "protocol_code": 61
}
```

*The operation was performed with errors*

### Example 12

reject generic/unspecific category

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 63
}
```

#### Outcome Event

```json
{
  "protocol_code": 63
}
```

*The operation was performed with errors*

### Example 13

reject generic/unspecific category

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 68
}
```

#### Outcome Event

```json
{
  "protocol_code": 68
}
```

*The operation was performed with errors*

### Example 14

reject generic/unspecific category

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 99
}
```

#### Outcome Event

```json
{
  "protocol_code": 99
}
```

*The operation was performed with errors*

### Example 15

reject generic/unspecific category

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 114
}
```

#### Outcome Event

```json
{
  "protocol_code": 114
}
```

*The operation was performed with errors*

### Example 16

unassigned protocol code

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 148
}
```

#### Outcome Event

```json
{
  "protocol_code": 148
}
```

*The operation was performed with errors*

### Example 17

experimental protocol code

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 253
}
```

#### Outcome Event

```json
{
  "protocol_code": 253
}
```

*The operation was performed with errors*

### Example 18

reserved protocol code

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 255
}
```

#### Outcome Event

```json
{
  "protocol_code": 255
}
```

*The operation was performed with errors*

### Example 19

out of range (negative)

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": -1
}
```

#### Outcome Event

```json
{
  "protocol_code": -1
}
```

*The operation was performed with errors*

### Example 20

out of range (>255)

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": 256
}
```

#### Outcome Event

```json
{
  "protocol_code": 256
}
```

*The operation was performed with errors*

### Example 21

null rejected

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number_to_name($protocol_code)
```

#### Input Event

```json
{
  "protocol_code": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*



---
# int_calculate

## Signature

```

field: int_calculate(operator, operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operator | string | value | mul, div, sub, sum |
| operand_left | number | value or reference | Integers between `-2^63` and `2^63-1` |
| operand_right | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

The function `int_calculate` performs basic arithmetic operations on integers.
The function receives an operator and two or more operands.
The function applies the operator to the first two operands and then applies the result to the next operand.
The result of the operation is stored in the field `field`.
The function supports the following operators: `sum` (addition), `sub` (subtraction), `mul` (multiplication), and `div` (division).


## Keywords

- `math` 

## Notes

- Division by zero is not allowed (the function will fail).

- The limit for a 64-bit integer is 2^63-1 and -2^63.

## Examples

### Example 1

Sum that produces overflow. the limit for a 64-bit integer is exceeded

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('sum', 1, 9223372036854775807)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 2

Sum that produces overflow. the limit for a 64-bit integer is exceeded

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('sum', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -1,
  "operand_right": -9223372036854775808
}
```

#### Outcome Event

```json
{
  "operand_left": -1,
  "operand_right": -9223372036854775808
}
```

*The operation was performed with errors*

### Example 3

Sub that produces overflow. the limit for a 64-bit integer is exceeded

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('sub', 9223372036854775807, -1)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 4

Sub that produces overflow. the limit for a 64-bit integer is exceeded

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('sub', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -9223372036854775808,
  "operand_right": 1
}
```

#### Outcome Event

```json
{
  "operand_left": -9223372036854775808,
  "operand_right": 1
}
```

*The operation was performed with errors*

### Example 5

Mul that produces overflow. the limit for a 64-bit integer is exceeded

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('mul', 4611686018427387904, 2)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 6

Mul that produces overflow. the limit for a 64-bit integer is exceeded

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('mul', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 3074457345618258603,
  "operand_right": -3
}
```

#### Outcome Event

```json
{
  "operand_left": 3074457345618258603,
  "operand_right": -3
}
```

*The operation was performed with errors*

### Example 7

Any division with a numerator equal to zero results in zero as long as the denominator is different from 0.

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('div', 0, 8)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": 0
}
```

*The operation was successful*

### Example 8

Any division with a denominator equal to zero is an indeterminate operation.

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('div', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": 5,
  "operand_right": 0
}
```

#### Outcome Event

```json
{
  "operand_left": 5,
  "operand_right": 0
}
```

*The operation was performed with errors*



---
# ip_version

## Signature

```

field: ip_version(ip)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks the protocol version of an IP. If the version is IPv4 then it maps the IPv4 value to field.
If the version is IPv6 then it maps the IPv6 value to field.
If the field field already exists, then it will be replaced. In case of errors target field will not be modified.
  - IPv4: support address in dotted-decimal format, "ddd.ddd.ddd.ddd" where ddd is a decimal number of up to three digits in the range  0  to  255
  - IPv6: support RFC 2373 representation of addresses


## Keywords

- `ip` 

## Examples

### Example 1

Get the version type of an ip

#### Asset

```yaml
normalize:
  - map:
      - target_field: ip_version($ip)
```

#### Input Event

```json
{
  "ip": "111.111.1.11"
}
```

#### Outcome Event

```json
{
  "ip": "111.111.1.11",
  "target_field": "IPv4"
}
```

*The operation was successful*

### Example 2

Get the version type of an ip

#### Asset

```yaml
normalize:
  - map:
      - target_field: ip_version($ip)
```

#### Input Event

```json
{
  "ip": "3002:0bd6:0000:0000:0000:ee00:0033:6778"
}
```

#### Outcome Event

```json
{
  "ip": "3002:0bd6:0000:0000:0000:ee00:0033:6778",
  "target_field": "IPv6"
}
```

*The operation was successful*



---
# join

## Signature

```

field: join(array, separator)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| array | array | reference | Any string |
| separator | string | value | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

The operation concatenates the elements (strings) of the "array" and separates them with “separator”.
The result of the string concatenation (join) operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.


## Keywords

- `undefined` 

## Examples

### Example 1

Join a string using space like separator

#### Asset

```yaml
normalize:
  - map:
      - target_field: join($array, ' ')
```

#### Input Event

```json
{
  "array": [
    "Hi Wazuh!",
    "It is",
    "the",
    "year",
    "2024"
  ]
}
```

#### Outcome Event

```json
{
  "array": [
    "Hi Wazuh!",
    "It is",
    "the",
    "year",
    "2024"
  ],
  "target_field": "Hi Wazuh! It is the year 2024"
}
```

*The operation was successful*

### Example 2

Join a string using a string like separator

#### Asset

```yaml
normalize:
  - map:
      - target_field: join($array, 'separator')
```

#### Input Event

```json
{
  "array": [
    "Hi Wazuh!",
    "It is",
    "the",
    "year",
    "2024"
  ]
}
```

#### Outcome Event

```json
{
  "array": [
    "Hi Wazuh!",
    "It is",
    "the",
    "year",
    "2024"
  ],
  "target_field": "Hi Wazuh!separatorIt isseparatortheseparatoryearseparator2024"
}
```

*The operation was successful*



---
# network_community_id

## Signature

```

field: network_community_id(source_ip, destination_ip, source_port, destination_port, protocol)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source_ip | string | reference | Any IP |
| destination_ip | string | reference | Any IP |
| source_port | number | reference | Integers between `-2^63` and `2^63-1` |
| destination_port | number | reference | Integers between `-2^63` and `2^63-1` |
| protocol | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Produces the Community ID v1 (format `1:<base64>`) for a network flow using source/destination IPs,
transport ports (or ICMP type/code), and the IANA protocol number. The seed is fixed to 0.
Port requirements by protocol:
  - TCP/UDP/SCTP: ports are mandatory and must be in 0..65535.
  - ICMP/ICMPv6: type/code are optional; if provided they must be in 0..255; otherwise 0/0 is used.
  - Other protocols: ports are optional (0..65535).
Both addresses must belong to the same IP family (IPv4 or IPv6).
The helper validates references, types, families, and ranges; on failure the target is left untouched.


## Keywords

- `network` 

- `community-id` 

## Examples

### Example 1

TCP/IPv4 flow (protocol literal), seed=0

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": 12345,
  "destination_port": 80
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": 12345,
  "destination_port": 80,
  "target_field": "1:JHvDxB6S6/K68OntUBf4DJZYvkM="
}
```

*The operation was successful*

### Example 2

UDP/IPv4 flow (protocol literal), seed=0

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
```

#### Input Event

```json
{
  "source_ip": "10.1.1.1",
  "destination_ip": "10.1.1.2",
  "source_port": 5353,
  "destination_port": 53,
  "protocol": 17
}
```

#### Outcome Event

```json
{
  "source_ip": "10.1.1.1",
  "destination_ip": "10.1.1.2",
  "source_port": 5353,
  "destination_port": 53,
  "protocol": 17,
  "target_field": "1:8JTDncPomK8OiyinJXhpO10W6EY="
}
```

*The operation was successful*

### Example 3

IPv6 encapsulation flow (no ports), seed=0

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, 41)
```

#### Input Event

```json
{
  "source_ip": "2001:db8::1",
  "destination_ip": "2001:db8::2",
  "source_port": 0,
  "destination_port": 0
}
```

#### Outcome Event

```json
{
  "source_ip": "2001:db8::1",
  "destination_ip": "2001:db8::2",
  "source_port": 0,
  "destination_port": 0,
  "target_field": "1:CXfAfp/8zYUwm/5DkEbJvPdJtcU="
}
```

*The operation was successful*

### Example 4

ICMP echo request (type/code mapped to ports), seed=0

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
```

#### Input Event

```json
{
  "source_ip": "192.0.2.1",
  "destination_ip": "198.51.100.2",
  "source_port": 8,
  "destination_port": 0,
  "protocol": 1
}
```

#### Outcome Event

```json
{
  "source_ip": "192.0.2.1",
  "destination_ip": "198.51.100.2",
  "source_port": 8,
  "destination_port": 0,
  "protocol": 1,
  "target_field": "1:zFLKq9oekfjLhmre/zOf0XYYjVE="
}
```

*The operation was successful*

### Example 5

Reject invalid source IP literal

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "not-an-ip",
  "destination_ip": "10.0.0.5",
  "source_port": 12345,
  "destination_port": 80
}
```

#### Outcome Event

```json
{
  "source_ip": "not-an-ip",
  "destination_ip": "10.0.0.5",
  "source_port": 12345,
  "destination_port": 80
}
```

*The operation was performed with errors*

### Example 6

Reject out-of-range protocol number (>255)

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": 12345,
  "destination_port": 80,
  "protocol": 300
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": 12345,
  "destination_port": 80,
  "protocol": 300
}
```

*The operation was performed with errors*

### Example 7

Reject transport port above 65535

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": 70000,
  "destination_port": 80
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": 70000,
  "destination_port": 80
}
```

*The operation was performed with errors*

### Example 8

Reject endpoints from mixed IP families

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "2001:db8::1",
  "source_port": 12345,
  "destination_port": 80,
  "protocol": 6
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "2001:db8::1",
  "source_port": 12345,
  "destination_port": 80,
  "protocol": 6
}
```

*The operation was performed with errors*

### Example 9

TCP puerto 0 inválido (dest)

#### Asset

```yaml
normalize:
  - map:
      - target_field: network_community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "222.222.2.22",
  "destination_ip": "222.222.2.22",
  "source_port": 8,
  "destination_port": 0
}
```

#### Outcome Event

```json
{
  "source_ip": "222.222.2.22",
  "destination_ip": "222.222.2.22",
  "source_port": 8,
  "destination_port": 0
}
```

*The operation was performed with errors*



---
# regex_extract

## Signature

```

field: regex_extract(fieldToMatch, regex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| fieldToMatch | string | reference | Any string |
| regex | string | value | Any regex |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Match and capture the regex expression against the indicated "fieldToMatch", saving the captured group in field.
Save in field the captured group if the regex expression matches, otherwise if "fieldToMatch"
is not found or is not of type string, or if the regex did not match, nothing is performed.
If the operation executes successfully the field is overridden, if it does not exist, it is created.
Keep in mind that we need to escape reserved Yaml characters depending on the string input mode of Yaml.
RE2 syntax: https://github.com/google/re2/wiki/Syntax
This helper function is used in the map stage


## Keywords

- `undefined` 

## Examples

### Example 1

Match regular expression

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($fieldToMatch, '^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "fieldToMatch": "bye pcre2"
}
```

#### Outcome Event

```json
{
  "fieldToMatch": "bye pcre2",
  "target_field": "bye pcre2"
}
```

*The operation was successful*

### Example 2

Don't match regular expression

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($fieldToMatch, '^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "fieldToMatch": "ye pcre2"
}
```

#### Outcome Event

```json
{
  "fieldToMatch": "ye pcre2"
}
```

*The operation was performed with errors*



---
# sha1

## Signature

```

field: sha1(any_string)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_string | string | reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Calculates the hash SHA-1 of a string. The result of the hash (sha1) operation is rendered as a hexadecimal number
which is 40 digits long and is mapped to “field”. If the “field” already exists, then it will be replaced.
In case of errors “field” will not be modified.
This helper function is typically used in the map stage


## Keywords

- `undefined` 

## Examples

### Example 1

Get hash of string

#### Asset

```yaml
normalize:
  - map:
      - target_field: sha1($any_string)
```

#### Input Event

```json
{
  "any_string": "Hi Wazuh!"
}
```

#### Outcome Event

```json
{
  "any_string": "Hi Wazuh!",
  "target_field": "c4e30dbc1b87ba8f29b24a74dba2f006be2a709e"
}
```

*The operation was successful*



---
# syslog_extract_facility

## Signature

```

field: syslog_extract_facility(priority)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| priority | number | reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Derives the syslog facility `code` and `name` from a priority value following RFC 5424.
Valid priorities range from 0 to 191 (facility*8 + severity).
The helper returns an object so it can be stored under `log.syslog.facility`.


## Keywords

- `syslog` 

- `facility name` 

- `facility code` 

## Examples

### Example 1

Facility derived from priority 165 (local4).

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_extract_facility($priority)
```

#### Input Event

```json
{
  "priority": 165
}
```

#### Outcome Event

```json
{
  "priority": 165,
  "target_field": {
    "code": 20,
    "name": "local4"
  }
}
```

*The operation was successful*

### Example 2

Reject priority above 191.

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_extract_facility($priority)
```

#### Input Event

```json
{
  "priority": 255
}
```

#### Outcome Event

```json
{
  "priority": 255
}
```

*The operation was performed with errors*

### Example 3

Reject negative priority values.

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_extract_facility($priority)
```

#### Input Event

```json
{
  "priority": -1
}
```

#### Outcome Event

```json
{
  "priority": -1
}
```

*The operation was performed with errors*



---
# syslog_extract_severity

## Signature

```

field: syslog_extract_severity(priority)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| priority | number | reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Derives the syslog severity `code` and `name` from a priority value following RFC 5424.
Valid priorities range from 0 to 191 (facility*8 + severity).
The helper returns an object so it can be stored under `log.syslog.severity`.


## Keywords

- `syslog` 

- `severity name` 

- `severity code` 

## Examples

### Example 1

Severity derived from priority 165 (Notice level).

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_extract_severity($priority)
```

#### Input Event

```json
{
  "priority": 165
}
```

#### Outcome Event

```json
{
  "priority": 165,
  "target_field": {
    "code": 5,
    "name": "notice"
  }
}
```

*The operation was successful*

### Example 2

Reject priority above 191.

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_extract_severity($priority)
```

#### Input Event

```json
{
  "priority": 255
}
```

#### Outcome Event

```json
{
  "priority": 255
}
```

*The operation was performed with errors*

### Example 3

Reject negative priority values.

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_extract_severity($priority)
```

#### Input Event

```json
{
  "priority": -1
}
```

#### Outcome Event

```json
{
  "priority": -1
}
```

*The operation was performed with errors*



---
# system_epoch

## Signature

```

field: system_epoch()
```

## Outputs

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Get unix epoch time in seconds from system clock. The result operation is mapped to “field”.
If the “field” already exists, then it will be replaced.


## Keywords

- `time` 

---
# to_bool

## Signature

```

field: to_bool(number_to_convert)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| number_to_convert | number | reference |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| boolean |


## Description

Converts a numeric reference to boolean.
Rule: non-zero → true, zero → false.
In case of errors “target_field” will not be modified.
This helper function is typically used in the map stage.


## Keywords

- `boolean` 

- `number` 

## Examples

### Example 1

Converts integer 1 to true.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": 1
}
```

#### Outcome Event

```json
{
  "number_to_convert": 1,
  "target_field": true
}
```

*The operation was successful*

### Example 2

Converts float 1.0 to true.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": 1.0
}
```

#### Outcome Event

```json
{
  "number_to_convert": 1.0,
  "target_field": true
}
```

*The operation was successful*

### Example 3

Converts integer 0 to false.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": 0
}
```

#### Outcome Event

```json
{
  "number_to_convert": 0,
  "target_field": false
}
```

*The operation was successful*

### Example 4

Converts float 0.0 to false.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": 0.0
}
```

#### Outcome Event

```json
{
  "number_to_convert": 0.0,
  "target_field": false
}
```

*The operation was successful*

### Example 5

Converts integer 2 to true (positive numbers are true).

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": 2
}
```

#### Outcome Event

```json
{
  "number_to_convert": 2,
  "target_field": true
}
```

*The operation was successful*

### Example 6

Converts integer -1 to true (non-positives are true).

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": -1
}
```

#### Outcome Event

```json
{
  "number_to_convert": -1,
  "target_field": true
}
```

*The operation was successful*

### Example 7

Converts float 0.5 to true (positive numbers are true).

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($number_to_convert)
```

#### Input Event

```json
{
  "number_to_convert": 0.5
}
```

#### Outcome Event

```json
{
  "number_to_convert": 0.5,
  "target_field": true
}
```

*The operation was successful*



---
# to_int

## Signature

```

field: to_int(number_to_transform, operation_mode)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| number_to_transform | number | reference |
| operation_mode | string | value | truncate, round |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Transforms a number to an integer by truncating the fractional part or rounding to the nearest integer based on the fractional value (e.g., 9.6 → 10, -4.7 → -5);
values with a fractional part ≥ 0.5 or ≤ -0.5 round away from zero, while others round toward zero.
The result of the to_int operation is mapped to “target_field”. In case of errors “target_field” will not be modified.
This helper function is typically used in the map stage


## Keywords

- `double` 

- `float` 

- `integer` 

## Examples

### Example 1

Truncates a negative float, ignoring the fractional part.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'truncate')
```

#### Input Event

```json
{
  "number_to_transform": -4.176666736602783
}
```

#### Outcome Event

```json
{
  "number_to_transform": -4.176666736602783,
  "target_field": -4
}
```

*The operation was successful*

### Example 2

Round a negative float.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'round')
```

#### Input Event

```json
{
  "number_to_transform": -4.716666736602783
}
```

#### Outcome Event

```json
{
  "number_to_transform": -4.716666736602783,
  "target_field": -5
}
```

*The operation was successful*

### Example 3

Rounds a negative float to the nearest integer.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'round')
```

#### Input Event

```json
{
  "number_to_transform": -4.176666736602783
}
```

#### Outcome Event

```json
{
  "number_to_transform": -4.176666736602783,
  "target_field": -4
}
```

*The operation was successful*

### Example 4

Truncates a positive float less than 1 to 0.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'truncate')
```

#### Input Event

```json
{
  "number_to_transform": 0.7124601006507874
}
```

#### Outcome Event

```json
{
  "number_to_transform": 0.7124601006507874,
  "target_field": 0
}
```

*The operation was successful*

### Example 5

Rounds a positive float greater than 0.5 to 1.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'round')
```

#### Input Event

```json
{
  "number_to_transform": 0.7124601006507874
}
```

#### Outcome Event

```json
{
  "number_to_transform": 0.7124601006507874,
  "target_field": 1
}
```

*The operation was successful*

### Example 6

Truncates a positive float with a fractional part of 0.5.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'truncate')
```

#### Input Event

```json
{
  "number_to_transform": 1.5
}
```

#### Outcome Event

```json
{
  "number_to_transform": 1.5,
  "target_field": 1
}
```

*The operation was successful*

### Example 7

Truncates a positive float just below 1.5 to 1.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'truncate')
```

#### Input Event

```json
{
  "number_to_transform": 1.49999999
}
```

#### Outcome Event

```json
{
  "number_to_transform": 1.49999999,
  "target_field": 1
}
```

*The operation was successful*

### Example 8

Rounds a positive float just below 1.5 to 2.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'round')
```

#### Input Event

```json
{
  "number_to_transform": 1.51
}
```

#### Outcome Event

```json
{
  "number_to_transform": 1.51,
  "target_field": 2
}
```

*The operation was successful*

### Example 9

Rounds a positive float below 1.5 but closer to 1 to 1.

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'round')
```

#### Input Event

```json
{
  "number_to_transform": 1.48888888
}
```

#### Outcome Event

```json
{
  "number_to_transform": 1.48888888,
  "target_field": 1
}
```

*The operation was successful*

### Example 10

Rounds a positive integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($number_to_transform, 'round')
```

#### Input Event

```json
{
  "number_to_transform": 1000
}
```

#### Outcome Event

```json
{
  "number_to_transform": 1000,
  "target_field": 1000
}
```

*The operation was successful*



---
# to_string

## Signature

```

field: to_string(any_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_number | number | reference | Integers between `-2^63` and `2^63-1` |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Transforms a number into a string with that number.
This helper function is typically used in the map stage


## Keywords

- `undefined` 

## Examples

### Example 1

Success to_string

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($any_number)
```

#### Input Event

```json
{
  "any_number": 12345
}
```

#### Outcome Event

```json
{
  "any_number": 12345,
  "target_field": "12345"
}
```

*The operation was successful*

### Example 2

Success to_string

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($any_number)
```

#### Input Event

```json
{
  "any_number": 23.565
}
```

#### Outcome Event

```json
{
  "any_number": 23.565,
  "target_field": "23.565000"
}
```

*The operation was successful*

### Example 3

Failure to_string

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($any_number)
```

#### Input Event

```json
{
  "any_number": "12345"
}
```

#### Outcome Event

```json
{
  "any_number": "12345"
}
```

*The operation was performed with errors*



---
# upcase

## Signature

```

field: upcase(lower_characters)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| lower_characters | string | value or reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Converts any lowercase character to an uppercase character.
The result of the uppercase (upcase) operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.


## Keywords

- `string` 

## Examples

### Example 1

Change string to uppercase

#### Asset

```yaml
normalize:
  - map:
      - target_field: upcase('abcd')
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": "ABCD"
}
```

*The operation was successful*

### Example 2

Change string to uppercase

#### Asset

```yaml
normalize:
  - map:
      - target_field: upcase($lower_characters)
```

#### Input Event

```json
{
  "lower_characters": "aBcD"
}
```

#### Outcome Event

```json
{
  "lower_characters": "aBcD",
  "target_field": "ABCD"
}
```

*The operation was successful*

### Example 3

Change string to uppercase

#### Asset

```yaml
normalize:
  - map:
      - target_field: upcase('aBcDECF')
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": "ABCDECF"
}
```

*The operation was successful*



---
# array_append

## Signature

```

field: array_append(any_object, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | number, string, object, boolean, array | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Adds the values or references of any Json type to the target array field.
This helper function is normally used in the map stage.
If the target field exists and is not an array it will be overridden, if it does not exist it will be created.
Currently this operations will fails as soon as one reference parameter is not found.
As it is an array, only elements of the same type can be added.
The type of the first element contained in the array will always be taken or, failing that, the type of the first
element to be added.


## Keywords

- `array` 

## Examples

### Example 1

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append(5)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The operation was successful*

### Example 2

The type of the value does not match the type of the array elements

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($any_object)
```

#### Input Event

```json
{
  "any_object": "hello",
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "any_object": "hello",
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The operation was performed with errors*

### Example 3

The type of the value does not match the type of the array elements

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append([1, 2])
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The operation was performed with errors*

### Example 4

The type of the value does match the type of the array elements

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($any_object)
```

#### Input Event

```json
{
  "any_object": 2,
  "target_field": [
    1.2,
    2.3,
    3.5,
    4.9
  ]
}
```

#### Outcome Event

```json
{
  "any_object": 2,
  "target_field": [
    1.2,
    2.3,
    3.5,
    4.9,
    2
  ]
}
```

*The operation was successful*



---
# array_append_any

## Signature

```

field: array_append_any(any_object, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | number, string, object, boolean, array | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Adds the values or references of any Json type to the target array field.
This helper function is normally used in the map stage.
If the target field exists and is not an array it will be overridden, if it does not exist it will be created.
This operation will not fail if a reference parameter is not found, any parameters before or after
it will be added to the target field.
As it is an array, only elements of the same type can be added. The type of the first element contained in the array
will always be taken or, failing that, the type of the first element to be added.


## Keywords

- `array` 

## Examples

### Example 1

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any(5, 6)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5,
    6
  ]
}
```

*The operation was successful*

### Example 2

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any($any_object, $any_object_2)
```

#### Input Event

```json
{
  "any_object": null,
  "any_object_2": 6,
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "any_object": null,
  "any_object_2": 6,
  "target_field": [
    1,
    2,
    3,
    4,
    6
  ]
}
```

*The operation was successful*

### Example 3

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any(5, $any_object_2)
```

#### Input Event

```json
{
  "any_object_2": null,
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "any_object_2": null,
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The operation was successful*



---
# array_append_unique

## Signature

```

field: array_append_unique(any_object, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | number, string, object, boolean, array | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Appends the string values or any Json type by reference to the target array field.
This helper function is typically used in the map stage.
If the target field exists and is not an array it will be overridden, if it does not exist it will be created.
Currently this operations will fails as soon as one reference parameter is not found or the element trying to be
added already exists in the array.


## Keywords

- `array` 

## Examples

### Example 1

Failure array append unique

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique('hello')
```

#### Input Event

```json
{
  "target_field": [
    "hola",
    "hello",
    "salut",
    "ciao"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "hola",
    "hello",
    "salut",
    "ciao"
  ]
}
```

*The operation was performed with errors*

### Example 2

Failure array append unique

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique($any_object)
```

#### Input Event

```json
{
  "any_object": 5,
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

#### Outcome Event

```json
{
  "any_object": 5,
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The operation was performed with errors*

### Example 3

Success array append unique

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique(5)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The operation was successful*



---
# array_append_unique_any

## Signature

```

field: array_append_unique_any(any_object, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | number, string, object, boolean, array | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Appends the string values or any Json type by reference to the target array field.
This helper function is typically used in the map stage.
If the target field exists and is not an array it will be overridden, if it does not exist it will be created.
This operation will not fail if a reference parameter is not found, any parameters before or after
it will be added to the target field.


## Keywords

- `array` 

## Examples

### Example 1

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any(5, 6)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4,
    5,
    6
  ]
}
```

*The operation was successful*

### Example 2

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any($any_object, $any_object_2)
```

#### Input Event

```json
{
  "any_object": null,
  "any_object_2": 6,
  "target_field": [
    1,
    2,
    3,
    4,
    6
  ]
}
```

#### Outcome Event

```json
{
  "any_object": null,
  "any_object_2": 6,
  "target_field": [
    1,
    2,
    3,
    4,
    6
  ]
}
```

*The operation was performed with errors*

### Example 3

The type of the value matches the type of the elements of the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any(5, $any_object_2)
```

#### Input Event

```json
{
  "any_object_2": null,
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "any_object_2": null,
  "target_field": [
    1,
    2,
    3,
    4,
    5
  ]
}
```

*The operation was successful*



---
# delete

## Signature

```

field: delete()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, object, boolean, array] | - |


## Description

Deletes the key named “field” from the event. If it does not exist, the function will evaluate to false.
This helper function is typically used in the map stage.


## Keywords

- `delete` 

## Examples

### Example 1

Success delete

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete()
```

#### Input Event

```json
{
  "target_field": "-- Hi wazuh! --"
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was successful*

### Example 2

Success delete

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was successful*

### Example 3

Success delete

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was successful*



---
# delete_fields_with_value

## Signature

```

field: delete_fields_with_value(any_object)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | number, string, object, boolean, array | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Deletes all immediate children of “field” whose value equals the provided argument.
The argument may be any JSON value (string, number, boolean, null, array, object) or a reference ($ref).
Equality is type-aware and structural (objects/arrays compared by value).


## Keywords

- `delete` 

## Examples

### Example 1

Deletes children equal to the given string

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value('N/A')
```

#### Input Event

```json
{
  "target_field": {
    "a": "N/A",
    "b": "ok",
    "c": "N/A"
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "b": "ok"
  }
}
```

*The operation was successful*

### Example 2

Deletes children equal to integer 1

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value(1)
```

#### Input Event

```json
{
  "target_field": {
    "a": 1,
    "b": 2,
    "c": 1
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "b": 2
  }
}
```

*The operation was successful*

### Example 3

Deletes children equal to the given double

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value(1.0)
```

#### Input Event

```json
{
  "target_field": {
    "a": 1.0,
    "b": 2.0,
    "c": 1.0
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "b": 2.0
  }
}
```

*The operation was successful*

### Example 4

Deletes children equal to the given boolean

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value(True)
```

#### Input Event

```json
{
  "target_field": {
    "a": true,
    "b": false,
    "c": true
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "b": false
  }
}
```

*The operation was successful*

### Example 5

Deletes children equal to the given object

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value({'k': 1})
```

#### Input Event

```json
{
  "target_field": {
    "a": {
      "k": 1
    },
    "b": {
      "k": 2
    },
    "c": {
      "k": 1
    }
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "b": {
      "k": 2
    }
  }
}
```

*The operation was successful*

### Example 6

Deletes children equal to the given array

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value([1, 2])
```

#### Input Event

```json
{
  "target_field": {
    "a": [
      1,
      2
    ],
    "b": [
      3
    ],
    "c": [
      1,
      2
    ]
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "b": [
      3
    ]
  }
}
```

*The operation was successful*

### Example 7

No deletions when there are no matches

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value('Z')
```

#### Input Event

```json
{
  "target_field": {
    "a": "foo",
    "b": 2
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "a": "foo",
    "b": 2
  }
}
```

*The operation was successful*

### Example 8

No deletions when reference path is not found

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value($any_object)
```

#### Input Event

```json
{
  "any_object": "$target.missing",
  "target_field": {
    "a": "keep",
    "b": 1
  }
}
```

#### Outcome Event

```json
{
  "any_object": "$target.missing",
  "target_field": {
    "a": "keep",
    "b": 1
  }
}
```

*The operation was successful*

### Example 9

No deletions when argument is null but target has no nulls

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value(null)
```

#### Input Event

```json
{
  "target_field": {
    "a": "keep",
    "b": 1,
    "c": false
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "a": "keep",
    "b": 1,
    "c": false
  }
}
```

*The operation was successful*



---
# erase_custom_fields

## Signature

```

field: erase_custom_fields()
```

## Target Field

| Type | Possible values |
| ---- | --------------- |
| [number, string, object, boolean, array] | - |


## Description

This operation removes all fields that do not belong to the schema.
Typically used with field = ".", the root element.


## Keywords

- `delete` 

## Examples

### Example 1

Success erase custom file

#### Asset

```yaml
normalize:
  - map:
      - target_field: erase_custom_fields()
```

#### Input Event

```json
{
  "target_field": "-- Hi wazuh! --"
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was successful*

### Example 2

Success erase custum file

#### Asset

```yaml
normalize:
  - map:
      - target_field: erase_custom_fields()
```

#### Input Event

```json
{
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was successful*

### Example 3

Success erase custom file

#### Asset

```yaml
normalize:
  - map:
      - target_field: erase_custom_fields()
```

#### Input Event

```json
{
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was successful*



---
# get_key_in

## Signature

```

field: get_key_in(any_object, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | object | value or reference | Any object |
| key | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Maps target field value with the content of some key in the specified object.
Where the key is specified with a reference to another field.
The object parameter must be a definition object or a reference to a field containing the object.
This helper function is typically used in the map stage.


## Keywords

- `undefined` 

## Examples

### Example 1

The value to replace was found

#### Asset

```yaml
normalize:
  - map:
      - target_field: get_key_in({'key': 'name', 'key2': 'surname'}, $key)
```

#### Input Event

```json
{
  "key": "key2",
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "key": "key2",
  "target_field": "surname"
}
```

*The operation was successful*

### Example 2

The value to replace was found

#### Asset

```yaml
normalize:
  - map:
      - target_field: get_key_in($any_object, $key)
```

#### Input Event

```json
{
  "any_object": {
    "key": "name",
    "key2": {
      "age": 27,
      "address": "new york"
    }
  },
  "key": "key2",
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "any_object": {
    "key": "name",
    "key2": {
      "age": 27,
      "address": "new york"
    }
  },
  "key": "key2",
  "target_field": {
    "age": 27,
    "address": "new york"
  }
}
```

*The operation was successful*



---
# kvdb_decode_bitmask

## Signature

```

field: kvdb_decode_bitmask(db_name, table_name, mask)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db_name | string | value | Any string |
| table_name | string | value | Any string |
| mask | string | reference | Any hexadecimal |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Decodes values based on a bitmask using a reference table constructed at compile time.
This table is generated from a object json stored in KVDB
- Compile Time:
    The function searches the db_name database for the value corresponding to table_name.
    table_name should contain a JSON object with up to 32 keys ranging from "0" to "31".
    These keys represent positions in a 32-bit binary number, with the least significant bit (LSB) positioned on the right.
    The values associated with these keys provide descriptions for each bit position or flag and must all be of the same JSON type.
    Using this information, a reference table is constructed.

- Execution Time:
    The function retrieves the value of $maskRef, which is a string containing a hexadecimal value.
    This hexadecimal value is decomposed and acts as a mask.
    For each bit set to 1 in this mask, the function looks up the reference table to fetch the corresponding value or description.
    If a value doesn't exist in the table for a particular bit, that bit is skipped.
    An array containing all the values corresponding to the activated bits in the mask is returned.


- Special Notes:
    It's not mandatory for the table to have all bit values. If a bit's value is missing, it is simply skipped.
    If the resulting array is empty, the function fails, and it neither creates nor overwrites the value of field.


## Keywords

- `kvdb` 

## Examples

### Example 1

Success decode bitmask

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('testing', 'test_bitmask', $mask)
```

#### Input Event

```json
{
  "mask": "33",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "mask": "33",
  "target_field": [
    "some_data"
  ]
}
```

*The operation was successful*

### Example 2

Failure decode bitmask. Values is out of range 0-0xFFFFFFFFFFFFFFFF

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('testing', 'test_bitmask', $mask)
```

#### Input Event

```json
{
  "mask": "99",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "mask": "99",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# kvdb_get

## Signature

```

field: kvdb_get(db-name, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | Any string |
| key | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array] | - |


## Description

Gets the value of a given key in the DB named db-name and if its successful it stores it in the given field.
Key value type can be string, number, object, array or null. This helper function is typically used in the map stage


## Keywords

- `kvdb` 

## Examples

### Example 1

Try get non exist key

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_get('testing', 'NON-EXIST-KEY')
```

#### Input Event

```json
{
  "target_field": true
}
```

#### Outcome Event

```json
{
  "target_field": false
}
```

*The operation was performed with errors*

### Example 2

Get an exist key

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_get('testing', $key)
```

#### Input Event

```json
{
  "key": "test",
  "target_field": true
}
```

#### Outcome Event

```json
{
  "key": "test",
  "target_field": false
}
```

*The operation was successful*



---
# kvdb_get_array

## Signature

```

field: kvdb_get_array(db_name, array_key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db_name | string | value | Any string |
| array_key | array | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Looks in the database for each key found in $array_ref, and appends the values to field.
Best effort, if a key is not present in the DB, skip it.


## Keywords

- `kvdb` 

## Examples

### Example 1

Success kvdb get array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_get_array('testing', ['test'])
```

#### Input Event

```json
{
  "target_field": true
}
```

#### Outcome Event

```json
{
  "target_field": false
}
```

*The operation was successful*



---
# kvdb_get_merge

## Signature

```

field: kvdb_get_merge(db-name, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | Any string |
| key | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array] | - |


## Description

Gets the value of a given key in the DB named db-name and if its successful it merge this
value with what the field had before.
Key value type can be string, number, object, array or null and it must match with the previous
value type hold by field. This helper function is typically used in the map stage.


## Keywords

- `kvdb` 

## Examples

### Example 1

Failure kvdb get merge

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_get_merge('testing', 'key')
```

#### Input Event

```json
{
  "target_field": "Type mismatch between target field and value when merging"
}
```

#### Outcome Event

```json
{
  "target_field": false
}
```

*The operation was performed with errors*



---
# kvdb_get_merge_recursive

## Signature

```

field: kvdb_get_merge_recursive(db-name, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | Any string |
| key | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array] | - |


## Description

Gets the value of a given key in the DB named db-name and, if successful, merges this value with what the field had before.
The merge process is recursive, meaning that for object or array types, the new value is deeply integrated with the existing value in the field.
Key value type can be string, number, object, array, or null, and it must match the previous value type held by the field.
This helper function is typically used in the map stage.


## Keywords

- `kvdb` 

- `recursive` 

## Examples

### Example 1

Failure kvdb get merge

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_get_merge_recursive('testing', 'key')
```

#### Input Event

```json
{
  "target_field": "Type mismatch between target field and value when merging"
}
```

#### Outcome Event

```json
{
  "target_field": false
}
```

*The operation was performed with errors*



---
# merge

## Signature

```

field: merge(any_object)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | object, array, number, string, boolean | reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, number, string, boolean] | - |


## Description

Merge “any_object“ into “field”. Both fields must be the same type and of type object or type array
otherwise the operation will fail and neither fields will be modified.
The result of the merge operation is mapped to “field” and “any_object“ is deleted.
When merging objects, if a collision is produced the target key will be overridden by the reference key.
When merging arrays, if a collision is produced the target key will be preserved in its original order
and will be not duplicated.
This helper function is typically used in the map stage


## Keywords

- `undefined` 

## Examples

### Example 1

JSON objects merged

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($any_object)
```

#### Input Event

```json
{
  "any_object": {
    "key": "name",
    "key2": {
      "age": 27,
      "address": "new york"
    }
  },
  "target_field": {
    "key3": "surname"
  }
}
```

#### Outcome Event

```json
{
  "any_object": {
    "key": "name",
    "key2": {
      "age": 27,
      "address": "new york"
    }
  },
  "target_field": {
    "key": "name",
    "key2": {
      "age": 27,
      "address": "new york"
    },
    "key3": "surname"
  }
}
```

*The operation was successful*

### Example 2

JSON objects merged

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($any_object)
```

#### Input Event

```json
{
  "any_object": [
    0,
    1,
    2,
    4
  ],
  "target_field": [
    1,
    3
  ]
}
```

#### Outcome Event

```json
{
  "any_object": [
    0,
    1,
    2,
    4
  ],
  "target_field": [
    1,
    3,
    0,
    2,
    4
  ]
}
```

*The operation was successful*



---
# merge_key_in

## Signature

```

field: merge_key_in(any_object, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | object | value or reference | Any object |
| key | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Merge in target field value with the content of some key in the specified object, where the key is specified with a reference to another field.
The object parameter must be a definition object or a reference to a field containing the object.
This helper function is typically used in the map stage.


## Keywords

- `undefined` 

## Examples

### Example 1

The merge was success

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_key_in({'input_key_1': {'v1': 'k1'}, 'input_key_2': {'v2': 'k2'}}, $key)
```

#### Input Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v0": "k0"
  }
}
```

#### Outcome Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "v1": "k1"
  }
}
```

*The operation was successful*

### Example 2

The input key was not found

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_key_in($any_object, $key)
```

#### Input Event

```json
{
  "any_object": {
    "input_key_1": {
      "v1": "k1"
    },
    "input_key_2": {
      "v2": "k2"
    }
  },
  "key": "input_key_not_found",
  "target_field": {
    "v0": "k0"
  }
}
```

#### Outcome Event

```json
{
  "any_object": {
    "input_key_1": {
      "v1": "k1"
    },
    "input_key_2": {
      "v2": "k2"
    }
  },
  "key": "input_key_not_found",
  "target_field": {
    "v0": "k0"
  }
}
```

*The operation was performed with errors*

### Example 3

The value from the specified key `input_key_1` is not merged into `target_field`, due to the need for recursion.

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_key_in({'input_key_1': {'v1': 'k1', 'nested': {'n1': 'value1'}}, 'input_key_2': {'v2': 'k2'}}, $key)
```

#### Input Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "nested": {
      "n2": "value2"
    }
  }
}
```

#### Outcome Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "v1": "k1",
    "nested": {
      "n1": "value1"
    }
  }
}
```

*The operation was successful*

### Example 4

Success merge in object with same keys

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_key_in($any_object, $key)
```

#### Input Event

```json
{
  "any_object": {
    "input_key_1": {
      "b": "a-value",
      "c": "a-value"
    }
  },
  "key": "input_key_1",
  "target_field": {
    "a": "b-value",
    "c": "b-value"
  }
}
```

#### Outcome Event

```json
{
  "any_object": {
    "input_key_1": {
      "b": "a-value",
      "c": "a-value"
    }
  },
  "key": "input_key_1",
  "target_field": {
    "a": "b-value",
    "b": "a-value",
    "c": "a-value"
  }
}
```

*The operation was successful*



---
# merge_recursive_key_in

## Signature

```

field: merge_recursive_key_in(any_object, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| any_object | object | value or reference | Any object |
| key | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Recursively merge the target field value with the content of a specified key in the given object.
The key is identified through a reference to another field.
If the key's value contains nested objects, the merge operation is applied recursively, combining all levels of the structure.
The object parameter must be a definition object or a reference to a field containing the object.
This helper function is typically used in the map stage to ensure deep merging of complex objects.


## Keywords

- `undefined` 

## Examples

### Example 1

The value from the specified key `input_key_1` is merged into `target_field`, including nested structures.

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_recursive_key_in({'input_key_1': {'v1': 'k1', 'nested': {'n1': 'value1'}}, 'input_key_2': {'v2': 'k2'}}, $key)
```

#### Input Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "nested": {
      "n2": "value2"
    }
  }
}
```

#### Outcome Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "v1": "k1",
    "nested": {
      "n1": "value1",
      "n2": "value2"
    }
  }
}
```

*The operation was successful*

### Example 2

The value from the specified key `input_key_1`, including a different nested structure (`other_nested`), is merged into `target_field`.

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_recursive_key_in($any_object, $key)
```

#### Input Event

```json
{
  "any_object": {
    "input_key_1": {
      "v1": "k1",
      "other_nested": {
        "n1": "value1"
      }
    },
    "input_key_2": {
      "v2": "k2"
    }
  },
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "nested": {
      "n2": "value2"
    }
  }
}
```

#### Outcome Event

```json
{
  "any_object": {
    "input_key_1": {
      "v1": "k1",
      "other_nested": {
        "n1": "value1"
      }
    },
    "input_key_2": {
      "v2": "k2"
    }
  },
  "key": "input_key_1",
  "target_field": {
    "v0": "k0",
    "v1": "k1",
    "other_nested": {
      "n1": "value1"
    },
    "nested": {
      "n2": "value2"
    }
  }
}
```

*The operation was successful*

### Example 3

The `nested` content from the specified key `input_key_1` is merged into `target_field`, preserving existing fields.

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_recursive_key_in({'input_key_1': {'v1': 'k1', 'nested': {'n1': 'value1'}}, 'input_key_2': {'v2': 'k2'}}, $key)
```

#### Input Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v1": "k1",
    "nested": {
      "n2": "value2"
    }
  }
}
```

#### Outcome Event

```json
{
  "key": "input_key_1",
  "target_field": {
    "v1": "k1",
    "nested": {
      "n1": "value1",
      "n2": "value2"
    }
  }
}
```

*The operation was successful*

### Example 4

The specified key `input_key_not_exists` does not exist in `any_object`, so no merge is performed, and the test fails as expected.

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge_recursive_key_in($any_object, $key)
```

#### Input Event

```json
{
  "any_object": {
    "input_key_1": {
      "v1": "k1",
      "nested": {
        "n1": "value1"
      }
    },
    "input_key_2": {
      "v2": "k2"
    }
  },
  "key": "input_key_not_exists",
  "target_field": {
    "v0": "k0",
    "nested": {
      "n2": "value2"
    }
  }
}
```

#### Outcome Event

```json
{
  "any_object": {
    "input_key_1": {
      "v1": "k1",
      "nested": {
        "n1": "value1"
      }
    },
    "input_key_2": {
      "v2": "k2"
    }
  },
  "key": "input_key_not_exists",
  "target_field": {
    "v0": "k0",
    "nested": {
      "n2": "value2"
    }
  }
}
```

*The operation was performed with errors*



---
# parse_alphanumeric

## Signature

```

field: parse_alphanumeric(field_to_parse, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| field_to_parse | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Checks if an input matches an alphanumeric string, and if so, it evaluates to true and the extracted data
contained in a JSON object is stored in the output field; otherwise, it evaluates to false.


## Keywords

- `parser` 

## Examples

### Example 1

Success alphanumeric parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_alphanumeric($field_to_parse)
```

#### Input Event

```json
{
  "field_to_parse": "Hello2024",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "field_to_parse": "Hello2024",
  "target_field": "Hello2024"
}
```

*The operation was successful*

### Example 2

Failure alphanumeric parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_alphanumeric($field_to_parse)
```

#### Input Event

```json
{
  "field_to_parse": "Not{isalphanum}",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "field_to_parse": "Not{isalphanum}",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_between

## Signature

```

field: parse_between(input_field, start, end, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| start | string | value | Any string |
| end | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that begins with the `start` delimiter and ends
with the `end` delimiter. If so, it extracts the text found between these delimiters
and stores this extracted substring in `field`


## Keywords

- `parser` 

## Examples

### Example 1

Success between parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input_field, '[', ']')
```

#### Input Event

```json
{
  "input_field": "[Hello, World!]",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "[Hello, World!]",
  "target_field": "Hello, World!"
}
```

*The operation was successful*

### Example 2

Failure between parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input_field, '(', ')')
```

#### Input Event

```json
{
  "input_field": "(Start) Middle End",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "(Start) Middle End",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Success between parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input_field, 'Start', 'End')
```

#### Input Event

```json
{
  "input_field": "Start and End",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "Start and End",
  "target_field": " and "
}
```

*The operation was successful*



---
# parse_binary

## Signature

```

field: parse_binary(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Evaluates if the content of the input field is a string that accurately represents base64 encoded data.
It checks the string for compliance with the base64 encoding standards, including character set and padding.
If the string is a valid base64 encoded string, it stores the same string in `field` without modification.


## Keywords

- `parser` 

## Examples

### Example 1

Success binary parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input_field)
```

#### Input Event

```json
{
  "input_field": "SGVsbG8sIFdvcmxkIQ==",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "SGVsbG8sIFdvcmxkIQ==",
  "target_field": "SGVsbG8sIFdvcmxkIQ=="
}
```

*The operation was successful*

### Example 2

Failure binary parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input_field)
```

#### Input Event

```json
{
  "input_field": "not base64",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "not base64",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure binary parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input_field)
```

#### Input Event

```json
{
  "input_field": "not base64",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "not base64",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

Failure binary parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input_field)
```

#### Input Event

```json
{
  "input_field": "not base64",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input_field": "not base64",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*

### Example 5

Failure binary parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input_field)
```

#### Input Event

```json
{
  "input_field": "not base64",
  "target_field": true
}
```

#### Outcome Event

```json
{
  "input_field": "not base64",
  "target_field": true
}
```

*The operation was performed with errors*



---
# parse_bool

## Signature

```

field: parse_bool(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Checks if an input is the “true” or “false” string and store a boolean value in field according to the string value.
The operation es key insensitive Fail if other value is store in $inField or not exist.


## Keywords

- `parser` 

## Examples

### Example 1

Success bool parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input_field)
```

#### Input Event

```json
{
  "input_field": "true",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "true",
  "target_field": true
}
```

*The operation was successful*

### Example 2

Failure bool parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure bool parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

Failure bool parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_byte

## Signature

```

field: parse_byte(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Evaluates if the content of the input field is a string representing a numeric value.
If the numeric value is within the range of -128 to 127 (inclusive)
it truncates the number to fit into a byte data type and stores the result in `field`. The operation is case-sensitive.


## Keywords

- `parser` 

## Examples

### Example 1

Success byte parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input_field)
```

#### Input Event

```json
{
  "input_field": "127",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "127",
  "target_field": 127
}
```

*The operation was successful*

### Example 2

Failure byte parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure byte parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input_field)
```

#### Input Event

```json
{
  "input_field": "130",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "130",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

Failure byte parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input_field)
```

#### Input Event

```json
{
  "input_field": "130",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input_field": "130",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_csv

## Signature

```

field: parse_csv(input_field, out1, out2, out3, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| out1 | string | value | Any string |
| out2 | string | value | Any string |
| out3 | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

This parser is just the same as the “dsv” parser, but its delimiter is the “comma”, the quoting and escaping character
are the quotation mark, and they cannot be changed.
It can be used to extract values separated by commas (“comma separated values”).
These values will be stored on user-specified fields (outputs), but only if all the expected outputs are obtained.
Eg, user expects 4 values but only 3 can be obtained, then the parser fails and no value is stored.
All the characters contained between the “quoting” characters will be considered part of a single value
even the “comma” character. If the quoting is not correctly balanced, the parser will fail.
The “escaping” character is used to escape the “quoting” characters that are intended to be used as literal characters.
This helper function is typically used in the map stage.


## Keywords

- `parser` 

## Examples

### Example 1

Success csv parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input_field, 'out1', 'out2', 'out3')
```

#### Input Event

```json
{
  "input_field": "value1,value2,value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "value1,value2,value3",
  "target_field": {
    "out1": "value1",
    "out2": "value2",
    "out3": "value3"
  }
}
```

*The operation was successful*

### Example 2

Success csv parse with slash and dotpath

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input_field, 'out1.key', 'out2/key', 'out3.key/subkey')
```

#### Input Event

```json
{
  "input_field": "value1,value2,value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "value1,value2,value3",
  "target_field": {
    "out1": {
      "key": "value1"
    },
    "out2": {
      "key": "value2"
    },
    "out3": {
      "key": {
        "subkey": "value3"
      }
    }
  }
}
```

*The operation was successful*

### Example 3

Failure csv parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input_field, 'out1', 'out2', 'out3')
```

#### Input Event

```json
{
  "input_field": "valu1=1 value2=2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "valu1=1 value2=2",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_date

## Signature

```

field: parse_date(input_field, format, locale)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| format | string | value | Any string |
| locale | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Parses a date/time string and normalizes it to a datetime value.
The first option must be either a strftime-like format (e.g., "%Y-%m-%dT%H:%M:%S%z")
or a sample date string from which the format can be inferred.
Optionally, a second parameter "locale" can be provided. If omitted, "C/POSIX" is used.


## Keywords

- `parser` 

- `date` 

- `time` 

## Examples

### Example 1

ISO-8601 with timezone (explicit format)

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input_field, '%Y-%m-%dT%H:%M:%S%Ez', '_auto')
```

#### Input Event

```json
{
  "input_field": "2025-09-01T10:30:00-05:00",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "2025-09-01T10:30:00-05:00",
  "target_field": "2025-09-01T15:30:00.000Z"
}
```

*The operation was successful*

### Example 2

dd/mm/YYYY HH:MM (explicit format)

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input_field, '%d/%m/%Y %H:%M', '_auto')
```

#### Input Event

```json
{
  "input_field": "01/09/2025 10:30",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "01/09/2025 10:30",
  "target_field": "2025-09-01T10:30:00.000Z"
}
```

*The operation was successful*

### Example 3

Format mismatch -> error

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input_field, '%Y-%m-%d %H:%M', '_auto')
```

#### Input Event

```json
{
  "input_field": "2025/09/01 10:30",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "2025/09/01 10:30",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_double

## Signature

```

field: parse_double(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that can be successfully converted into a double-precision
floating-point number. It converts and stores the double-precision number in `field` without truncation
as double-precision floating-point numbers are capable of representing a wide range of decimal numbers with
significant precision.


## Keywords

- `undefined` 

## Examples

### Example 1

Success double parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_double($input_field)
```

#### Input Event

```json
{
  "input_field": "23.45",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "23.45",
  "target_field": 23.45
}
```

*The operation was successful*

### Example 2

Failure double parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_double($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_dsv

## Signature

```

field: parse_dsv(input_field, delim_char, quote_char, esc_char, out, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| delim_char | string | value | Any string |
| quote_char | string | value | Any string |
| esc_char | string | value | Any string |
| out | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

This parser can be used to extract values separated by a specific delimiter (“delimiter separated values”)
which must be a single character. These values will be stored on user-specified fields (outputs)
but only if all the expected outputs are obtained. Eg, user expects 4 values but only 3 can be obtained
then the parser fails and no value is stored.
Additionally to the “delimiting” character, the user must define a “quoting” and “escaping” character.
All the characters contained between the “quoting” characters will be considered part
of  a single value, even the “delimiting” character. If the quoting is not correctly balanced, the parser will fail.
The “escaping” character is used to escape the “quoting” characters that are intended to be used as literal characters.
This helper function is typically used in the map stage.


## Keywords

- `parser` 

## Examples

### Example 1

Success dsv parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input_field, '|', "'", '\\', 'out1', 'out2')
```

#### Input Event

```json
{
  "input_field": "value1|value2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "value1|value2",
  "target_field": {
    "out1": "value1",
    "out2": "value2"
  }
}
```

*The operation was successful*

### Example 2

Success dsv parse with slash and dotpath

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input_field, '|', "'", '\\', 'out1.key', 'out2/key', 'out3.key/subkey')
```

#### Input Event

```json
{
  "input_field": "value1|value2|value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "value1|value2|value3",
  "target_field": {
    "out1": {
      "key": "value1"
    },
    "out2": {
      "key": "value2"
    },
    "out3": {
      "key": {
        "subkey": "value3"
      }
    }
  }
}
```

*The operation was successful*

### Example 3

Failure dsv parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input_field, '|', '\\', "'", 'out1', 'out2')
```

#### Input Event

```json
{
  "input_field": "key1:value1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "key1:value1",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_file

## Signature

```

field: parse_file(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Checks whether an input contains a valid file path and, if so,  it evaluates to true and the extracted data contained
in a JSON object is then stored on the field, otherwise it evaluates to false.


## Keywords

- `parser` 

## Examples

### Example 1

Success file parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_file($input_field)
```

#### Input Event

```json
{
  "input_field": "C:\\Windows\\System32\\program.exe",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "C:\\Windows\\System32\\program.exe",
  "target_field": {
    "path": "C:\\Windows\\System32",
    "ext": "exe",
    "drive_letter": "C",
    "name": "program.exe"
  }
}
```

*The operation was successful*



---
# parse_float

## Signature

```

field: parse_float(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that can be successfully converted into a floating-point number.
It converts and stores the floating-point number in `field`, as floating-point numbers inherently support decimals.


## Keywords

- `parser` 

## Examples

### Example 1

Success float parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input_field)
```

#### Input Event

```json
{
  "input_field": "23.45234",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "23.45234",
  "target_field": 23.45233917236328
}
```

*The operation was successful*

### Example 2

Failure float parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure float parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

Failure float parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input_field)
```

#### Input Event

```json
{
  "input_field": "hello",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input_field": "hello",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_fqdn

## Signature

```

field: parse_fqdn(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is used to obtain, if possible, a valid domain name.
Such domain cannot be longer than 255 characters and can only contain “a-z”, “A-Z”, “0-9”, “.” and “-”.
Checks whether an input contains a valid domain name format and, if so, it evaluates to true and is then
stored on the field, otherwise it evaluates to false.


## Keywords

- `parser` 

## Examples

### Example 1

Success fqdn parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input_field)
```

#### Input Event

```json
{
  "input_field": "www.someurl.co",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "www.someurl.co",
  "target_field": "www.someurl.co"
}
```

*The operation was successful*

### Example 2

Failure fqdn parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input_field)
```

#### Input Event

```json
{
  "input_field": "www.some~url.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "www.some~url.com",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure fqdn parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input_field)
```

#### Input Event

```json
{
  "input_field": "www.some~url.com",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "www.some~url.com",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

Failure fqdn parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input_field)
```

#### Input Event

```json
{
  "input_field": "www.some~url.com",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input_field": "www.some~url.com",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_ip

## Signature

```

field: parse_ip(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to validate and parse strings representing IP addresses, whether they are in IPv4 or IPv6 format.
Evaluates if the content of the input field is a string that accurately represents an IP address in either IPv4 or IPv6 format.
It checks the string for compliance with IP addressing standards, including the correct notation
and range for IPv4 (four decimal numbers separated by dots, each ranging from 0 to 255)
and the correct format for IPv6 (eight groups of four hexadecimal digits separated by colons).
If the string is a valid IP address, it stores the same string in `field` without modification.


## Keywords

- `parser` 

## Examples

### Example 1

Success ip parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input_field)
```

#### Input Event

```json
{
  "input_field": "192.168.1.1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "192.168.1.1",
  "target_field": "192.168.1.1"
}
```

*The operation was successful*

### Example 2

Success ip parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input_field)
```

#### Input Event

```json
{
  "input_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "target_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}
```

*The operation was successful*

### Example 3

Failure ip parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input_field)
```

#### Input Event

```json
{
  "input_field": "999.999.999.999",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "999.999.999.999",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

Failure ip parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input_field)
```

#### Input Event

```json
{
  "input_field": "999.999.999.999",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input_field": "999.999.999.999",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_json

## Signature

```

field: parse_json(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to interpret and convert strings formatted in JSON notation into a JSON.
It is particularly useful for extracting structured data from stringified JSON representations.
Upon invocation, the parser reads the input string and attempts to validate it as a proper JSON format.
If the validation is successful, the input is transformed into a JSON object
which is then assigned to the specified field. If the input is not valid JSON, the parser does not modify the output.


## Keywords

- `parser` 

## Examples

### Example 1

Success json parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input_field)
```

#### Input Event

```json
{
  "input_field": "{\"key\": {\"innerKey\": \"value\"}}",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "{\"key\": {\"innerKey\": \"value\"}}",
  "target_field": {
    "key": {
      "innerKey": "value"
    }
  }
}
```

*The operation was successful*

### Example 2

Failure json parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input_field)
```

#### Input Event

```json
{
  "input_field": "{\"key\": \"innerKey\": \"value\"}}",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "{\"key\": \"innerKey\": \"value\"}}",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*



---
# parse_key_value

## Signature

```

field: parse_key_value(input_field, sep_token, delim_token, quote_char, esc_char, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| sep_token | string | value | Any string |
| delim_token | string | value | Any string |
| quote_char | string | value | Any string |
| esc_char | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser can be used to extract key-value pairs from a keys-values list.
If the parser succeeds, each value will be stored on a field named as its corresponding key.
Keys are linked to values by the “separator” token (may be multi-character).
Each key-value pair is split from others, given the “delimiting” token (may be multi-character).
Additionally, the user must define a “quoting” and “escaping” character.
All the characters contained between the “quoting” characters will be considered part of  a single value
even the “separator” and “delimiting” tokens. If the quoting is not correctly balanced, the parser will fail.
The “escaping” character is used to escape the “quoting” characters that are intended to be used as literal characters.
This helper function is typically used in the map stage.
Checks whether an input fits a keys-values list format and, if it does, such pairs of keys and values are stored as new fields of the event.


## Keywords

- `parser` 

## Examples

### Example 1

Success key value parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_key_value($input_field, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input_field": "key1=value1 key2=value2 key3=value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "key1=value1 key2=value2 key3=value3",
  "target_field": {
    "key1": "value1",
    "key2": "value2",
    "key3": "value3"
  }
}
```

*The operation was successful*

### Example 2

Failure key value parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_key_value($input_field, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input_field": "key1:value1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "key1:value1",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Success with multi-char delimiter and single-char separator

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_key_value($input_field, '=', ' || ', "'", '\\')
```

#### Input Event

```json
{
  "input_field": "k1=v1 || k2=v2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "k1=v1 || k2=v2",
  "target_field": {
    "k1": "v1",
    "k2": "v2"
  }
}
```

*The operation was successful*

### Example 4

Success with single-char delimiter and multi-char separator

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_key_value($input_field, '::=', ',', "'", '\\')
```

#### Input Event

```json
{
  "input_field": "a::=x,b::=y",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "a::=x,b::=y",
  "target_field": {
    "a": "x",
    "b": "y"
  }
}
```

*The operation was successful*

### Example 5

Success multi-character tokens

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_key_value($input_field, '::=', ' || ', '"', '\\')
```

#### Input Event

```json
{
  "input_field": "k1::=v1 || k2::=v2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "k1::=v1 || k2::=v2",
  "target_field": {
    "k1": "v1",
    "k2": "v2"
  }
}
```

*The operation was successful*

### Example 6

Failure when separator and delimiter are the same

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_key_value($input_field, '=', '=', "'", '\\')
```

#### Input Event

```json
{
  "input_field": "a=b=c",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "a=b=c",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_long

## Signature

```

field: parse_long(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that can be successfully converted into a 64-bit
integer (long). It converts and stores the integer value in `field`.


## Keywords

- `parser` 

## Examples

### Example 1

Success long parse (positive integer)

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input_field)
```

#### Input Event

```json
{
  "input_field": "12345",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "12345",
  "target_field": 12345
}
```

*The operation was successful*

### Example 2

Success long parse (negative integer)

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input_field)
```

#### Input Event

```json
{
  "input_field": "-42",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "-42",
  "target_field": -42
}
```

*The operation was successful*

### Example 3

Failure long parse (non-numeric characters)

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input_field)
```

#### Input Event

```json
{
  "input_field": "12a3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "12a3",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_quoted

## Signature

```

field: parse_quoted(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to extract text enclosed in quotation marks from the input string.
It supports custom quotation and escape characters, allowing for flexibility in parsing complex quoted strings.
Evaluates the content of the input field to extract text that is enclosed in the specified `quoted` character
considering any `escape` characters used to include the quotation character within the quoted text.


## Keywords

- `parser` 

## Examples

### Example 1

Success quoted parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input_field)
```

#### Input Event

```json
{
  "input_field": "\"Hello, my name is 'Wazuh'.\"",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "\"Hello, my name is 'Wazuh'.\"",
  "target_field": "Hello, my name is 'Wazuh'."
}
```

*The operation was successful*

### Example 2

Failure quoted parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input_field)
```

#### Input Event

```json
{
  "input_field": "'escaped\\' quotes'",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "'escaped\\' quotes'",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure quoted parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input_field)
```

#### Input Event

```json
{
  "input_field": "don't start with quotes \"here",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "don't start with quotes \"here",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_uri

## Signature

```

field: parse_uri(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is used to obtain, if possible, information from a valid URI.
The result will be an ECS url object encoded as a JSON string. This parser takes no arguments.
Checks whether an input contains a valid URI format and, if so, it evaluates to true and transforms
it to a ECS url object encoded as a JSON string which is then stored on the field, otherwise it evaluates to false.


## Keywords

- `parser` 

## Examples

### Example 1

Success uri parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input_field)
```

#### Input Event

```json
{
  "input_field": "http://someurl.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "http://someurl.com",
  "target_field": {
    "original": "http://someurl.com/",
    "scheme": "http",
    "domain": "someurl.com",
    "path": "/"
  }
}
```

*The operation was successful*

### Example 2

Failure uri parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input_field)
```

#### Input Event

```json
{
  "input_field": "www.someurl.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "www.someurl.com",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Failure uri parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input_field)
```

#### Input Event

```json
{
  "input_field": "www.someurl.com",
  "target_field": true
}
```

#### Outcome Event

```json
{
  "input_field": "www.someurl.com",
  "target_field": true
}
```

*The operation was performed with errors*

### Example 4

Failure uri parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input_field)
```

#### Input Event

```json
{
  "input_field": "www.someurl.com",
  "target_field": [
    true
  ]
}
```

#### Outcome Event

```json
{
  "input_field": "www.someurl.com",
  "target_field": [
    true
  ]
}
```

*The operation was performed with errors*



---
# parse_useragent

## Signature

```

field: parse_useragent(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to process and map user agent strings.
It does not perform any transformation or parsing in the traditional sense but directly maps
the input user agent string to a specific field in the output.
Takes a reference to a string that represents the user agent of a device or browser.
It directly maps this string to `field` without any modification or parsing.
This function is particularly useful for logging or analyzing user agent strings in their original format.


## Keywords

- `parser` 

## Examples

### Example 1

Success useragent parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_useragent($input_field)
```

#### Input Event

```json
{
  "input_field": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110",
  "target_field": {
    "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110"
  }
}
```

*The operation was successful*



---
# parse_xml

## Signature

```

field: parse_xml(input_field, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser is designed to interpret and convert strings formatted in XML notation into a JSON object.
It preserves the structure of the original XML in the default mode and provides a specialized
transformation for Windows Event Log XML when the optional "windows" argument is used.


## Keywords

- `parser` 

## Examples

### Example 1

Success xml parse

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input_field)
```

#### Input Event

```json
{
  "input_field": "<greeting>some greetring</greeting>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "<greeting>some greetring</greeting>",
  "target_field": {
    "greeting": {
      "#text": "some greetring"
    }
  }
}
```

*The operation was successful*

### Example 2

Invalid XML

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input_field)
```

#### Input Event

```json
{
  "input_field": "<greeting>some greetring<greeting>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input_field": "<greeting>some greetring<greeting>",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# rename

## Signature

```

field: rename(input_field)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Moves existing “input_field” to the field name provided (field). Replace if field exist.
This helper function is used in the map stage.


## Keywords

- `undefined` 

## Examples

### Example 1

Target field 'target_field' already exists

#### Asset

```yaml
normalize:
  - map:
      - target_field: rename($input_field)
```

#### Input Event

```json
{
  "input_field": 42,
  "target_field": "elapsed_time"
}
```

#### Outcome Event

```json
{
  "input_field": 42,
  "target_field": "elapsed_time"
}
```

*The operation was performed with errors*



---
# replace

## Signature

```

field: replace(old, new)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| old | string | value | Any string |
| new | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string |


## Description

The operation replaces in “field”, all occurrences of the given string by the new string.
In case of errors “field” will not be modified.
This helper function is typically used in the map stage


## Keywords

- `string` 

## Examples

### Example 1

The value to replace was found

#### Asset

```yaml
normalize:
  - map:
      - target_field: replace('hello', 'hi')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

#### Outcome Event

```json
{
  "target_field": "hi world!"
}
```

*The operation was successful*

### Example 2

The value to replace was not found

#### Asset

```yaml
normalize:
  - map:
      - target_field: replace('non exist', 'hi')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

#### Outcome Event

```json
{
  "target_field": "hello world!"
}
```

*The operation was successful*



---
# sanitize_fields

## Signature

```

field: sanitize_fields(recursive)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| recursive | boolean | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string] | - |


## Description

Normalize JSON object keys, nested object keys, standalone strings, and strings inside arrays using `basicNormalize`.

### Behavior:
- **Object keys** are sanitized: all keys in the object are normalized.
- **Nested objects**: if `recursive` is true, keys inside nested objects are also sanitized.
- **Arrays**:
  - Arrays that are **not values of JSON object keys** are processed element-wise.
  - Elements can be:
    - **Strings:** normalized individually.
    - **Objects:** their keys are sanitized.
    - **Nested arrays:** processed recursively if `recursive` is true.
  - Arrays containing unsupported primitives (numbers, booleans, null) cause failure.
- **Standalone strings** (when `target_field` is a string node) are normalized directly.


## Keywords

- `sanitize` 

- `rename` 

- `normalize` 

## Examples

### Example 1

Keys already normalized

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "a": 1,
    "b": 2
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "a": 1,
    "b": 2
  }
}
```

*The operation was successful*

### Example 2

Keys lowercased and separators mapped to underscores

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "Full Name": "Ana",
    "e-mail": "x",
    "Pais": "AR"
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "full_name": "Ana",
    "e_mail": "x",
    "pais": "AR"
  }
}
```

*The operation was successful*

### Example 3

Both map to 'hello_world' -> collision

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "hello world": 1,
    "hello-world": 2
  }
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*

### Example 4

basicNormalize does not prefix underscores for leading digits

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "123abc": 1,
    "x": 2
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "123abc": 1,
    "x": 2
  }
}
```

*The operation was successful*

### Example 5

Strings in arrays normalized

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    "Hello world",
    "hello-world",
    "HELLO  world"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "hello_world",
    "hello_world",
    "hello_world"
  ]
}
```

*The operation was successful*

### Example 6

Object keys inside arrays normalized

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    {
      "Full Name": "Ana"
    },
    {
      "e-mail": "x"
    }
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    {
      "full_name": "Ana"
    },
    {
      "e_mail": "x"
    }
  ]
}
```

*The operation was successful*

### Example 7

Mixed string/object array supported

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    "Hello world",
    {
      "Full Name": "Ana"
    }
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "hello_world",
    {
      "full_name": "Ana"
    }
  ]
}
```

*The operation was successful*

### Example 8

Numbers in arrays not allowed by policy

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    1,
    {
      "a": 1
    }
  ]
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*

### Example 9

Booleans in arrays not allowed by policy

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    true,
    {
      "a": 1
    }
  ]
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*

### Example 10

Nulls in arrays not allowed by policy

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    null,
    {
      "a": 1
    }
  ]
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*

### Example 11

Nested arrays/objects processed recursively

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    [
      "Hello world",
      "hello-world"
    ],
    [
      {
        "Full Name": "Ana"
      }
    ]
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    [
      "hello_world",
      "hello_world"
    ],
    [
      {
        "full_name": "Ana"
      }
    ]
  ]
}
```

*The operation was successful*

### Example 12

Deep object keys normalized

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(True)
```

#### Input Event

```json
{
  "target_field": {
    "a": {
      "B-C": {
        "D E": 1
      }
    }
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "a": {
      "b_c": {
        "d_e": 1
      }
    }
  }
}
```

*The operation was successful*

### Example 13

Duplicated normalized strings in arrays are allowed

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    "a b",
    "a-b",
    "a_b"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "a_b",
    "a_b",
    "a_b"
  ]
}
```

*The operation was successful*

### Example 14

All characters dropped -> empty key is invalid

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "***": 1
  }
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*

### Example 15

Mixed '\\', '/', ':', spaces collapse to single underscores

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "a\\\\b///c::d  e": 1
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "a_b_c_d_e": 1
  }
}
```

*The operation was successful*

### Example 16

Trailing ':' produces '_' then it is trimmed at the end

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    "name:": 1
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "name": 1
  }
}
```

*The operation was successful*

### Example 17

All characters are separators; normalized key becomes empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": {
    ":\\ /- .": 1
  }
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*

### Example 18

Backslash and colon in strings become underscores

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": [
    "A\\B:C",
    "X:Y\\Z"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "a_b_c",
    "x_y_z"
  ]
}
```

*The operation was successful*

### Example 19

Single string node normalized directly

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": "HELLO-world\\TEST"
}
```

#### Outcome Event

```json
{
  "target_field": "hello_world_test"
}
```

*The operation was successful*

### Example 20

Only separators -> sanitized string becomes empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: sanitize_fields(False)
```

#### Input Event

```json
{
  "target_field": "::::"
}
```

#### Outcome Event

```json
{
  "target_field": ""
}
```

*The operation was performed with errors*



---
# split

## Signature

```

field: split(input_field, character)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| character | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

The operation splits a string into parts by a separator character.
The parts are put into an array of strings. The result of the split into array (split) operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.
This helper function is typically used in the map stage


## Keywords

- `string` 

## Examples

### Example 1

Success split

#### Asset

```yaml
normalize:
  - map:
      - target_field: split($input_field, '|')
```

#### Input Event

```json
{
  "input_field": "val 1 | val 2 | val 3"
}
```

#### Outcome Event

```json
{
  "input_field": "val 1 | val 2 | val 3",
  "target_field": [
    "val 1 ",
    " val 2 ",
    " val 3"
  ]
}
```

*The operation was successful*



---
# trim

## Signature

```

field: trim(trim_place, character)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| trim_place | string | value | begin, end, both |
| character | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| string |


## Description

The operation removes characters (0 or more) from the start, end or start and end of the field.
The result of the trim (trim) operation is mapped to “field”. In case of errors “field” will not be modified.
This helper function is typically used in the map stage


## Keywords

- `string` 

## Examples

### Example 1

Success trim

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('end', '-')
```

#### Input Event

```json
{
  "target_field": "-- Hi wazuh! --"
}
```

#### Outcome Event

```json
{
  "target_field": "-- Hi wazuh! "
}
```

*The operation was successful*

### Example 2

Success trim

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('begin', '-')
```

#### Input Event

```json
{
  "target_field": "-- Hi wazuh! --"
}
```

#### Outcome Event

```json
{
  "target_field": " Hi wazuh! --"
}
```

*The operation was successful*

### Example 3

Success trim

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('both', '-')
```

#### Input Event

```json
{
  "target_field": "-- Hi wazuh! --"
}
```

#### Outcome Event

```json
{
  "target_field": " Hi wazuh! "
}
```

*The operation was successful*



---
