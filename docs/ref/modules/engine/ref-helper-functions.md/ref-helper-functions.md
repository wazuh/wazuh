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
- [is_not_object](#is_not_object)
- [is_not_string](#is_not_string)
- [is_number](#is_number)
- [is_object](#is_object)
- [is_public_ip](#is_public_ip)
- [is_string](#is_string)
- [is_test_session](#is_test_session)
- [keys_exist_in_list](#keys_exist_in_list)
- [kvdb_match](#kvdb_match)
- [kvdb_not_match](#kvdb_not_match)
- [match_value](#match_value)
- [regex_match](#regex_match)
- [starts_with](#starts_with)
- [string_equal](#string_equal)
- [string_greater](#string_greater)
- [string_less](#string_less)
- [string_less_or_equal](#string_less_or_equal)
- [string_not_equal](#string_not_equal)

### Map

- [as](#as)
- [concat](#concat)
- [concat_any](#concat_any)
- [date_from_epoch](#date_from_epoch)
- [decode_base16](#decode_base16)
- [downcase](#downcase)
- [float_calculate](#float_calculate)
- [geoip](#geoip)
- [get_date](#get_date)
- [hex_to_number](#hex_to_number)
- [int_calculate](#int_calculate)
- [ip_version](#ip_version)
- [join](#join)
- [regex_extract](#regex_extract)
- [sha1](#sha1)
- [system_epoch](#system_epoch)
- [to_int](#to_int)
- [to_string](#to_string)
- [upcase](#upcase)

### Transformation

- [array_append](#array_append)
- [array_append_any](#array_append_any)
- [array_append_unique](#array_append_unique)
- [array_append_unique_any](#array_append_unique_any)
- [delete](#delete)
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
- [parse_double](#parse_double)
- [parse_dsv](#parse_dsv)
- [parse_file](#parse_file)
- [parse_float](#parse_float)
- [parse_fqdn](#parse_fqdn)
- [parse_ip](#parse_ip)
- [parse_json](#parse_json)
- [parse_key_value](#parse_key_value)
- [parse_quoted](#parse_quoted)
- [parse_uri](#parse_uri)
- [parse_useragent](#parse_useragent)
- [parse_xml](#parse_xml)
- [rename](#rename)
- [replace](#replace)
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

field: parse_binary(input_field, [...])
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

field: parse_bool(input_field, [...])
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

field: parse_byte(input_field, [...])
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
# parse_double

## Signature

```

field: parse_double(input_field, [...])
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

field: parse_float(input_field, [...])
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

field: parse_key_value(input_field, sep_char, delim_char, quote_char, esc_char, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input_field | string | reference | Any string |
| sep_char | string | value | Any string |
| delim_char | string | value | Any string |
| quote_char | string | value | Any string |
| esc_char | string | value | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

This parser can be used to extract key-value pairs from a keys-values list.
If the parser succeeds, each value will be stored on a field named as its corresponding key.
Keys are linked to values by the “separator” character.
Each key-value pair is split from others, given the “delimiting” character.
Additionally, the user must define a “quoting” and “escaping” character.
All the characters contained between the “quoting” characters will be considered part of  a single value
even the “separator” and “delimiting” characters. If the quoting is not correctly balanced, the parser will fail.
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
      - target_field: parse_key_value($input_field, '=', ' ', '\\', "'")
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
      - target_field: parse_key_value($input_field, '=', ' ', '\\', "'")
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
