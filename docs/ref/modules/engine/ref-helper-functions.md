# Summary

This reference lists every helper function available to decoders, filters and outputs. Check helpers are used in `check` stages and `first_of` branches; map helpers are used in `map` stages (some modify the target field in place).

## Index

### Type

- [exists](#exists) — check
- [is_array](#is_array) — check
- [is_boolean](#is_boolean) — check
- [is_not_array](#is_not_array) — check
- [is_not_boolean](#is_not_boolean) — check
- [is_not_null](#is_not_null) — check
- [is_not_number](#is_not_number) — check
- [is_not_object](#is_not_object) — check
- [is_not_string](#is_not_string) — check
- [is_null](#is_null) — check
- [is_number](#is_number) — check
- [is_object](#is_object) — check
- [is_string](#is_string) — check
- [not_exists](#not_exists) — check

### Comparison

- [int_eq](#int_eq) — check
- [int_gt](#int_gt) — check
- [int_gte](#int_gte) — check
- [int_lt](#int_lt) — check
- [int_lte](#int_lte) — check
- [int_ne](#int_ne) — check
- [number_eq](#number_eq) — check
- [number_gt](#number_gt) — check
- [number_gte](#number_gte) — check
- [number_lt](#number_lt) — check
- [number_lte](#number_lte) — check
- [number_ne](#number_ne) — check
- [string_eq](#string_eq) — check
- [string_gt](#string_gt) — check
- [string_gte](#string_gte) — check
- [string_lt](#string_lt) — check
- [string_lte](#string_lte) — check
- [string_ne](#string_ne) — check

### String

- [concat](#concat) — map
- [concat_any](#concat_any) — map
- [contains](#contains) — check
- [decode_hex](#decode_hex) — map
- [ends_with](#ends_with) — check
- [join](#join) — map
- [lowercase](#lowercase) — map
- [regex_extract](#regex_extract) — map
- [regex_extract_all](#regex_extract_all) — map
- [regex_match](#regex_match) — check
- [regex_not_match](#regex_not_match) — check
- [replace](#replace) — map
- [sha1](#sha1) — map
- [split](#split) — map
- [starts_with](#starts_with) — check
- [trim](#trim) — map
- [trim_end](#trim_end) — map
- [trim_start](#trim_start) — map
- [uppercase](#uppercase) — map

### Array

- [array_append](#array_append) — map
- [array_append_any](#array_append_any) — map
- [array_append_unique](#array_append_unique) — map
- [array_append_unique_any](#array_append_unique_any) — map
- [array_contains_all](#array_contains_all) — check
- [array_contains_any](#array_contains_any) — check
- [array_contains_none](#array_contains_none) — check
- [array_length_eq](#array_length_eq) — check
- [array_to_object](#array_to_object) — map
- [array_to_object_changes](#array_to_object_changes) — map
- [one_of](#one_of) — check

### Object

- [delete](#delete) — map
- [delete_custom_fields](#delete_custom_fields) — map
- [delete_fields_with_value](#delete_fields_with_value) — map
- [has_only_keys](#has_only_keys) — check
- [is_key_of](#is_key_of) — check
- [lookup](#lookup) — map
- [lookup_merge](#lookup_merge) — map
- [merge](#merge) — map
- [rename](#rename) — map
- [snake_case_keys](#snake_case_keys) — map

### Number

- [float_calculate](#float_calculate) — map
- [has_any_bit](#has_any_bit) — check
- [hex_to_int](#hex_to_int) — map
- [int_calculate](#int_calculate) — map
- [to_bool](#to_bool) — map
- [to_int](#to_int) — map
- [to_string](#to_string) — map

### Date

- [date_to_epoch](#date_to_epoch) — map
- [epoch_to_date](#epoch_to_date) — map
- [now](#now) — map
- [now_epoch](#now_epoch) — map

### Network

- [asn](#asn) — map
- [community_id](#community_id) — map
- [geoip](#geoip) — map
- [iana_protocol_name](#iana_protocol_name) — map
- [iana_protocol_number](#iana_protocol_number) — map
- [in_cidr](#in_cidr) — check
- [ip_version](#ip_version) — map
- [is_ipv4](#is_ipv4) — check
- [is_ipv6](#is_ipv6) — check
- [is_public_ip](#is_public_ip) — check

### Syslog

- [syslog_facility](#syslog_facility) — map
- [syslog_severity](#syslog_severity) — map

### KVDB

- [in_kvdb](#in_kvdb) — check
- [kvdb_decode_bitmask](#kvdb_decode_bitmask) — map
- [kvdb_lookup](#kvdb_lookup) — map
- [kvdb_lookup_append](#kvdb_lookup_append) — map
- [kvdb_lookup_merge](#kvdb_lookup_merge) — map
- [not_in_kvdb](#not_in_kvdb) — check

### Parse

- [parse_alphanumeric](#parse_alphanumeric) — map
- [parse_between](#parse_between) — map
- [parse_binary](#parse_binary) — map
- [parse_bool](#parse_bool) — map
- [parse_byte](#parse_byte) — map
- [parse_csv](#parse_csv) — map
- [parse_date](#parse_date) — map
- [parse_double](#parse_double) — map
- [parse_dsv](#parse_dsv) — map
- [parse_file](#parse_file) — map
- [parse_float](#parse_float) — map
- [parse_fqdn](#parse_fqdn) — map
- [parse_half_float](#parse_half_float) — map
- [parse_integer](#parse_integer) — map
- [parse_ip](#parse_ip) — map
- [parse_json](#parse_json) — map
- [parse_kv](#parse_kv) — map
- [parse_long](#parse_long) — map
- [parse_quoted](#parse_quoted) — map
- [parse_short](#parse_short) — map
- [parse_unsigned_long](#parse_unsigned_long) — map
- [parse_uri](#parse_uri) — map
- [parse_xml](#parse_xml) — map

### Event

- [discard_event](#discard_event) — map
- [index_unclassified_events](#index_unclassified_events) — check

# exists

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: exists($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the target field exists in the event.

Behavior:
- True when the target path resolves to any JSON value: `null`, `""`, `0`, `false`, `[]` and `{}` all
  count as existing values.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- A field holding `null` exists; use `is_not_null` to also require a non-null value.
- `not_exists` is the exact complement of this helper.


## Fails when

- The target field does not exist in the event.

## Examples

### Example 1

The target field exists with a number value.

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

### Example 2

The target field exists with a string value.

#### Asset

```yaml
check:
  - target_field: exists()
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 3

The target field exists with a boolean value.

#### Asset

```yaml
check:
  - target_field: exists()
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was successful*

### Example 4

The target field exists with an object value.

#### Asset

```yaml
check:
  - target_field: exists()
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
# is_array

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_array($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether the target field holds a JSON array.

Behavior:
- True when the target exists and its JSON type is array; the array may be empty.
- A missing target gives false.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `array_length_eq` additionally checks the number of elements.
- `is_not_array` is not the negation of this helper: both are false for a missing field.


## Fails when

- The target field does not exist.
- The target field is not an array.

## Examples

### Example 1

The target field is an array.

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

The target field is a boolean, not an array.

#### Asset

```yaml
check:
  - target_field: is_array()
```

#### Input Event

```json
{
  "target_field": false
}
```

*The check was performed with errors*

### Example 3

The target field is a string, not an array.

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

### Example 4

The target field is an object, not an array.

#### Asset

```yaml
check:
  - target_field: is_array()
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
# is_boolean

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_boolean($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Checks whether the target field holds a JSON boolean.

Behavior:
- True when the target exists and its value is the JSON literal `true` or `false`.
- The strings `"true"` and `"false"` are not booleans.
- A missing target gives false.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `is_not_boolean` is not the negation of this helper: both are false for a missing field.


## Fails when

- The target field does not exist.
- The target field is not a boolean.

## Examples

### Example 1

The target field is the boolean true.

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

The target field is the boolean false.

#### Asset

```yaml
check:
  - target_field: is_boolean()
```

#### Input Event

```json
{
  "target_field": false
}
```

*The check was successful*

### Example 3

The target field is the string "false", not a boolean.

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

### Example 4

The target field is a number, not a boolean.

#### Asset

```yaml
check:
  - target_field: is_boolean()
```

#### Input Event

```json
{
  "target_field": 1
}
```

*The check was performed with errors*



---
# is_not_array

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_not_array($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, boolean, object, string] | - |


## Description

Checks whether the target field exists and does not hold a JSON array.

Behavior:
- True when the target exists and its JSON type is anything but array; `null` counts as "not an array".
- A missing target gives false, so this is not the same as `NOT is_array(...)`, which is true for a
  missing field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- Use `exists` or `not_exists` to decide about a missing field explicitly.


## Fails when

- The target field does not exist.
- The target field is an array.

## Examples

### Example 1

The target field is an array.

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

The target field is a number, not an array.

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

The target field is an object, not an array.

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

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_not_boolean($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, array, object, string] | - |


## Description

Checks whether the target field exists and does not hold a JSON boolean.

Behavior:
- True when the target exists and its value is neither the JSON literal `true` nor `false`; `null` and
  the strings `"true"` and `"false"` count as "not a boolean".
- A missing target gives false, so this is not the same as `NOT is_boolean(...)`, which is true for a
  missing field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- Use `exists` or `not_exists` to decide about a missing field explicitly.


## Fails when

- The target field does not exist.
- The target field is a boolean.

## Examples

### Example 1

The target field is a boolean.

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

The target field is a number, not a boolean.

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

The target field is an object, not a boolean.

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

### Example 4

The string "true" is not a boolean.

#### Asset

```yaml
check:
  - target_field: is_not_boolean()
```

#### Input Event

```json
{
  "target_field": "true"
}
```

*The check was successful*



---
# is_not_null

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_not_null($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the target field exists and holds a value other than `null`.

Behavior:
- True when the target exists and its value is not the JSON literal `null`; `""`, `0`, `false`, `[]` and
  `{}` all qualify.
- A missing target gives false, so this is not the same as `NOT is_null(...)`, which is true for a
  missing field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `exists` also accepts a null value; this helper is the stricter check.


## Fails when

- The target field does not exist.
- The target field is null.

## Examples

### Example 1

The target field is present with the value null.

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

### Example 2

A string value is not null.

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

### Example 3

The number 0 is not null.

#### Asset

```yaml
check:
  - target_field: is_not_null()
```

#### Input Event

```json
{
  "target_field": 0
}
```

*The check was successful*

### Example 4

A boolean value is not null.

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

### Example 5

An array value is not null.

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

### Example 6

An object value is not null.

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



---
# is_not_number

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_not_number($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [string, boolean, array, object] | - |


## Description

Checks whether the target field exists and does not hold a JSON number.

Behavior:
- True when the target exists and its JSON type is anything but number; `null` and a string holding
  digits count as "not a number".
- A missing target gives false, so this is not the same as `NOT is_number(...)`, which is true for a
  missing field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- Integers and floating-point values are both numbers.


## Fails when

- The target field does not exist.
- The target field is a number.

## Examples

### Example 1

The target field is a string, not a number.

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

The target field is a boolean, not a number.

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

The target field is an array, not a number.

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

The target field is an object, not a number.

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

The target field is an integer.

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{
  "target_field": 0
}
```

*The check was performed with errors*

### Example 6

The target field is a floating-point number.

#### Asset

```yaml
check:
  - target_field: is_not_number()
```

#### Input Event

```json
{
  "target_field": 2.5
}
```

*The check was performed with errors*



---
# is_not_object

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_not_object($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, array, string, boolean] | - |


## Description

Checks whether the target field exists and does not hold a JSON object.

Behavior:
- True when the target exists and its JSON type is anything but object; `null` counts as "not an object".
- A missing target gives false, so this is not the same as `NOT is_object(...)`, which is true for a
  missing field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- Use `exists` or `not_exists` to decide about a missing field explicitly.


## Fails when

- The target field does not exist.
- The target field is an object.

## Examples

### Example 1

The target field is an object.

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

The target field is a number, not an object.

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

The target field is an array, not an object.

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

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_not_string($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, array, object, boolean] | - |


## Description

Checks whether the target field exists and does not hold a JSON string.

Behavior:
- True when the target exists and its JSON type is anything but string; `null` counts as "not a string".
- A missing target gives false, so this is not the same as `NOT is_string(...)`, which is true for a
  missing field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- Use `exists` or `not_exists` to decide about a missing field explicitly.


## Fails when

- The target field does not exist.
- The target field is a string.

## Examples

### Example 1

The target field is an object, not a string.

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

The target field is an array, not a string.

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

The target field is a string.

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

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_null($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the target field is present with the value `null`.

Behavior:
- True only when the target exists and its value is the JSON literal `null`.
- A missing target gives false: an absent field is not a null field.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `not_exists` is the check for an absent field.
- `is_not_null` is not the negation of this helper: both are false for a missing field.


## Fails when

- The target field does not exist.
- The target field holds a value other than null.

## Examples

### Example 1

The target field is present with the value null.

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{}
```

*The check was successful*

### Example 2

The target field is a string, not null.

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

The target field is a number, not null.

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{
  "target_field": 0
}
```

*The check was performed with errors*

### Example 4

The target field is a boolean, not null.

#### Asset

```yaml
check:
  - target_field: is_null()
```

#### Input Event

```json
{
  "target_field": false
}
```

*The check was performed with errors*

### Example 5

The target field is an object, not null.

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

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_number($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target field holds a JSON number.

Behavior:
- True when the target exists and its JSON type is number: integers and floating-point values both qualify.
- A string holding digits is not a number.
- A missing target gives false.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- There is no integer-only type check; the `int_*` comparisons are the only helpers that tell `2` from `2.0`.
- `is_not_number` is not the negation of this helper: both are false for a missing field.


## Fails when

- The target field does not exist.
- The target field is not a number.

## Examples

### Example 1

The target field is an object, not a number.

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

The target field is an array, not a number.

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

The target field is a string, not a number.

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

A string holding digits is not a number.

#### Asset

```yaml
check:
  - target_field: is_number()
```

#### Input Event

```json
{
  "target_field": "23"
}
```

*The check was performed with errors*

### Example 5

The target field is a boolean, not a number.

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

### Example 6

The target field is an integer.

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

### Example 7

The target field is a floating-point number.

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

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_object($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Checks whether the target field holds a JSON object.

Behavior:
- True when the target exists and its JSON type is object.
- A missing target gives false.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `has_only_keys` additionally restricts the keys an object may carry.
- `is_not_object` is not the negation of this helper: both are false for a missing field.


## Fails when

- The target field does not exist.
- The target field is not an object.

## Examples

### Example 1

The target field is an object.

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

The target field is an array, not an object.

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

The target field is a string, not an object.

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

### Example 4

The target field is a number, not an object.

#### Asset

```yaml
check:
  - target_field: is_object()
```

#### Input Event

```json
{
  "target_field": 7
}
```

*The check was performed with errors*



---
# is_string

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_string($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target field holds a JSON string.

Behavior:
- True when the target exists and its JSON type is string; the string may be empty.
- A missing target gives false.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `is_not_string` is not the negation of this helper: both are false for a missing field.


## Fails when

- The target field does not exist.
- The target field is not a string.

## Examples

### Example 1

The target field is an object, not a string.

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

The target field is an array, not a string.

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

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: is_string()
```

#### Input Event

```json
{
  "target_field": 42
}
```

*The check was performed with errors*

### Example 4

The target field is a string.

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

### Example 5

An empty string is a string.

#### Asset

```yaml
check:
  - target_field: is_string()
```

#### Input Event

```json
{
  "target_field": ""
}
```

*The check was successful*



---
# not_exists

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: not_exists($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the target field is absent from the event.

Behavior:
- True only when the target path does not resolve to any value.
- A field holding `null` exists, so the check is false for it.
- No arguments are accepted.

Build errors:
- The target is neither a schema field nor a temporary field rooted at `_`.
- Any argument is given.

Notes:
- `exists` is the exact complement of this helper.
- `is_null` requires the field to be present with a null value; `not_exists` requires it to be absent.


## Fails when

- The target field exists in the event, whatever its value (null included).

## Examples

### Example 1

The field exists with a string value.

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

The field exists with a number value.

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{
  "target_field": 0
}
```

*The check was performed with errors*

### Example 3

The field exists with an array value.

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

The field exists with an object value.

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

The field exists with a boolean value.

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

The target field is absent from the event (the test harness leaves an empty array unmapped).

#### Asset

```yaml
check:
  - target_field: not_exists()
```

#### Input Event

```json
{
  "target_field": []
}
```

*The check was successful*



---
# int_eq

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: int_eq($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks whether the target integer is equal to `value`, as exact 64-bit integers.

Behavior:
- The target must hold a JSON integer; a floating-point value, even `2.0`, is not an integer and gives
  false.
- `value` is a literal integer or a reference to an integer field; the comparison is exact, so no
  precision is lost above 2^53.
- Values above 2^63-1 are not 64-bit integers and give false.

Build errors:
- `value` is a literal that is not an integer: a floating-point number (`2.0`), a quoted number, a boolean,
  null or a value above 2^63-1.
- `value` is a reference to a schema field whose type is not an integer type (`integer`, `long`, `short`
  or `byte`).
- The target is a schema field whose type is not numeric.

Notes:
- `number_eq` converts both operands to double and treats `2` and `2.0` as equal.
- The comparison operators (`!=`, `>`, `>=`, `<`, `<=`) map to the `number_*` helpers for a numeric literal
  and to the `string_*` helpers for a string literal, never to the `int_*` ones.
- `int_ne` is not the negation of this helper: both are false for a missing or non-integer target.


## Fails when

- The target field does not exist.
- The target field is not an integer (a floating-point value such as `2.0` included).
- The reference given as `value` does not exist or is not an integer.
- The two integers differ.

## Examples

### Example 1

The two integers differ.

#### Asset

```yaml
check:
  - target_field: int_eq(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

The two integers are equal.

#### Asset

```yaml
check:
  - target_field: int_eq($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 22
}
```

*The check was successful*

### Example 3

A floating-point target is not an integer, even without a fractional part.

#### Asset

```yaml
check:
  - target_field: int_eq(2)
```

#### Input Event

```json
{
  "target_field": 2.0
}
```

*The check was performed with errors*

### Example 4

The target field is a string, not an integer.

#### Asset

```yaml
check:
  - target_field: int_eq($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": "2"
}
```

*The check was performed with errors*

### Example 5

A floating-point literal is rejected at build time.

#### Asset

```yaml
check:
  - target_field: int_eq(2.5)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*



---
# int_gt

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: int_gt($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks whether the target integer is greater than `value`, as exact 64-bit integers.

Behavior:
- The target must hold a JSON integer; a floating-point value, even `2.0`, is not an integer and gives
  false.
- `value` is a literal integer or a reference to an integer field; the comparison is exact, so no
  precision is lost above 2^53.
- Values above 2^63-1 are not 64-bit integers and give false.

Build errors:
- `value` is a literal that is not an integer: a floating-point number (`2.0`), a quoted number, a boolean,
  null or a value above 2^63-1.
- `value` is a reference to a schema field whose type is not an integer type (`integer`, `long`, `short`
  or `byte`).
- The target is a schema field whose type is not numeric.

Notes:
- `number_gt` converts both operands to double and also accepts floating-point values.
- The `>` operator with a numeric literal maps to `number_gt`, never to this helper.


## Fails when

- The target field does not exist.
- The target field is not an integer (a floating-point value such as `2.0` included).
- The reference given as `value` does not exist or is not an integer.
- The target integer is less than or equal to `value`.

## Examples

### Example 1

The target integer is greater than the value.

#### Asset

```yaml
check:
  - target_field: int_gt(1)
```

#### Input Event

```json
{
  "target_field": 100
}
```

*The check was successful*

### Example 2

The target integer is less than the value.

#### Asset

```yaml
check:
  - target_field: int_gt($value)
```

#### Input Event

```json
{
  "value": 50,
  "target_field": 20
}
```

*The check was performed with errors*

### Example 3

Equal integers are not greater.

#### Asset

```yaml
check:
  - target_field: int_gt(1000)
```

#### Input Event

```json
{
  "target_field": 1000
}
```

*The check was performed with errors*

### Example 4

A floating-point target is not an integer, so the check fails although it is greater.

#### Asset

```yaml
check:
  - target_field: int_gt($value)
```

#### Input Event

```json
{
  "value": 1,
  "target_field": 100.0
}
```

*The check was performed with errors*



---
# int_gte

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: int_gte($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks whether the target integer is greater than or equal to `value`, as exact 64-bit integers.

Behavior:
- The target must hold a JSON integer; a floating-point value, even `2.0`, is not an integer and gives
  false.
- `value` is a literal integer or a reference to an integer field; the comparison is exact, so no
  precision is lost above 2^53.
- Values above 2^63-1 are not 64-bit integers and give false.

Build errors:
- `value` is a literal that is not an integer: a floating-point number (`2.0`), a quoted number, a boolean,
  null or a value above 2^63-1.
- `value` is a reference to a schema field whose type is not an integer type (`integer`, `long`, `short`
  or `byte`).
- The target is a schema field whose type is not numeric.

Notes:
- `number_gte` converts both operands to double and also accepts floating-point values.
- The `>=` operator with a numeric literal maps to `number_gte`, never to this helper.
- Not the negation of `int_lt`: both are false for a missing or non-integer target.


## Fails when

- The target field does not exist.
- The target field is not an integer (a floating-point value such as `2.0` included).
- The reference given as `value` does not exist or is not an integer.
- The target integer is less than `value`.

## Examples

### Example 1

The target integer is less than the value.

#### Asset

```yaml
check:
  - target_field: int_gte(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

Equal integers satisfy the check.

#### Asset

```yaml
check:
  - target_field: int_gte($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 22
}
```

*The check was successful*

### Example 3

The target integer is greater than the value.

#### Asset

```yaml
check:
  - target_field: int_gte(2)
```

#### Input Event

```json
{
  "target_field": 22
}
```

*The check was successful*

### Example 4

A floating-point target is not an integer, so the check fails although the values are equal.

#### Asset

```yaml
check:
  - target_field: int_gte($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 22.0
}
```

*The check was performed with errors*



---
# int_lt

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: int_lt($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks whether the target integer is less than `value`, as exact 64-bit integers.

Behavior:
- The target must hold a JSON integer; a floating-point value, even `2.0`, is not an integer and gives
  false.
- `value` is a literal integer or a reference to an integer field; the comparison is exact, so no
  precision is lost above 2^53.
- Values above 2^63-1 are not 64-bit integers and give false.

Build errors:
- `value` is a literal that is not an integer: a floating-point number (`2.0`), a quoted number, a boolean,
  null or a value above 2^63-1.
- `value` is a reference to a schema field whose type is not an integer type (`integer`, `long`, `short`
  or `byte`).
- The target is a schema field whose type is not numeric.

Notes:
- `number_lt` converts both operands to double and also accepts floating-point values.
- The `<` operator with a numeric literal maps to `number_lt`, never to this helper.


## Fails when

- The target field does not exist.
- The target field is not an integer (a floating-point value such as `2.0` included).
- The reference given as `value` does not exist or is not an integer.
- The target integer is greater than or equal to `value`.

## Examples

### Example 1

The target integer is less than the value.

#### Asset

```yaml
check:
  - target_field: int_lt(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

The target integer is greater than the value.

#### Asset

```yaml
check:
  - target_field: int_lt($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 22
}
```

*The check was performed with errors*

### Example 3

Equal integers are not less.

#### Asset

```yaml
check:
  - target_field: int_lt(100)
```

#### Input Event

```json
{
  "target_field": 100
}
```

*The check was performed with errors*

### Example 4

A floating-point target is not an integer, so the check fails although it is less.

#### Asset

```yaml
check:
  - target_field: int_lt($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 2.0
}
```

*The check was performed with errors*



---
# int_lte

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: int_lte($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks whether the target integer is less than or equal to `value`, as exact 64-bit integers.

Behavior:
- The target must hold a JSON integer; a floating-point value, even `2.0`, is not an integer and gives
  false.
- `value` is a literal integer or a reference to an integer field; the comparison is exact, so no
  precision is lost above 2^53.
- Values above 2^63-1 are not 64-bit integers and give false.

Build errors:
- `value` is a literal that is not an integer: a floating-point number (`2.0`), a quoted number, a boolean,
  null or a value above 2^63-1.
- `value` is a reference to a schema field whose type is not an integer type (`integer`, `long`, `short`
  or `byte`).
- The target is a schema field whose type is not numeric.

Notes:
- `number_lte` converts both operands to double and also accepts floating-point values.
- The `<=` operator with a numeric literal maps to `number_lte`, never to this helper.
- Not the negation of `int_gt`: both are false for a missing or non-integer target.


## Fails when

- The target field does not exist.
- The target field is not an integer (a floating-point value such as `2.0` included).
- The reference given as `value` does not exist or is not an integer.
- The target integer is greater than `value`.

## Examples

### Example 1

The target integer is less than the value.

#### Asset

```yaml
check:
  - target_field: int_lte(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

Equal integers satisfy the check.

#### Asset

```yaml
check:
  - target_field: int_lte($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 22
}
```

*The check was successful*

### Example 3

The target integer is greater than the value.

#### Asset

```yaml
check:
  - target_field: int_lte(2)
```

#### Input Event

```json
{
  "target_field": 22
}
```

*The check was performed with errors*

### Example 4

A floating-point target is not an integer, so the check fails although the values are equal.

#### Asset

```yaml
check:
  - target_field: int_lte($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 22.0
}
```

*The check was performed with errors*



---
# int_ne

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: int_ne($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks whether the target integer differs from `value`, as exact 64-bit integers.

Behavior:
- The target must hold a JSON integer; a floating-point value, even `2.0`, is not an integer and gives
  false.
- `value` is a literal integer or a reference to an integer field; the comparison is exact, so no
  precision is lost above 2^53.
- A missing or non-integer target gives false, so this is not the same as `NOT int_eq(...)`, which is
  true for a missing field.

Build errors:
- `value` is a literal that is not an integer: a floating-point number (`2.0`), a quoted number, a boolean,
  null or a value above 2^63-1.
- `value` is a reference to a schema field whose type is not an integer type (`integer`, `long`, `short`
  or `byte`).
- The target is a schema field whose type is not numeric.

Notes:
- `number_ne` converts both operands to double and treats `2` and `2.0` as equal.
- The `!=` operator with a numeric literal maps to `number_ne`, never to this helper.


## Fails when

- The target field does not exist.
- The target field is not an integer (a floating-point value such as `2.0` included).
- The reference given as `value` does not exist or is not an integer.
- The two integers are equal.

## Examples

### Example 1

The two integers differ.

#### Asset

```yaml
check:
  - target_field: int_ne(22)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

The two integers are equal.

#### Asset

```yaml
check:
  - target_field: int_ne($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": 22
}
```

*The check was performed with errors*

### Example 3

A floating-point target is not an integer, so the check fails although the values differ.

#### Asset

```yaml
check:
  - target_field: int_ne(22)
```

#### Input Event

```json
{
  "target_field": 2.0
}
```

*The check was performed with errors*

### Example 4

The target field is a string, not an integer, so the check fails although the values differ.

#### Asset

```yaml
check:
  - target_field: int_ne($value)
```

#### Input Event

```json
{
  "value": 22,
  "target_field": "2"
}
```

*The check was performed with errors*



---
# number_eq

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: number_eq($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Any number |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target number is equal to `value`.

Behavior:
- Both operands are converted to double before the comparison, so `2` equals `2.0`.
- `value` is a literal integer or floating-point number, or a reference to a numeric field.
- Integers above 2^53 lose precision in the conversion: `9007199254740993` compares equal to
  `9007199254740992`.

Build errors:
- `value` is a literal that is not a number (a quoted number, a boolean or null), or an integer above 2^63-1.
- `value` is a reference to a schema field whose type is not numeric.
- The target is a schema field whose type is not numeric.

Notes:
- `int_eq` compares exact 64-bit integers and tells `2` from `2.0`.
- `one_of` compares the target against several candidates with the same numeric equality.
- `number_ne` is not the negation of this helper: both are false for a missing or non-number target.


## Fails when

- The target field does not exist.
- The target field is not a number, or is an integer above 2^63-1.
- The reference given as `value` does not exist or is not a number.
- The two numbers differ.

## Examples

### Example 1

The two numbers differ.

#### Asset

```yaml
check:
  - target_field: number_eq(2.6)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

The two numbers differ.

#### Asset

```yaml
check:
  - target_field: number_eq($value)
```

#### Input Event

```json
{
  "value": 6,
  "target_field": 5.5
}
```

*The check was performed with errors*

### Example 3

The two floating-point numbers are equal.

#### Asset

```yaml
check:
  - target_field: number_eq(2.3)
```

#### Input Event

```json
{
  "target_field": 2.3
}
```

*The check was successful*

### Example 4

An integer and a floating-point number with the same value are equal.

#### Asset

```yaml
check:
  - target_field: number_eq($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 2.0
}
```

*The check was successful*

### Example 5

The target field is a string, not a number.

#### Asset

```yaml
check:
  - target_field: number_eq(2)
```

#### Input Event

```json
{
  "target_field": "2"
}
```

*The check was performed with errors*



---
# number_gt

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: number_gt($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Any number |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target number is greater than `value`.

Behavior:
- Both operands are converted to double before the comparison, so integers and floating-point numbers can
  be mixed freely.
- `value` is a literal integer or floating-point number, or a reference to a numeric field.
- Integers above 2^53 lose precision in the conversion: `9007199254740993` compares equal to
  `9007199254740992`.

Build errors:
- `value` is a literal that is not a number (a quoted number, a boolean or null), or an integer above 2^63-1.
- `value` is a reference to a schema field whose type is not numeric.
- The target is a schema field whose type is not numeric.

Notes:
- The `>` operator with a numeric literal (`$field > 5`) maps to this helper.
- `int_gt` compares exact 64-bit integers.


## Fails when

- The target field does not exist.
- The target field is not a number, or is an integer above 2^63-1.
- The reference given as `value` does not exist or is not a number.
- The target number is less than or equal to `value`.

## Examples

### Example 1

The target number is greater than the value.

#### Asset

```yaml
check:
  - target_field: number_gt(1.5)
```

#### Input Event

```json
{
  "target_field": 4.6
}
```

*The check was successful*

### Example 2

A floating-point target is greater than an integer value.

#### Asset

```yaml
check:
  - target_field: number_gt($value)
```

#### Input Event

```json
{
  "value": 1,
  "target_field": 2.2
}
```

*The check was successful*

### Example 3

The target number is less than the value.

#### Asset

```yaml
check:
  - target_field: number_gt(3.8)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was performed with errors*

### Example 4

Equal numbers are not greater.

#### Asset

```yaml
check:
  - target_field: number_gt($value)
```

#### Input Event

```json
{
  "value": 3,
  "target_field": 3
}
```

*The check was performed with errors*

### Example 5

The target field is a string, not a number.

#### Asset

```yaml
check:
  - target_field: number_gt(3)
```

#### Input Event

```json
{
  "target_field": "5"
}
```

*The check was performed with errors*



---
# number_gte

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: number_gte($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Any number |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target number is greater than or equal to `value`.

Behavior:
- Both operands are converted to double before the comparison, so integers and floating-point numbers can
  be mixed freely and `2` equals `2.0`.
- `value` is a literal integer or floating-point number, or a reference to a numeric field.
- Integers above 2^53 lose precision in the conversion: `9007199254740993` compares equal to
  `9007199254740992`.

Build errors:
- `value` is a literal that is not a number (a quoted number, a boolean or null), or an integer above 2^63-1.
- `value` is a reference to a schema field whose type is not numeric.
- The target is a schema field whose type is not numeric.

Notes:
- The `>=` operator with a numeric literal (`$field >= 5`) maps to this helper.
- `int_gte` compares exact 64-bit integers.
- Not the negation of `number_lt`: both are false for a missing or non-number target.


## Fails when

- The target field does not exist.
- The target field is not a number, or is an integer above 2^63-1.
- The reference given as `value` does not exist or is not a number.
- The target number is less than `value`.

## Examples

### Example 1

The target number is less than the value.

#### Asset

```yaml
check:
  - target_field: number_gte(2.6)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 2

The target number is less than the value.

#### Asset

```yaml
check:
  - target_field: number_gte($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 1.5
}
```

*The check was performed with errors*

### Example 3

Equal floating-point numbers satisfy the check.

#### Asset

```yaml
check:
  - target_field: number_gte(2.2)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was successful*

### Example 4

Equal integers satisfy the check.

#### Asset

```yaml
check:
  - target_field: number_gte($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 2
}
```

*The check was successful*

### Example 5

An integer and a floating-point number with the same value are equal.

#### Asset

```yaml
check:
  - target_field: number_gte(2)
```

#### Input Event

```json
{
  "target_field": 2.0
}
```

*The check was successful*

### Example 6

The target field is a string, not a number.

#### Asset

```yaml
check:
  - target_field: number_gte($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": "5"
}
```

*The check was performed with errors*



---
# number_lt

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: number_lt($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Any number |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target number is less than `value`.

Behavior:
- Both operands are converted to double before the comparison, so integers and floating-point numbers can
  be mixed freely.
- `value` is a literal integer or floating-point number, or a reference to a numeric field.
- Integers above 2^53 lose precision in the conversion: `9007199254740993` compares equal to
  `9007199254740992`.

Build errors:
- `value` is a literal that is not a number (a quoted number, a boolean or null), or an integer above 2^63-1.
- `value` is a reference to a schema field whose type is not numeric.
- The target is a schema field whose type is not numeric.

Notes:
- The `<` operator with a numeric literal (`$field < 5`) maps to this helper.
- `int_lt` compares exact 64-bit integers.


## Fails when

- The target field does not exist.
- The target field is not a number, or is an integer above 2^63-1.
- The reference given as `value` does not exist or is not a number.
- The target number is greater than or equal to `value`.

## Examples

### Example 1

An integer target is less than a floating-point value.

#### Asset

```yaml
check:
  - target_field: number_lt(2.2)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

The target number is less than the value.

#### Asset

```yaml
check:
  - target_field: number_lt($value)
```

#### Input Event

```json
{
  "value": 2.1,
  "target_field": 1.6
}
```

*The check was successful*

### Example 3

The target number is greater than the value.

#### Asset

```yaml
check:
  - target_field: number_lt(2)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was performed with errors*

### Example 4

Equal numbers are not less.

#### Asset

```yaml
check:
  - target_field: number_lt($value)
```

#### Input Event

```json
{
  "value": 10,
  "target_field": 10
}
```

*The check was performed with errors*

### Example 5

The target field is a string, not a number.

#### Asset

```yaml
check:
  - target_field: number_lt(10)
```

#### Input Event

```json
{
  "target_field": "5"
}
```

*The check was performed with errors*



---
# number_lte

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: number_lte($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Any number |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target number is less than or equal to `value`.

Behavior:
- Both operands are converted to double before the comparison, so integers and floating-point numbers can
  be mixed freely and `2` equals `2.0`.
- `value` is a literal integer or floating-point number, or a reference to a numeric field.
- Integers above 2^53 lose precision in the conversion: `9007199254740993` compares equal to
  `9007199254740992`.

Build errors:
- `value` is a literal that is not a number (a quoted number, a boolean or null), or an integer above 2^63-1.
- `value` is a reference to a schema field whose type is not numeric.
- The target is a schema field whose type is not numeric.

Notes:
- The `<=` operator with a numeric literal (`$field <= 5`) maps to this helper.
- `int_lte` compares exact 64-bit integers.
- Not the negation of `number_gt`: both are false for a missing or non-number target.


## Fails when

- The target field does not exist.
- The target field is not a number, or is an integer above 2^63-1.
- The reference given as `value` does not exist or is not a number.
- The target number is greater than `value`.

## Examples

### Example 1

The target number is less than the value.

#### Asset

```yaml
check:
  - target_field: number_lte(2.2)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

The target number is less than the value.

#### Asset

```yaml
check:
  - target_field: number_lte($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 1.2
}
```

*The check was successful*

### Example 3

The target number is greater than the value.

#### Asset

```yaml
check:
  - target_field: number_lte(1.8)
```

#### Input Event

```json
{
  "target_field": 2.6
}
```

*The check was performed with errors*

### Example 4

The target number is greater than the value.

#### Asset

```yaml
check:
  - target_field: number_lte($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 22
}
```

*The check was performed with errors*

### Example 5

An integer and a floating-point number with the same value are equal.

#### Asset

```yaml
check:
  - target_field: number_lte(2)
```

#### Input Event

```json
{
  "target_field": 2.0
}
```

*The check was successful*

### Example 6

The target field is a string, not a number.

#### Asset

```yaml
check:
  - target_field: number_lte($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": "1"
}
```

*The check was performed with errors*



---
# number_ne

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: number_ne($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | value or reference | Any number |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Checks whether the target number differs from `value`.

Behavior:
- Both operands are converted to double before the comparison, so `2` and `2.0` are equal and the check
  fails for them.
- `value` is a literal integer or floating-point number, or a reference to a numeric field.
- Integers above 2^53 lose precision in the conversion: `9007199254740993` compares equal to
  `9007199254740992`.
- A missing or non-number target gives false, so this is not the same as `NOT number_eq(...)`, which is
  true for a missing field.

Build errors:
- `value` is a literal that is not a number (a quoted number, a boolean or null), or an integer above 2^63-1.
- `value` is a reference to a schema field whose type is not numeric.
- The target is a schema field whose type is not numeric.

Notes:
- The `!=` operator with a numeric literal (`$field != 5`) maps to this helper.
- `int_ne` compares exact 64-bit integers and tells `2` from `2.0`.


## Fails when

- The target field does not exist.
- The target field is not a number, or is an integer above 2^63-1.
- The reference given as `value` does not exist or is not a number.
- The two numbers are equal.

## Examples

### Example 1

The two numbers differ.

#### Asset

```yaml
check:
  - target_field: number_ne(2.2)
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was successful*

### Example 2

The two numbers differ.

#### Asset

```yaml
check:
  - target_field: number_ne($value)
```

#### Input Event

```json
{
  "value": 1,
  "target_field": 2.3
}
```

*The check was successful*

### Example 3

The two floating-point numbers are equal.

#### Asset

```yaml
check:
  - target_field: number_ne(2.2)
```

#### Input Event

```json
{
  "target_field": 2.2
}
```

*The check was performed with errors*

### Example 4

The two integers are equal.

#### Asset

```yaml
check:
  - target_field: number_ne($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": 2
}
```

*The check was performed with errors*

### Example 5

An integer and a floating-point number with the same value are equal, so the check fails.

#### Asset

```yaml
check:
  - target_field: number_ne(2)
```

#### Input Event

```json
{
  "target_field": 2.0
}
```

*The check was performed with errors*

### Example 6

The target field is a string, not a number, so the check fails although the values differ.

#### Asset

```yaml
check:
  - target_field: number_ne($value)
```

#### Input Event

```json
{
  "value": 2,
  "target_field": "3"
}
```

*The check was performed with errors*



---
# string_eq

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: string_eq($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is equal to `value`, byte for byte.

Behavior:
- Both operands must be strings; they are compared byte by byte, so the comparison is case-sensitive and
  applies no locale or Unicode normalization.
- `value` is a literal string or a reference to a string field.

Build errors:
- `value` is a literal that is not a string: write `'404'`, not `404`.
- `value` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- `one_of` compares the target against several candidates at once.
- `string_ne` is not the negation of this helper: both are false for a missing or non-string target.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `value` does not exist or is not a string.
- The two strings differ.

## Examples

### Example 1

The two strings differ.

#### Asset

```yaml
check:
  - target_field: string_eq('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was performed with errors*

### Example 2

The two strings are equal.

#### Asset

```yaml
check:
  - target_field: string_eq($value)
```

#### Input Event

```json
{
  "value": "hello world!",
  "target_field": "hello world!"
}
```

*The check was successful*

### Example 3

The comparison is case-sensitive.

#### Asset

```yaml
check:
  - target_field: string_eq('Hello World!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was performed with errors*

### Example 4

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: string_eq($value)
```

#### Input Event

```json
{
  "value": "404",
  "target_field": 404
}
```

*The check was performed with errors*



---
# string_gt

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: string_gt($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is greater than `value` in byte-wise lexicographic order.

Behavior:
- Both operands must be strings; they are compared byte by byte as unsigned values (UTF-8 code-unit order),
  case-sensitively and without locale: `"Z"` sorts before `"a"`, `"10"` before `"9"` and `"ab"` before `"abc"`.
- `value` is a literal string or a reference to a string field.

Build errors:
- `value` is a literal that is not a string: write `'9'`, not `9`.
- `value` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- The `>` operator with a string literal (`$field > 'x'`) maps to this helper.
- Use `number_gt` or `int_gt` to compare numbers; strings are never compared numerically.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `value` does not exist or is not a string.
- The target string is less than or equal to `value`.

## Examples

### Example 1

The target string sorts after the value.

#### Asset

```yaml
check:
  - target_field: string_gt('hello world!')
```

#### Input Event

```json
{
  "target_field": "wazuh"
}
```

*The check was successful*

### Example 2

The target string sorts before the value.

#### Asset

```yaml
check:
  - target_field: string_gt($value)
```

#### Input Event

```json
{
  "value": "wazuh",
  "target_field": "hello world!"
}
```

*The check was performed with errors*

### Example 3

Equal strings are not greater.

#### Asset

```yaml
check:
  - target_field: string_gt('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was performed with errors*

### Example 4

Strings are not compared numerically, so "10" sorts before "9".

#### Asset

```yaml
check:
  - target_field: string_gt($value)
```

#### Input Event

```json
{
  "value": "9",
  "target_field": "10"
}
```

*The check was performed with errors*

### Example 5

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: string_gt('abc')
```

#### Input Event

```json
{
  "target_field": 123
}
```

*The check was performed with errors*



---
# string_gte

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: string_gte($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is greater than or equal to `value` in byte-wise lexicographic order.

Behavior:
- Both operands must be strings; they are compared byte by byte as unsigned values (UTF-8 code-unit order),
  case-sensitively and without locale: `"Z"` sorts before `"a"`, `"10"` before `"9"` and `"ab"` before `"abc"`.
- `value` is a literal string or a reference to a string field.

Build errors:
- `value` is a literal that is not a string: write `'9'`, not `9`.
- `value` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- The `>=` operator with a string literal (`$field >= 'x'`) maps to this helper.
- Not the negation of `string_lt`: both are false for a missing or non-string target.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `value` does not exist or is not a string.
- The target string is less than `value`.

## Examples

### Example 1

Equal strings satisfy the check.

#### Asset

```yaml
check:
  - target_field: string_gte('hello')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 2

The target string sorts after the value.

#### Asset

```yaml
check:
  - target_field: string_gte($value)
```

#### Input Event

```json
{
  "value": "hello",
  "target_field": "world"
}
```

*The check was successful*

### Example 3

The target string sorts before the value.

#### Asset

```yaml
check:
  - target_field: string_gte('def')
```

#### Input Event

```json
{
  "target_field": "abc"
}
```

*The check was performed with errors*

### Example 4

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: string_gte($value)
```

#### Input Event

```json
{
  "value": "abc",
  "target_field": 123
}
```

*The check was performed with errors*



---
# string_lt

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: string_lt($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is less than `value` in byte-wise lexicographic order.

Behavior:
- Both operands must be strings; they are compared byte by byte as unsigned values (UTF-8 code-unit order),
  case-sensitively and without locale: `"Z"` sorts before `"a"`, `"10"` before `"9"` and `"ab"` before `"abc"`.
- `value` is a literal string or a reference to a string field.

Build errors:
- `value` is a literal that is not a string: write `'9'`, not `9`.
- `value` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- The `<` operator with a string literal (`$field < 'x'`) maps to this helper.
- Use `number_lt` or `int_lt` to compare numbers; strings are never compared numerically.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `value` does not exist or is not a string.
- The target string is greater than or equal to `value`.

## Examples

### Example 1

The target string sorts before the value.

#### Asset

```yaml
check:
  - target_field: string_lt('wazuh')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was successful*

### Example 2

The target string sorts after the value.

#### Asset

```yaml
check:
  - target_field: string_lt($value)
```

#### Input Event

```json
{
  "value": "hello world!",
  "target_field": "wazuh"
}
```

*The check was performed with errors*

### Example 3

Equal strings are not less.

#### Asset

```yaml
check:
  - target_field: string_lt('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was performed with errors*

### Example 4

Strings are not compared numerically, so "9" does not sort before "10".

#### Asset

```yaml
check:
  - target_field: string_lt($value)
```

#### Input Event

```json
{
  "value": "10",
  "target_field": "9"
}
```

*The check was performed with errors*

### Example 5

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: string_lt('abc')
```

#### Input Event

```json
{
  "target_field": 123
}
```

*The check was performed with errors*



---
# string_lte

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: string_lte($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is less than or equal to `value` in byte-wise lexicographic order.

Behavior:
- Both operands must be strings; they are compared byte by byte as unsigned values (UTF-8 code-unit order),
  case-sensitively and without locale: `"Z"` sorts before `"a"`, `"10"` before `"9"` and `"ab"` before `"abc"`.
- `value` is a literal string or a reference to a string field.

Build errors:
- `value` is a literal that is not a string: write `'9'`, not `9`.
- `value` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- The `<=` operator with a string literal (`$field <= 'x'`) maps to this helper.
- Not the negation of `string_gt`: both are false for a missing or non-string target.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `value` does not exist or is not a string.
- The target string is greater than `value`.

## Examples

### Example 1

The target string sorts before the value.

#### Asset

```yaml
check:
  - target_field: string_lte('wazuh')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was successful*

### Example 2

The target string sorts after the value.

#### Asset

```yaml
check:
  - target_field: string_lte($value)
```

#### Input Event

```json
{
  "value": "hello world!",
  "target_field": "wazuh"
}
```

*The check was performed with errors*

### Example 3

Equal strings satisfy the check.

#### Asset

```yaml
check:
  - target_field: string_lte('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello world!"
}
```

*The check was successful*

### Example 4

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: string_lte($value)
```

#### Input Event

```json
{
  "value": "abc",
  "target_field": 123
}
```

*The check was performed with errors*



---
# string_ne

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: string_ne($target_field, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string differs from `value`, byte for byte.

Behavior:
- Both operands must be strings; they are compared byte by byte, so the comparison is case-sensitive and
  applies no locale or Unicode normalization.
- `value` is a literal string or a reference to a string field.
- A missing or non-string target gives false, so this is not the same as `NOT string_eq(...)`, which is
  true for a missing field.

Build errors:
- `value` is a literal that is not a string: write `'404'`, not `404`.
- `value` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- The `!=` operator with a string literal (`$field != 'x'`) maps to this helper.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `value` does not exist or is not a string.
- The two strings are equal.

## Examples

### Example 1

The two strings differ.

#### Asset

```yaml
check:
  - target_field: string_ne('hello world!')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 2

The two strings are equal.

#### Asset

```yaml
check:
  - target_field: string_ne($value)
```

#### Input Event

```json
{
  "value": "hello world!",
  "target_field": "hello world!"
}
```

*The check was performed with errors*

### Example 3

The comparison is case-sensitive, so the strings differ.

#### Asset

```yaml
check:
  - target_field: string_ne('Hello')
```

#### Input Event

```json
{
  "target_field": "hello"
}
```

*The check was successful*

### Example 4

The target field is a number, not a string, so the check fails although the values differ.

#### Asset

```yaml
check:
  - target_field: string_ne($value)
```

#### Input Event

```json
{
  "value": "hello",
  "target_field": 123
}
```

*The check was performed with errors*



---
# concat

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: concat(value, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string, number, object | value or reference | Any value of the listed types |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Concatenates two or more values in argument order, without a separator, and maps the resulting
string to the target field.

Behavior:
- Every argument is a literal or a reference of type string, number or object.
- A string is used as is.
- A literal number or object is written as compact JSON: `1.2` gives `1.2` and `{"a": 1}` gives
  `{"a":1}`.
- A referenced integer is written in decimal and a referenced double with 6 fixed decimals (`1.2`
  gives `1.200000`, as `to_string` does); a referenced object is written as compact JSON.

Build errors:
- Fewer than 2 arguments.
- A literal that is a boolean, an array or `null`.
- A referenced schema field whose type is not string, number or object.

Notes:
- `concat_any` skips the references that are missing instead of failing.
- `join` concatenates the strings of an array with a separator.


## Fails when

- any referenced field is missing
- a referenced field is a boolean, an array, `null` or an integer above 2^63-1

## Examples

### Example 1

Concatenate several strings in argument order

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat('hello', ' ', 'no', 'yes', 'yes')
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

Fail when a referenced field is missing

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat($value, 'hello')
```

#### Input Event

```json
{
  "value": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 3

Concatenate a referenced object, a literal number and a referenced string

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat($value, 2, $value_2)
```

#### Input Event

```json
{
  "value": {
    "key": "value"
  },
  "value_2": "hello"
}
```

#### Outcome Event

```json
{
  "value": {
    "key": "value"
  },
  "value_2": "hello",
  "target_field": "{\"key\":\"value\"}2hello"
}
```

*The operation was successful*

### Example 4

Write a referenced double with 6 decimals and a literal double as compact JSON

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat($value, '-', 1.5)
```

#### Input Event

```json
{
  "value": 1.5
}
```

#### Outcome Event

```json
{
  "value": 1.5,
  "target_field": "1.500000-1.5"
}
```

*The operation was successful*

### Example 5

Write a referenced integer in decimal

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat($value, ' items')
```

#### Input Event

```json
{
  "value": 42
}
```

#### Outcome Event

```json
{
  "value": 42,
  "target_field": "42 items"
}
```

*The operation was successful*



---
# concat_any

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: concat_any(value, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string, number, object | value or reference | Any value of the listed types |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Concatenates two or more values in argument order, without a separator, skipping the references
that are missing, and maps the resulting string to the target field.

Behavior:
- Every argument is a literal or a reference of type string, number or object.
- A missing reference contributes nothing; the other arguments are concatenated as `concat`
  does: strings as is, literal numbers and objects as compact JSON, referenced integers in
  decimal, referenced doubles with 6 fixed decimals and referenced objects as compact JSON.
- At least one argument must resolve: a literal always does.

Build errors:
- Fewer than 2 arguments.
- A literal that is a boolean, an array or `null`.
- A referenced schema field whose type is not string, number or object.

Notes:
- `concat` fails as soon as one reference is missing; both give the same result when every
  reference exists.
- `array_append_any` is the array counterpart: it skips missing references too.


## Fails when

- every argument is a reference and all of them are missing
- a referenced field that exists is a boolean, an array, `null` or an integer above 2^63-1

## Examples

### Example 1

Concatenate several strings in argument order

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

Skip a missing reference and keep the one that exists

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any($value, $value_1)
```

#### Input Event

```json
{
  "value": null,
  "value_1": "hello"
}
```

#### Outcome Event

```json
{
  "value": null,
  "value_1": "hello",
  "target_field": "hello"
}
```

*The operation was successful*

### Example 3

Skip a missing reference and keep the literal

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any($value, 'hello')
```

#### Input Event

```json
{
  "value": null
}
```

#### Outcome Event

```json
{
  "value": null,
  "target_field": "hello"
}
```

*The operation was successful*

### Example 4

Fail when every argument is a missing reference

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any($value, $value_1)
```

#### Input Event

```json
{
  "value": null,
  "value_1": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*

### Example 5

Fail when a referenced field exists but is a boolean

#### Asset

```yaml
normalize:
  - map:
      - target_field: concat_any($value, 'hello')
```

#### Input Event

```json
{
  "value": true
}
```

#### Outcome Event

```json
{
  "value": true
}
```

*The operation was performed with errors*



---
# contains

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: contains($target_field, substring)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| substring | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string contains `substring`.

Behavior:
- Byte-wise, case-sensitive substring search; no locale or Unicode normalization is applied.
- `substring` is a literal string or a reference to a string field.

Build errors:
- `substring` is an empty literal.
- `substring` is a literal that is not a string (an unquoted number, boolean or null).
- `substring` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- A reference that resolves to an empty string is not rejected: the check is false (an empty substring is never found).
- `starts_with` and `ends_with` are the anchored variants; `regex_match` takes a pattern.
- An array target is never searched; use `array_contains_all` or `array_contains_any` for arrays.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `substring` does not exist or is not a string.
- The target string does not contain `substring`.

## Examples

### Example 1

The target string contains the substring.

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

The substring does not occur in the target string.

#### Asset

```yaml
check:
  - target_field: contains($substring)
```

#### Input Event

```json
{
  "substring": "hello!",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 3

The substring does not occur in the target string.

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

### Example 4

The search is case-sensitive.

#### Asset

```yaml
check:
  - target_field: contains($substring)
```

#### Input Event

```json
{
  "substring": "Hello",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 5

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: contains('hello')
```

#### Input Event

```json
{
  "target_field": 123
}
```

*The check was performed with errors*

### Example 6

An empty literal is rejected at build time.

#### Asset

```yaml
check:
  - target_field: contains('')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*



---
# decode_hex

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: decode_hex(hex, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| hex | string | reference | Any hexadecimal |
| mode (option, optional) | string | value | quoted |


## Output

| Type | Possible values |
| ---- | --------------- |
| [string, array] | - |


## Description

Decodes a string of hexadecimal digits into text and maps it to the target field.

Behavior:
- Without `mode`, `hex` must be a string with an even number of hexadecimal digits (`0-9`, `A-F`
  or `a-f`, with no `0x` prefix, whitespace or sign) whose every decoded byte is ASCII (`0x00` to
  `0x7F`, control characters included); the result is that text, and an empty string gives an
  empty string.
- With the mode `quoted`, each value is handled by its quoting, as auditd writes its arguments: a
  value between double quotes loses the quotes and is kept as text (so `"10"` or `"1234"` stay
  text); an unquoted value made of upper-case hexadecimal digits that decodes to valid UTF-8 is
  decoded; any other value (lower-case hexadecimal, invalid UTF-8, other text, a value that is
  not a string) is kept unchanged. The reference can be a string or an array, handled element by
  element, and the result has the same type; this mode never fails on the content.

Build errors:
- `mode` is given and is not the literal `quoted`.
- `hex` is a schema field whose type is not a string.

Notes:
- `hex_to_int` reads hexadecimal digits as an integer instead.
- `regex_extract_all` with `(?:^|\s)a\d+=(\S+)` collects the raw auditd EXECVE arguments, quotes
  included, that the mode `quoted` then decodes.
- When the target is a keyword field such as `process.args`, an element that is not a string
  fails the schema validation and the whole operation fails.


## Fails when

- `hex` is missing
- without `mode`: `hex` is not a string, has an odd number of digits, contains a character that is not a hexadecimal digit, or decodes to a byte above 0x7F
- with the mode `quoted`: `hex` is neither a string nor an array

## Examples

### Example 1

Decode an even number of hexadecimal digits to ASCII text

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
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

### Example 2

Decode lower and upper case digits alike

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": "48656C6C6F20776F726C64"
}
```

#### Outcome Event

```json
{
  "hex": "48656C6C6F20776F726C64",
  "target_field": "Hello world"
}
```

*The operation was successful*

### Example 3

Decode an empty string to an empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": ""
}
```

*The operation was successful*

### Example 4

Fail on an odd number of hexadecimal digits

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": "48656C6C6F20776F726C6"
}
```

#### Outcome Event

```json
{
  "hex": "48656C6C6F20776F726C6"
}
```

*The operation was performed with errors*

### Example 5

Fail on a character that is not a hexadecimal digit

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": "48656C6C6G"
}
```

#### Outcome Event

```json
{
  "hex": "48656C6C6G"
}
```

*The operation was performed with errors*

### Example 6

Fail on a 0x prefix, as x is not a hexadecimal digit

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": "0x4142"
}
```

#### Outcome Event

```json
{
  "hex": "0x4142"
}
```

*The operation was performed with errors*

### Example 7

Fail when a decoded byte is not ASCII

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": "CAFE"
}
```

#### Outcome Event

```json
{
  "hex": "CAFE"
}
```

*The operation was performed with errors*

### Example 8

Fail on an array reference without the mode quoted

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex)
```

#### Input Event

```json
{
  "hex": [
    "48656C6C6F",
    "776F726C6421"
  ]
}
```

#### Outcome Event

```json
{
  "hex": [
    "48656C6C6F",
    "776F726C6421"
  ]
}
```

*The operation was performed with errors*

### Example 9

Fail on a reference that is neither a string nor an array, also with the mode quoted

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": {
    "key": "4142"
  }
}
```

#### Outcome Event

```json
{
  "hex": {
    "key": "4142"
  }
}
```

*The operation was performed with errors*

### Example 10

Strip the quotes of the quoted auditd arguments and decode the unquoted hexadecimal one

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": [
    "\"/usr/bin/sudo\"",
    "\"grep\"",
    "6B65793D226172742D7465737422",
    "\"/var/log/audit/audit.log\""
  ]
}
```

#### Outcome Event

```json
{
  "hex": [
    "\"/usr/bin/sudo\"",
    "\"grep\"",
    "6B65793D226172742D7465737422",
    "\"/var/log/audit/audit.log\""
  ],
  "target_field": [
    "/usr/bin/sudo",
    "grep",
    "key=\"art-test\"",
    "/var/log/audit/audit.log"
  ]
}
```

*The operation was successful*

### Example 11

Keep quoted arguments as text even when they look hexadecimal

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": [
    "\"kill\"",
    "\"-9\"",
    "\"1234\"",
    "\"10\"",
    "\"0755\""
  ]
}
```

#### Outcome Event

```json
{
  "hex": [
    "\"kill\"",
    "\"-9\"",
    "\"1234\"",
    "\"10\"",
    "\"0755\""
  ],
  "target_field": [
    "kill",
    "-9",
    "1234",
    "10",
    "0755"
  ]
}
```

*The operation was successful*

### Example 12

Decode an unquoted hexadecimal argument to UTF-8

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": [
    "\"touch\"",
    "636166C3A9"
  ]
}
```

#### Outcome Event

```json
{
  "hex": [
    "\"touch\"",
    "636166C3A9"
  ],
  "target_field": [
    "touch",
    "caf\u00e9"
  ]
}
```

*The operation was successful*

### Example 13

Keep lower-case hexadecimal, invalid UTF-8 and other unquoted values unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": [
    "3c3e",
    "CAFE",
    "(null)",
    ""
  ]
}
```

#### Outcome Event

```json
{
  "hex": [
    "3c3e",
    "CAFE",
    "(null)",
    ""
  ],
  "target_field": [
    "3c3e",
    "CAFE",
    "(null)",
    ""
  ]
}
```

*The operation was successful*

### Example 14

Keep the elements that are not strings unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": [
    1,
    "\"4142\"",
    "4142",
    true
  ]
}
```

#### Outcome Event

```json
{
  "hex": [
    1,
    "\"4142\"",
    "4142",
    true
  ],
  "target_field": [
    1,
    "4142",
    "AB",
    true
  ]
}
```

*The operation was successful*

### Example 15

Apply the mode quoted to a string reference

#### Asset

```yaml
normalize:
  - map:
      - target_field: decode_hex($hex, 'quoted')
```

#### Input Event

```json
{
  "hex": "\"1234\""
}
```

#### Outcome Event

```json
{
  "hex": "\"1234\"",
  "target_field": "1234"
}
```

*The operation was successful*



---
# ends_with

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: ends_with($target_field, suffix)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| suffix | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string ends with `suffix`.

Behavior:
- Byte-wise, case-sensitive suffix comparison; no locale or Unicode normalization is applied.
- `suffix` is a literal string or a reference to a string field.

Build errors:
- `suffix` is an empty literal.
- `suffix` is a literal that is not a string (an unquoted number, boolean or null).
- `suffix` is a reference to a schema field whose type is not `keyword` or `text`; this is stricter than
  `starts_with` and `contains`, which accept any string type.
- The target is a schema field whose type is not a string type.

Notes:
- A reference that resolves to an empty string is not rejected: the check is true (every string ends with the empty string).
- `starts_with` is the mirror check; `contains` searches anywhere in the string; `regex_match('...$')` is
  the pattern alternative.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `suffix` does not exist or is not a string.
- The target string does not end with `suffix`.

## Examples

### Example 1

The target string ends with the suffix.

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

The target string does not end with the suffix.

#### Asset

```yaml
check:
  - target_field: ends_with($suffix)
```

#### Input Event

```json
{
  "suffix": "wazuh",
  "target_field": "hello wazuh!!!"
}
```

*The check was performed with errors*

### Example 3

The suffix occurs at the start of the string, not at the end.

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

### Example 4

The comparison is case-sensitive.

#### Asset

```yaml
check:
  - target_field: ends_with($suffix)
```

#### Input Event

```json
{
  "suffix": "WAZUH!",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 5

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: ends_with('wazuh!')
```

#### Input Event

```json
{
  "target_field": 123
}
```

*The check was performed with errors*

### Example 6

An empty literal is rejected at build time.

#### Asset

```yaml
check:
  - target_field: ends_with('')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*



---
# join

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: join(array, separator)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| array | array | reference | Any array |
| separator | string | value | Any string |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Concatenates the strings of an array with a separator and maps the result to the target field.

Behavior:
- `array` is a reference to an array whose elements are all strings; numbers are not converted.
- `separator` is a string literal of any length, the empty string included, written between
  consecutive elements.
- An empty array gives an empty string.

Build errors:
- `separator` is a reference or is not a string.
- `array` is a schema field whose elements are not strings.

Notes:
- `concat` and `concat_any` concatenate separate arguments and convert numbers and objects.
- `split` is the inverse operation.


## Fails when

- `array` is missing or is not an array
- an element of `array` is not a string

## Examples

### Example 1

Join the strings with a space

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

Join the strings with a multi-character separator

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

### Example 3

Join the strings with an empty separator

#### Asset

```yaml
normalize:
  - map:
      - target_field: join($array, '')
```

#### Input Event

```json
{
  "array": [
    "a",
    "b",
    "c"
  ]
}
```

#### Outcome Event

```json
{
  "array": [
    "a",
    "b",
    "c"
  ],
  "target_field": "abc"
}
```

*The operation was successful*

### Example 4

Join an empty array into an empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: join($array, ',')
```

#### Input Event

```json
{
  "array": []
}
```

*The operation was successful*

### Example 5

Fail on an element that is not a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: join($array, ',')
```

#### Input Event

```json
{
  "array": [
    "a",
    1
  ]
}
```

#### Outcome Event

```json
{
  "array": [
    "a",
    1
  ]
}
```

*The operation was performed with errors*



---
# lowercase

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: lowercase(value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Converts the ASCII upper-case letters of a string to lower case and maps the result to the target
field.

Behavior:
- Only the ASCII letters `A-Z` change; every other byte is kept, so non-ASCII (UTF-8 multibyte)
  characters are left as they are.
- `value` can be a literal or a reference.

Build errors:
- `value` is a literal that is not a string.
- `value` is a schema field whose type is not a string.

Notes:
- `uppercase` is the opposite conversion.


## Fails when

- `value` is a reference that is missing or is not a string

## Examples

### Example 1

Convert an upper-case string to lower case

#### Asset

```yaml
normalize:
  - map:
      - target_field: lowercase('ABCD')
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

Convert a mixed-case string to lower case

#### Asset

```yaml
normalize:
  - map:
      - target_field: lowercase($value)
```

#### Input Event

```json
{
  "value": "AbcD"
}
```

#### Outcome Event

```json
{
  "value": "AbcD",
  "target_field": "abcd"
}
```

*The operation was successful*

### Example 3

Keep the letters that are already lower case

#### Asset

```yaml
normalize:
  - map:
      - target_field: lowercase('aBcDECF')
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

### Example 4

Leave a non-ASCII letter unchanged and convert the ASCII ones

#### Asset

```yaml
normalize:
  - map:
      - target_field: lowercase($value)
```

#### Input Event

```json
{
  "value": "\u00c9COLE"
}
```

#### Outcome Event

```json
{
  "value": "\u00c9COLE",
  "target_field": "\u00c9cole"
}
```

*The operation was successful*



---
# regex_extract

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: regex_extract(field_to_match, regex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| field_to_match | string | reference | Any string |
| regex | string | value | Any regex |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Extracts the first capture group of the first match of a regular expression in a string and maps
it to the target field.

Behavior:
- `regex` is an RE2 expression (https://github.com/google/re2/wiki/Syntax) matched anywhere in
  the string; anchor it with `^` and `$` to match the whole string.
- Only capture group 1 is returned; further groups are ignored: `^(va)l(ue)$` on `value` gives
  `va`.
- A regex with no capture group builds, but every match fails at runtime.

Build errors:
- `regex` is not a string literal or is not a valid RE2 expression.
- `field_to_match` is a schema field whose type is not a string.

Notes:
- Escape the reserved YAML characters of the regex according to the quoting style used.
- `regex_extract_all` collects group 1 of every match into an array.
- `regex_match` is the check helper with the same matching.


## Fails when

- `field_to_match` is missing or is not a string
- the regex does not match, or it has no capture group

## Examples

### Example 1

Extract the capture group of an anchored regex that matches the whole string

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($field_to_match, '^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "field_to_match": "bye pcre2"
}
```

#### Outcome Event

```json
{
  "field_to_match": "bye pcre2",
  "target_field": "bye pcre2"
}
```

*The operation was successful*

### Example 2

Fail when the regex does not match

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($field_to_match, '^(bye pcre\\d)$')
```

#### Input Event

```json
{
  "field_to_match": "ye pcre2"
}
```

#### Outcome Event

```json
{
  "field_to_match": "ye pcre2"
}
```

*The operation was performed with errors*

### Example 3

Extract the capture group of the first match of an unanchored regex

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($field_to_match, 'id=(\\d+)')
```

#### Input Event

```json
{
  "field_to_match": "id=12 id=34"
}
```

#### Outcome Event

```json
{
  "field_to_match": "id=12 id=34",
  "target_field": "12"
}
```

*The operation was successful*

### Example 4

Return capture group 1 only and ignore the other groups

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($field_to_match, '^(va)l(ue)$')
```

#### Input Event

```json
{
  "field_to_match": "value"
}
```

#### Outcome Event

```json
{
  "field_to_match": "value",
  "target_field": "va"
}
```

*The operation was successful*

### Example 5

Fail at runtime when the regex has no capture group

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract($field_to_match, 'value')
```

#### Input Event

```json
{
  "field_to_match": "value"
}
```

#### Outcome Event

```json
{
  "field_to_match": "value"
}
```

*The operation was performed with errors*



---
# regex_extract_all

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: regex_extract_all(field_to_match, regex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| field_to_match | string | reference | Any string |
| regex | string | value | Any regex |


## Output

| Type | Possible values |
| ---- | --------------- |
| array | Any array |


## Description

Collects the first capture group of every match of a regular expression in a string and maps the
array of captures to the target field.

Behavior:
- `regex` is an RE2 expression (https://github.com/google/re2/wiki/Syntax) matched from left to
  right, without overlapping; the captures keep their order and their text unchanged.
- Only capture group 1 of each match is collected; further groups are ignored, and a group that
  does not take part in a match yields an empty string.
- An empty match advances by one UTF-8 character.

Build errors:
- `regex` is not a string literal, is not a valid RE2 expression or has no capture group.
- `field_to_match` is a schema field whose type is not a string.

Notes:
- The auditd EXECVE arguments, raw and in order, are collected with the regex
  `(?:^|\s)a\d+=(\S+)`; quoted values keep their quotes, so `decode_hex` with the mode `quoted`
  can tell text from hexadecimal. Arguments that auditd splits in chunks (`aN_len=` and `aN[i]=`)
  are not matched by that regex.
- Escape the reserved YAML characters of the regex according to the quoting style used.
- `regex_extract` returns the capture of the first match only, as a string.


## Fails when

- `field_to_match` is missing or is not a string
- the regex does not match

## Examples

### Example 1

Collect the raw auditd EXECVE arguments, quotes included

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract_all($field_to_match, '(?:^|\\s)a\\d+=(\\S+)')
```

#### Input Event

```json
{
  "field_to_match": "type=EXECVE msg=audit(1730000000.123:42): argc=4 a0=\"/usr/bin/sudo\" a1=\"grep\" a2=6B65793D226172742D7465737422 a3=\"/var/log/audit/audit.log\""
}
```

#### Outcome Event

```json
{
  "field_to_match": "type=EXECVE msg=audit(1730000000.123:42): argc=4 a0=\"/usr/bin/sudo\" a1=\"grep\" a2=6B65793D226172742D7465737422 a3=\"/var/log/audit/audit.log\"",
  "target_field": [
    "\"/usr/bin/sudo\"",
    "\"grep\"",
    "6B65793D226172742D7465737422",
    "\"/var/log/audit/audit.log\""
  ]
}
```

*The operation was successful*

### Example 2

Keep the first group of every match, an empty capture included

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract_all($field_to_match, 'k\\d=(\\w*);?')
```

#### Input Event

```json
{
  "field_to_match": "k1=v1;k2=;k3=v3"
}
```

#### Outcome Event

```json
{
  "field_to_match": "k1=v1;k2=;k3=v3",
  "target_field": [
    "v1",
    "",
    "v3"
  ]
}
```

*The operation was successful*

### Example 3

Advance by one character after an empty match, one capture per position

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract_all($field_to_match, '(x*)')
```

#### Input Event

```json
{
  "field_to_match": "ab"
}
```

#### Outcome Event

```json
{
  "field_to_match": "ab",
  "target_field": [
    "",
    "",
    ""
  ]
}
```

*The operation was successful*

### Example 4

Fail when the regex does not match

#### Asset

```yaml
normalize:
  - map:
      - target_field: regex_extract_all($field_to_match, '(?:^|\\s)a\\d+=(\\S+)')
```

#### Input Event

```json
{
  "field_to_match": "argc=0"
}
```

#### Outcome Event

```json
{
  "field_to_match": "argc=0"
}
```

*The operation was performed with errors*



---
# regex_match

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: regex_match($target_field, regex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| regex | string | value | Any regex |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string matches the regular expression `regex`.

Behavior:
- `regex` is a literal pattern compiled with RE2 (syntax: https://github.com/google/re2/wiki/Syntax) with
  the default options: UTF-8, case-sensitive, `.` does not match a newline.
- The match is unanchored: the pattern may match anywhere in the string. Use `^` and `$` to require a
  match of the whole string.
- An empty pattern matches every string.

Build errors:
- `regex` is not a valid RE2 pattern.
- `regex` is a reference or a literal that is not a string.
- The target is a schema field whose type is not a string type.

Notes:
- Quote the pattern when it contains a comma, a closing parenthesis or a space, and mind the YAML escaping
  rules for backslashes.
- `contains`, `starts_with` and `ends_with` are the literal (non-pattern) alternatives.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The pattern does not match the target string.

## Examples

### Example 1

The anchored pattern matches the whole string.

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

The anchored pattern does not match the string.

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

### Example 3

An unanchored pattern matches anywhere in the string.

#### Asset

```yaml
check:
  - target_field: regex_match('pcre\\d')
```

#### Input Event

```json
{
  "target_field": "say bye pcre2 now"
}
```

*The check was successful*

### Example 4

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: regex_match('^bye')
```

#### Input Event

```json
{
  "target_field": 42
}
```

*The check was performed with errors*



---
# regex_not_match

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: regex_not_match($target_field, regex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| regex | string | value | Any regex |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string does not match the regular expression `regex`.

Behavior:
- `regex` is a literal pattern compiled with RE2 (syntax: https://github.com/google/re2/wiki/Syntax) with
  the default options: UTF-8, case-sensitive, `.` does not match a newline.
- The match is unanchored: the check fails as soon as the pattern matches anywhere in the string. Use `^`
  and `$` to constrain the match to the whole string.
- A missing or non-string target gives false, so this is not the same as `NOT regex_match(...)`, which is
  true for a missing field.

Build errors:
- `regex` is not a valid RE2 pattern.
- `regex` is a reference or a literal that is not a string.
- The target is a schema field whose type is not a string type.

Notes:
- Quote the pattern when it contains a comma, a closing parenthesis or a space, and mind the YAML escaping
  rules for backslashes.
- An empty pattern matches every string, so the check is always false with it.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The pattern matches the target string.

## Examples

### Example 1

The pattern does not match the string.

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

The pattern matches the string.

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

An unanchored pattern matches in the middle of the string, so the check fails.

#### Asset

```yaml
check:
  - target_field: regex_not_match('abc')
```

#### Input Event

```json
{
  "target_field": "123abc"
}
```

*The check was performed with errors*

### Example 4

The target field is a number, not a string.

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
# replace

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: replace(old, new)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| old | string | value | Any string |
| new | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Replaces every occurrence of `old` with `new` in the target string.

Behavior:
- `old` and `new` are literal strings; `old` must not be empty, `new` may be empty.
- The match is literal (not a regular expression) and case-sensitive.
- Occurrences are replaced from left to right without overlapping, and the inserted text is not scanned
  again.
- The result is written back to the target field; the operation succeeds even when nothing was replaced.

Build errors:
- `old` is empty, or `old` or `new` is not a literal string.
- A number of arguments other than 2.

Notes:
- `trim` removes characters at the ends of the string only.


## Fails when

- The target field does not exist or is not a string.

## Examples

### Example 1

Replaces the occurrence of old with new

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

Succeeds without changes when old does not occur

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

### Example 3

The match is case-sensitive

#### Asset

```yaml
normalize:
  - map:
      - target_field: replace('Hello', 'hi')
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

### Example 4

Every occurrence is replaced

#### Asset

```yaml
normalize:
  - map:
      - target_field: replace('-', '+')
```

#### Input Event

```json
{
  "target_field": "a-b-c"
}
```

#### Outcome Event

```json
{
  "target_field": "a+b+c"
}
```

*The operation was successful*

### Example 5

An empty new string removes every occurrence of old

#### Asset

```yaml
normalize:
  - map:
      - target_field: replace('o', '')
```

#### Input Event

```json
{
  "target_field": "hello world"
}
```

#### Outcome Event

```json
{
  "target_field": "hell wrld"
}
```

*The operation was successful*

### Example 6

Occurrences are replaced from left to right without overlapping

#### Asset

```yaml
normalize:
  - map:
      - target_field: replace('aa', 'b')
```

#### Input Event

```json
{
  "target_field": "aaa"
}
```

#### Outcome Event

```json
{
  "target_field": "ba"
}
```

*The operation was successful*



---
# sha1

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: sha1(value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | reference | Any string |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Computes the SHA-1 hash of a string and maps it to the target field as 40 lower-case hexadecimal
digits.

Behavior:
- `value` is a reference to a string; its bytes are hashed as they are.
- The result is the hash in lower-case hexadecimal, 40 characters long.

Build errors:
- `value` is a literal.
- `value` is a schema field whose type is not a string.

Notes:
- A single string is hashed: to hash several values, build the string with `concat` first.


## Fails when

- `value` is missing or is not a string

## Examples

### Example 1

Hash a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: sha1($value)
```

#### Input Event

```json
{
  "value": "Hi Wazuh!"
}
```

#### Outcome Event

```json
{
  "value": "Hi Wazuh!",
  "target_field": "c4e30dbc1b87ba8f29b24a74dba2f006be2a709e"
}
```

*The operation was successful*

### Example 2

Hash the empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: sha1($value)
```

#### Input Event

```json
{
  "value": ""
}
```

#### Outcome Event

```json
{
  "value": "",
  "target_field": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
}
```

*The operation was successful*



---
# split

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: split(input, separator)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| separator | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | Any string |


## Description

Splits the string referenced by `input` on `separator` and stores the parts as an array of strings in the
target field.

Behavior:
- `input` is a reference to a string field; `separator` is a literal string of one or more characters,
  matched literally and case-sensitively.
- The parts are stored in order and unchanged (the spaces around them are kept). One separator at the
  start of the input is skipped, an empty part between two separators is kept, and one empty part at the
  end is dropped: `",,a"` gives `["", "a"]`, `"a,b,,"` gives `["a", "b", ""]` and an empty input gives
  an empty array.
- The target field is set to the new array: any previous value, an existing array included, is replaced.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `separator` is not a literal string, or is empty.
- A number of arguments other than 2.
- The target field is a schema field whose elements are not strings.

Notes:
- `join` is the inverse operation.
- `parse_csv` and `parse_dsv` handle quoted values and write named fields.


## Fails when

- The input field does not exist or is not a string.

## Examples

### Example 1

Fails and keeps the target unchanged when the input field does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: split($input, ',')
```

#### Input Event

```json
{
  "input": null,
  "target_field": [
    "old"
  ]
}
```

#### Outcome Event

```json
{
  "input": null,
  "target_field": [
    "old"
  ]
}
```

*The operation was performed with errors*

### Example 2

The parts keep the spaces around them

#### Asset

```yaml
normalize:
  - map:
      - target_field: split($input, '|')
```

#### Input Event

```json
{
  "input": "val 1 | val 2 | val 3",
  "target_field": ""
}
```

#### Outcome Event

```json
{
  "input": "val 1 | val 2 | val 3",
  "target_field": [
    "val 1 ",
    " val 2 ",
    " val 3"
  ]
}
```

*The operation was successful*

### Example 3

An existing array in the target field is replaced by the new parts

#### Asset

```yaml
normalize:
  - map:
      - target_field: split($input, ',')
```

#### Input Event

```json
{
  "input": "a,b,c",
  "target_field": [
    "old",
    "values"
  ]
}
```

#### Outcome Event

```json
{
  "input": "a,b,c",
  "target_field": [
    "a",
    "b",
    "c"
  ]
}
```

*The operation was successful*

### Example 4

The separator may have more than one character

#### Asset

```yaml
normalize:
  - map:
      - target_field: split($input, ', ')
```

#### Input Event

```json
{
  "input": "a, b, c",
  "target_field": ""
}
```

#### Outcome Event

```json
{
  "input": "a, b, c",
  "target_field": [
    "a",
    "b",
    "c"
  ]
}
```

*The operation was successful*



---
# starts_with

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: starts_with($target_field, prefix)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| prefix | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string starts with `prefix`.

Behavior:
- Byte-wise, case-sensitive prefix comparison; no locale or Unicode normalization is applied.
- `prefix` is a literal string or a reference to a string field.

Build errors:
- `prefix` is an empty literal.
- `prefix` is a literal that is not a string (an unquoted number, boolean or null).
- `prefix` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not a string type.

Notes:
- A reference that resolves to an empty string is not rejected: the check is true (every string starts with the empty string).
- `ends_with` is the mirror check; `contains` searches anywhere in the string; `regex_match('^...')` is
  the pattern alternative.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `prefix` does not exist or is not a string.
- The target string does not start with `prefix`.

## Examples

### Example 1

The target string starts with the prefix.

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

The target string does not start with the prefix.

#### Asset

```yaml
check:
  - target_field: starts_with($prefix)
```

#### Input Event

```json
{
  "prefix": "hello!",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 3

The prefix occurs at the end of the string, not at the start.

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

### Example 4

The comparison is case-sensitive.

#### Asset

```yaml
check:
  - target_field: starts_with($prefix)
```

#### Input Event

```json
{
  "prefix": "Hello",
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*

### Example 5

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: starts_with('hello')
```

#### Input Event

```json
{
  "target_field": 123
}
```

*The check was performed with errors*

### Example 6

An empty literal is rejected at build time.

#### Asset

```yaml
check:
  - target_field: starts_with('')
```

#### Input Event

```json
{
  "target_field": "hello wazuh!"
}
```

*The check was performed with errors*



---
# trim

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: trim([chars])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| chars (optional) | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Removes from both ends of the target string the characters that belong to a set.

Behavior:
- `chars` is an optional literal string listing the characters to remove; when it is omitted the set is
  the whitespace characters: space, tab, line feed, carriage return, form feed and vertical tab.
- At each end of the string, every character that is in the set is removed until the first character
  that is not; the characters in the middle are kept.
- A string made only of characters of the set becomes the empty string.
- The result is written back to the target field; the operation succeeds even when nothing is removed.

Build errors:
- `chars` is not a literal string.
- `chars` is an empty string.
- More than 1 argument.

Notes:
- The characters are matched byte by byte: a multi-byte UTF-8 character is not one unit of the set.
- `chars` is a set, not a sequence: `xy` removes any run of `x` and `y` characters.
- `trim_start` and `trim_end` trim one end only; `replace` removes characters anywhere in the string.


## Fails when

- The target field does not exist or is not a string.

## Examples

### Example 1

Without arguments the whitespace at both ends is removed

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim()
```

#### Input Event

```json
{
  "target_field": "  \t hi there \n"
}
```

#### Outcome Event

```json
{
  "target_field": "hi there"
}
```

*The operation was successful*

### Example 2

Succeeds without changes when there is nothing to remove

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim()
```

#### Input Event

```json
{
  "target_field": "hi there"
}
```

#### Outcome Event

```json
{
  "target_field": "hi there"
}
```

*The operation was successful*

### Example 3

Removes any run of the given characters from both ends

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('xy')
```

#### Input Event

```json
{
  "target_field": "xyxhixyy"
}
```

#### Outcome Event

```json
{
  "target_field": "hi"
}
```

*The operation was successful*

### Example 4

A string made only of the given characters becomes empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('x')
```

#### Input Event

```json
{
  "target_field": "xxxx"
}
```

*The operation was successful*

### Example 5

Only the characters of the set are removed, the spaces next to them are kept

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('-')
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

### Example 6

The characters are matched as a set, in any order

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim('-=')
```

#### Input Event

```json
{
  "target_field": "-=hi=-"
}
```

#### Outcome Event

```json
{
  "target_field": "hi"
}
```

*The operation was successful*



---
# trim_end

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: trim_end([chars])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| chars (optional) | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Removes from the end of the target string the characters that belong to a set.

Behavior:
- `chars` is an optional literal string listing the characters to remove; when it is omitted the set is
  the whitespace characters: space, tab, line feed, carriage return, form feed and vertical tab.
- Every trailing character that is in the set is removed until the first character that is not; the
  start of the string is not touched.
- A string made only of characters of the set becomes the empty string.
- The result is written back to the target field; the operation succeeds even when nothing is removed.

Build errors:
- `chars` is not a literal string.
- `chars` is an empty string.
- More than 1 argument.

Notes:
- The characters are matched byte by byte: a multi-byte UTF-8 character is not one unit of the set.
- `chars` is a set, not a sequence: `xy` removes any run of `x` and `y` characters.
- `trim` trims both ends and `trim_start` the start only.


## Fails when

- The target field does not exist or is not a string.

## Examples

### Example 1

Without arguments the trailing whitespace is removed and the leading one is kept

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_end()
```

#### Input Event

```json
{
  "target_field": "  hi  "
}
```

#### Outcome Event

```json
{
  "target_field": "  hi"
}
```

*The operation was successful*

### Example 2

Carriage returns and line feeds count as whitespace

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_end()
```

#### Input Event

```json
{
  "target_field": "hi \r\n"
}
```

#### Outcome Event

```json
{
  "target_field": "hi"
}
```

*The operation was successful*

### Example 3

Removes the given character from the end only

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_end('-')
```

#### Input Event

```json
{
  "target_field": "--hi--"
}
```

#### Outcome Event

```json
{
  "target_field": "--hi"
}
```

*The operation was successful*

### Example 4

A string made only of the given characters becomes empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_end('xy')
```

#### Input Event

```json
{
  "target_field": "xyx"
}
```

*The operation was successful*



---
# trim_start

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: trim_start([chars])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| chars (optional) | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Removes from the start of the target string the characters that belong to a set.

Behavior:
- `chars` is an optional literal string listing the characters to remove; when it is omitted the set is
  the whitespace characters: space, tab, line feed, carriage return, form feed and vertical tab.
- Every leading character that is in the set is removed until the first character that is not; the end
  of the string is not touched.
- A string made only of characters of the set becomes the empty string.
- The result is written back to the target field; the operation succeeds even when nothing is removed.

Build errors:
- `chars` is not a literal string.
- `chars` is an empty string.
- More than 1 argument.

Notes:
- The characters are matched byte by byte: a multi-byte UTF-8 character is not one unit of the set.
- `chars` is a set, not a sequence: `xy` removes any run of `x` and `y` characters.
- `trim` trims both ends and `trim_end` the end only.


## Fails when

- The target field does not exist or is not a string.

## Examples

### Example 1

Without arguments the leading whitespace is removed and the trailing one is kept

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_start()
```

#### Input Event

```json
{
  "target_field": "  hi  "
}
```

#### Outcome Event

```json
{
  "target_field": "hi  "
}
```

*The operation was successful*

### Example 2

Tabs and line feeds count as whitespace

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_start()
```

#### Input Event

```json
{
  "target_field": "\t\nhi"
}
```

#### Outcome Event

```json
{
  "target_field": "hi"
}
```

*The operation was successful*

### Example 3

Removes the given character from the start only

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_start('-')
```

#### Input Event

```json
{
  "target_field": "--hi--"
}
```

#### Outcome Event

```json
{
  "target_field": "hi--"
}
```

*The operation was successful*

### Example 4

A string made only of the given characters becomes empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: trim_start('xy')
```

#### Input Event

```json
{
  "target_field": "xyx"
}
```

*The operation was successful*



---
# uppercase

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: uppercase(value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | string | value or reference | Any string |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Converts the ASCII lower-case letters of a string to upper case and maps the result to the target
field.

Behavior:
- Only the ASCII letters `a-z` change; every other byte is kept, so non-ASCII (UTF-8 multibyte)
  characters are left as they are.
- `value` can be a literal or a reference.

Build errors:
- `value` is a literal that is not a string.
- `value` is a schema field whose type is not a string.

Notes:
- `lowercase` is the opposite conversion.


## Fails when

- `value` is a reference that is missing or is not a string

## Examples

### Example 1

Convert a lower-case string to upper case

#### Asset

```yaml
normalize:
  - map:
      - target_field: uppercase('abcd')
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

Convert a mixed-case string to upper case

#### Asset

```yaml
normalize:
  - map:
      - target_field: uppercase($value)
```

#### Input Event

```json
{
  "value": "aBcD"
}
```

#### Outcome Event

```json
{
  "value": "aBcD",
  "target_field": "ABCD"
}
```

*The operation was successful*

### Example 3

Keep the letters that are already upper case

#### Asset

```yaml
normalize:
  - map:
      - target_field: uppercase('aBcDECF')
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

### Example 4

Leave a non-ASCII letter unchanged and convert the ASCII ones

#### Asset

```yaml
normalize:
  - map:
      - target_field: uppercase($value)
```

#### Input Event

```json
{
  "value": "\u00e9cole"
}
```

#### Outcome Event

```json
{
  "value": "\u00e9cole",
  "target_field": "\u00e9COLE"
}
```

*The operation was successful*



---
# array_append

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: array_append(value, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number, string, object, boolean, array | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Appends every argument to the array stored in the target field.

Behavior:
- The target field must be an array or be missing; a missing target is created as an empty array first.
- Each argument is a literal of any JSON type or a reference to a field, and is appended as one element,
  in argument order, without removing duplicates.
- Every element must share one JSON type: the schema type of the target field when it has one, otherwise
  the type of the first element already in the array, otherwise the type of the first argument that
  resolves. Integers and floating-point values count as the same type (number).
- The operation is all-or-nothing: the array is rewritten only after every argument has been accepted,
  so a failure leaves the target field unchanged.

Build errors:
- No arguments, or more than 150 arguments.
- A literal argument whose JSON type differs from the element type of a schema target field.
- The target field is not a schema field and does not start with `_`.

Notes:
- A reference that does not exist in the event fails the whole operation; `array_append_any` skips the
  missing references instead.
- A target field that exists and is not an array makes the operation fail; it is never overwritten.
- `array_append_unique` skips the values that are already in the array.


## Fails when

- The target field exists and is not an array.
- Any reference argument does not exist in the event.
- An argument has a JSON type different from the element type of the array.
- The resulting array is rejected by the schema validation of the target field.

## Examples

### Example 1

A missing reference fails the whole operation and nothing is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($value, 6)
```

#### Input Event

```json
{
  "value": null,
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
  "value": null,
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The operation was performed with errors*

### Example 2

A number is appended to an array of numbers

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($value)
```

#### Input Event

```json
{
  "value": 5,
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
  "value": 5,
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

### Example 3

Several arguments are appended in argument order

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append(5, 6)
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

### Example 4

A value already present is appended again (no duplicate check)

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($value)
```

#### Input Event

```json
{
  "value": 4,
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
  "value": 4,
  "target_field": [
    1,
    2,
    3,
    4,
    4
  ]
}
```

*The operation was successful*

### Example 5

A string is rejected by an array of numbers

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append('hello')
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

### Example 6

An array is rejected by an array of numbers

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($value)
```

#### Input Event

```json
{
  "value": [
    1,
    2
  ],
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
  "value": [
    1,
    2
  ],
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The operation was performed with errors*

### Example 7

An integer is accepted by an array of floating-point numbers

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append(2)
```

#### Input Event

```json
{
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

### Example 8

A target field that is not an array makes the operation fail and is not overwritten

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append($value)
```

#### Input Event

```json
{
  "value": 5,
  "target_field": "text"
}
```

#### Outcome Event

```json
{
  "value": 5,
  "target_field": "text"
}
```

*The operation was performed with errors*



---
# array_append_any

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: array_append_any(value, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number, string, object, boolean, array | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Appends the arguments that resolve to the array stored in the target field, skipping the references that
do not exist.

Behavior:
- The target field must be an array or be missing; a missing target is created as an empty array first.
- Each argument is a literal of any JSON type or a reference to a field, and is appended as one element,
  in argument order, without removing duplicates.
- A reference that does not exist in the event is skipped; the other arguments are still appended.
- Every element must share one JSON type: the schema type of the target field when it has one, otherwise
  the type of the first element already in the array, otherwise the type of the first argument that
  resolves. Integers and floating-point values count as the same type (number). A reference that exists
  with another type is not skipped: it fails the operation.
- The operation fails when nothing was appended, for example when every reference is missing.
- The operation is all-or-nothing: the array is rewritten only after every argument has been accepted,
  so a failure leaves the target field unchanged.

Build errors:
- No arguments, or more than 150 arguments.
- A literal argument whose JSON type differs from the element type of a schema target field.
- The target field is not a schema field and does not start with `_`.

Notes:
- With literal arguments only, the behavior is the same as `array_append`.
- A target field that exists and is not an array makes the operation fail; it is never overwritten.


## Fails when

- The target field exists and is not an array.
- No argument was appended because every reference is missing.
- A resolved argument has a JSON type different from the element type of the array.
- The resulting array is rejected by the schema validation of the target field.

## Examples

### Example 1

A missing reference is skipped and the one that resolves is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any($value, $value_1)
```

#### Input Event

```json
{
  "value": null,
  "value_1": 6,
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
  "value": null,
  "value_1": 6,
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

### Example 2

A literal is appended although the reference after it is missing

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any(5, $value_1)
```

#### Input Event

```json
{
  "value_1": null,
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
  "value_1": null,
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

### Example 3

Fails when every reference is missing because nothing is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any($value, $value_1)
```

#### Input Event

```json
{
  "value": null,
  "value_1": null,
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
  "value": null,
  "value_1": null,
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

A reference that resolves to another type is not skipped and fails the operation

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_any($value)
```

#### Input Event

```json
{
  "value": "hello",
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
  "value": "hello",
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The operation was performed with errors*

### Example 5

Literal numbers are appended in argument order

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



---
# array_append_unique

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: array_append_unique(value, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number, string, object, boolean, array | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Appends to the array stored in the target field the arguments that are not already in it.

Behavior:
- The target field must be an array or be missing; a missing target is created as an empty array first.
- Each argument is a literal of any JSON type or a reference to a field, and is appended as one element,
  in argument order.
- An argument equal to an element already in the array (the elements appended by the same call included)
  is skipped silently. Equality is deep JSON equality: object member order is ignored and numbers compare
  numerically, so `1` equals `1.0`.
- A reference that does not exist in the event fails the whole operation.
- Every element must share one JSON type: the schema type of the target field when it has one, otherwise
  the type of the first element already in the array, otherwise the type of the first argument that
  resolves. Integers and floating-point values count as the same type (number).
- The operation fails when no new element was added.
- The operation is all-or-nothing: the array is rewritten only after every argument has been accepted,
  so a failure leaves the target field unchanged.

Build errors:
- No arguments, or more than 150 arguments.
- A literal argument whose JSON type differs from the element type of a schema target field.
- The target field is not a schema field and does not start with `_`.

Notes:
- A duplicate does not fail the operation by itself: `array_append_unique(5, 6)` on `[1, 5]` succeeds
  and adds `6`; only a call that adds nothing fails.
- A target field that exists and is not an array makes the operation fail; it is never overwritten.


## Fails when

- The target field exists and is not an array.
- Any reference argument does not exist in the event.
- An argument has a JSON type different from the element type of the array.
- No new element was added because every argument is already in the array.
- The resulting array is rejected by the schema validation of the target field.

## Examples

### Example 1

A missing reference fails the whole operation and nothing is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique($value, 9)
```

#### Input Event

```json
{
  "value": null,
  "target_field": [
    1,
    2
  ]
}
```

#### Outcome Event

```json
{
  "value": null,
  "target_field": [
    1,
    2
  ]
}
```

*The operation was performed with errors*

### Example 2

Fails because the only argument is already in the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique($value)
```

#### Input Event

```json
{
  "value": "hello",
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
  "value": "hello",
  "target_field": [
    "hola",
    "hello",
    "salut",
    "ciao"
  ]
}
```

*The operation was performed with errors*

### Example 3

Fails because the only argument is already in the array

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
    5
  ]
}
```

*The operation was performed with errors*

### Example 4

A new value is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique($value)
```

#### Input Event

```json
{
  "value": 5,
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
  "value": 5,
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

### Example 5

The value already present is skipped and the new one is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique(5, 6)
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

### Example 6

A value repeated in the same call is appended once

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique($value, 7)
```

#### Input Event

```json
{
  "value": 7,
  "target_field": [
    1
  ]
}
```

#### Outcome Event

```json
{
  "value": 7,
  "target_field": [
    1,
    7
  ]
}
```

*The operation was successful*

### Example 7

Numbers compare numerically, so 1.0 counts as the 1 already in the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique(1.0)
```

#### Input Event

```json
{
  "target_field": [
    1,
    2
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    1,
    2
  ]
}
```

*The operation was performed with errors*



---
# array_append_unique_any

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: array_append_unique_any(value, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number, string, object, boolean, array | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Appends to the array stored in the target field the arguments that resolve and are not already in it.

Behavior:
- The target field must be an array or be missing; a missing target is created as an empty array first.
- Each argument is a literal of any JSON type or a reference to a field, and is appended as one element,
  in argument order.
- A reference that does not exist in the event is skipped.
- An argument equal to an element already in the array (the elements appended by the same call included)
  is skipped silently. Equality is deep JSON equality: object member order is ignored and numbers compare
  numerically, so `1` equals `1.0`.
- Every element must share one JSON type: the schema type of the target field when it has one, otherwise
  the type of the first element already in the array, otherwise the type of the first argument that
  resolves. Integers and floating-point values count as the same type (number). A reference that exists
  with another type is not skipped: it fails the operation.
- The operation fails when no new element was added, whether because every reference is missing or
  because every value is already in the array.
- The operation is all-or-nothing: the array is rewritten only after every argument has been accepted,
  so a failure leaves the target field unchanged.

Build errors:
- No arguments, or more than 150 arguments.
- A literal argument whose JSON type differs from the element type of a schema target field.
- The target field is not a schema field and does not start with `_`.

Notes:
- With literal arguments only, the behavior is the same as `array_append_unique`.
- A target field that exists and is not an array makes the operation fail; it is never overwritten.


## Fails when

- The target field exists and is not an array.
- A resolved argument has a JSON type different from the element type of the array.
- No new element was added, because every reference is missing or every value is already in the array.
- The resulting array is rejected by the schema validation of the target field.

## Examples

### Example 1

Fails because the first reference is missing and the second one is already in the array

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any($value, $value_1)
```

#### Input Event

```json
{
  "value": null,
  "value_1": 6,
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
  "value": null,
  "value_1": 6,
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

### Example 2

The literal is appended and the missing reference is skipped

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any(5, $value_1)
```

#### Input Event

```json
{
  "value_1": null,
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
  "value_1": null,
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

### Example 3

The missing reference is skipped and the new value is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any($value, $value_1)
```

#### Input Event

```json
{
  "value": null,
  "value_1": 6,
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
  "value": null,
  "value_1": 6,
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

### Example 4

The value already present is skipped and the new one is appended

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_append_unique_any($value, 6)
```

#### Input Event

```json
{
  "value": 5,
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
  "value": 5,
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



---
# array_contains_all

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: array_contains_all($target_field, element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether every argument is an element of the target array.

Behavior:
- Variadic: from 1 to 150 arguments of any JSON type, literals or references.
- Each argument is compared with the elements using deep JSON equality: the types must match (`"1"` is not
  `1`), numbers compare by value (`1` equals `1.0`), strings byte by byte, arrays element by element in
  order, and objects member by member regardless of the member order.
- A reference whose value is an array is matched as a single element; it is not spread.
- True only when all the arguments are found. A reference that does not exist can never be found, so it
  makes the check fail.

Build errors:
- No argument is given, or more than 150.

Notes:
- `array_contains_any` requires a single match; with one argument the two helpers are identical.
- `one_of` is the reverse check: the target value is searched in an argument array.
- `NOT array_contains_all(...)` is the negation; note that this helper is false for a missing or non-array
  target, so the negation is true in those cases.


## Fails when

- The target field does not exist.
- The target field is not an array.
- Any argument is not an element of the array.
- Any reference argument does not exist.

## Examples

### Example 1

A reference that does not exist can never be found, so the check fails although the other element is present.

#### Asset

```yaml
check:
  - target_field: array_contains_all('dracut', $element_1)
```

#### Input Event

```json
{
  "element_1": null,
  "target_field": [
    "dracut",
    "lvm2"
  ]
}
```

*The check was performed with errors*

### Example 2

All the specified strings are elements of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_all($element, 'vz-start', 'thin-provisioning-tools')
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

One of the specified strings ("iscsi") is not an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_all('dracut', 'vz-start', 'iscsi')
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

### Example 4

All the specified numbers are elements of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_all($element, 1, 5)
```

#### Input Event

```json
{
  "element": 2,
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

### Example 5

The target field is a string, not an array.

#### Asset

```yaml
check:
  - target_field: array_contains_all('dracut')
```

#### Input Event

```json
{
  "target_field": "dracut"
}
```

*The check was performed with errors*

### Example 6

All the specified objects are elements of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_all($element, {"key1":"value1"}, {"key2":"value2"})
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

### Example 7

Two of the specified objects are not elements of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_all({"key":"value"}, {"key-non-exists":"value-non-exists"}, {"keyn":"valuen"})
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

### Example 8

The specified object, number and string are all elements of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_all($element, 1, 'value')
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

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: array_contains_any($target_field, element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether at least one argument is an element of the target array.

Behavior:
- Variadic: from 1 to 150 arguments of any JSON type, literals or references.
- Each argument is compared with the elements using deep JSON equality: the types must match (`"1"` is not
  `1`), numbers compare by value (`1` equals `1.0`), strings byte by byte, arrays element by element in
  order, and objects member by member regardless of the member order.
- A reference whose value is an array is matched as a single element; it is not spread.
- True as soon as one argument is found. References that do not exist are skipped: they cannot make the
  check fail while another argument matches.

Build errors:
- No argument is given, or more than 150.

Notes:
- `array_contains_all` requires every argument to be found; with one argument the two helpers are
  identical.
- `one_of` is the reverse check: the target value is searched in an argument array.
- `array_contains_none` is not the negation of this helper: both are false for a missing or non-array
  target and for a reference that does not exist.


## Fails when

- The target field does not exist.
- The target field is not an array.
- None of the arguments that resolve is an element of the array.
- Every argument is a reference that does not exist.

## Examples

### Example 1

A reference that does not exist is skipped, and the other element is present.

#### Asset

```yaml
check:
  - target_field: array_contains_any('dracut', $element_1)
```

#### Input Event

```json
{
  "element_1": null,
  "target_field": [
    "dracut",
    "lvm2"
  ]
}
```

*The check was successful*

### Example 2

The only argument is a reference that does not exist.

#### Asset

```yaml
check:
  - target_field: array_contains_any($element)
```

#### Input Event

```json
{
  "element": null,
  "target_field": [
    "dracut",
    "lvm2"
  ]
}
```

*The check was performed with errors*

### Example 3

All the specified strings are elements of the array, which satisfies the check.

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

### Example 4

One of the specified strings ("dracut") is an element of the array.

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

### Example 5

None of the specified strings is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_any('hello', 'wazuh')
```

#### Input Event

```json
{
  "target_field": [
    "mkinitramfs",
    "cryptroot",
    "dracut"
  ]
}
```

*The check was performed with errors*

### Example 6

One of the specified numbers (1) is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_any($element, 1, 8)
```

#### Input Event

```json
{
  "element": 7,
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

### Example 7

The target field is a string, not an array.

#### Asset

```yaml
check:
  - target_field: array_contains_any('dracut')
```

#### Input Event

```json
{
  "target_field": "dracut"
}
```

*The check was performed with errors*

### Example 8

One of the specified objects is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_any($element, {"key-non-exists":"value-non-exists"}, {"keyn":"valuen"})
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

### Example 9

One of the specified values (1000) is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_any({"keyn":"valuen"}, 1000, 'valuen')
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
# array_contains_none

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: array_contains_none($target_field, element, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| element | object, array, number, string, boolean | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether none of the arguments is an element of the target array.

Behavior:
- Variadic: from 1 to 150 arguments of any JSON type, literals or references.
- Each argument is compared with the elements using deep JSON equality: the types must match (`"1"` is not
  `1`), numbers compare by value (`1` equals `1.0`), strings byte by byte, arrays element by element in
  order, and objects member by member regardless of the member order.
- A reference whose value is an array is matched as a single element; it is not spread.
- True only when every argument is absent from the array. A reference that does not exist cannot be
  proven absent, so it makes the check fail.

Build errors:
- No argument is given, or more than 150.

Notes:
- `array_contains_any` is the positive counterpart; both are false for a missing or non-array target, so
  neither is the `NOT` of the other.
- Not the negation of `array_contains_any`: both are false for a missing or non-array target and for a
  reference that does not exist.


## Fails when

- The target field does not exist.
- The target field is not an array.
- Any argument is an element of the array.
- Any reference argument does not exist.

## Examples

### Example 1

A reference that does not exist cannot be proven absent, so the check fails although the other element is absent.

#### Asset

```yaml
check:
  - target_field: array_contains_none('iscsi', $element_1)
```

#### Input Event

```json
{
  "element_1": null,
  "target_field": [
    "dracut",
    "lvm2"
  ]
}
```

*The check was performed with errors*

### Example 2

All the specified strings are elements of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_none($element, 'vz-start', 'thin-provisioning-tools')
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

One of the specified strings ("dracut") is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_none('dracut', 'hello', 'wazuh')
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

### Example 4

One of the specified numbers (1) is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_none($element, 1, 8)
```

#### Input Event

```json
{
  "element": 7,
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

### Example 5

The target field is a string, not an array.

#### Asset

```yaml
check:
  - target_field: array_contains_none('iscsi')
```

#### Input Event

```json
{
  "target_field": "dracut"
}
```

*The check was performed with errors*

### Example 6

One of the specified objects is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_none($element, {"key-non-exists":"value-non-exists"}, {"keyn":"valuen"})
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

### Example 7

One of the specified values (1000) is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_none({"keyn":"valuen"}, 1000, 'valuen')
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

### Example 8

None of the specified values is an element of the array.

#### Asset

```yaml
check:
  - target_field: array_contains_none($element, 10, 'valuen')
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
# array_length_eq

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: array_length_eq($target_field, expected_length)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| expected_length | number | value | Integers between `-2^63` and `2^63-1` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Checks whether the target array has exactly `expected_length` elements.

Behavior:
- `expected_length` is a literal non-negative integer.
- True when the target exists, is an array and its number of elements equals `expected_length`.

Build errors:
- `expected_length` is a reference.
- `expected_length` is not a JSON integer (`2.0`, `'2'` and `1e1` are rejected) or is negative.

Notes:
- Only the equality comparison exists; there is no helper for other length comparisons.
- `array_length_eq(0)` is true only for an array that is present and empty.
- `is_array` checks the type alone.


## Fails when

- The target field does not exist.
- The target field is not an array.
- The number of elements differs from `expected_length`.

## Examples

### Example 1

The array has one element.

#### Asset

```yaml
check:
  - target_field: array_length_eq(1)
```

#### Input Event

```json
{
  "target_field": [
    "single_element"
  ]
}
```

*The check was successful*

### Example 2

The array has three elements.

#### Asset

```yaml
check:
  - target_field: array_length_eq(3)
```

#### Input Event

```json
{
  "target_field": [
    "first",
    "second",
    "third"
  ]
}
```

*The check was successful*

### Example 3

The array has five numeric elements.

#### Asset

```yaml
check:
  - target_field: array_length_eq(5)
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

The array has one element, not two.

#### Asset

```yaml
check:
  - target_field: array_length_eq(2)
```

#### Input Event

```json
{
  "target_field": [
    "element"
  ]
}
```

*The check was performed with errors*

### Example 5

The array has two elements, not one.

#### Asset

```yaml
check:
  - target_field: array_length_eq(1)
```

#### Input Event

```json
{
  "target_field": [
    "first",
    "second"
  ]
}
```

*The check was performed with errors*

### Example 6

The target field is a string, not an array.

#### Asset

```yaml
check:
  - target_field: array_length_eq(1)
```

#### Input Event

```json
{
  "target_field": "not_an_array"
}
```

*The check was performed with errors*

### Example 7

The target field is a number, not an array.

#### Asset

```yaml
check:
  - target_field: array_length_eq(0)
```

#### Input Event

```json
{
  "target_field": 42
}
```

*The check was performed with errors*

### Example 8

A negative length is rejected at build time.

#### Asset

```yaml
check:
  - target_field: array_length_eq(-1)
```

#### Input Event

```json
{
  "target_field": [
    "element"
  ]
}
```

*The check was performed with errors*



---
# array_to_object

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: array_to_object(source_array, key_path, value_path, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source_array | array | reference | Any array |
| key_path | string | value | Any string |
| value_path | string | value | Any string |
| mode (option, optional) | string | value | raw_keys |


## Output

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Builds an object from an array of objects, taking from every element a key and a value at the
given dot paths, and maps it to the target field.

Behavior:
- `key_path` and `value_path` are dot paths relative to each element (for example `Name` or
  `Value`); `.` selects the whole element.
- Every element that is an object and holds a non-empty string at `key_path` and any value at
  `value_path` (`null`, an array or an object included) produces one member of the result. Other
  elements are skipped.
- Unless `mode` is `raw_keys`, each key is normalized: ASCII `A-Z` is lowercased; `a-z`, `0-9`
  and `_` are kept (consecutive `_` collapse into one); a space, `/`, `.`, `-`, `\` or `:` becomes
  a single `_`, never leading or trailing; every other byte is dropped. camelCase is not split:
  `Request.Type` becomes `request_type` and `UserAgent` becomes `useragent`.
- A key whose normalized form is empty is skipped. The last element with a given key wins.
- On success the whole target value is replaced by the new object.

Build errors:
- Fewer than 3 or more than 4 arguments.
- `source_array` is not a reference, or it is a schema field whose elements are not objects.
- `key_path` or `value_path` is not a string literal, is empty, or starts with `/` (JSON pointers are not
  accepted).
- `mode` is given and is not the literal `raw_keys`.

Notes:
- The target can be a schema object field or a temporary (`_`) field.
- `array_to_object_changes` builds one nested object per key from a new and an old value.
- `snake_case_keys` applies the same key normalization to an existing object.


## Fails when

- `source_array` is missing or is not an array
- no element produces a member, so the result would be empty

## Examples

### Example 1

Build the object from the Name and Value of every element, with normalized keys

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object($source_array, 'Name', 'Value')
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

Keep the keys verbatim with the mode raw_keys and copy values of any JSON type

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object($source_array, 'Name', 'Value', 'raw_keys')
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

Store the whole element under its key when the value path is a dot

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object($source_array, 'Name', '.')
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "Request",
      "Value": "GET"
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "Request",
      "Value": "GET"
    }
  ],
  "target_field": {
    "request": {
      "Name": "Request",
      "Value": "GET"
    }
  }
}
```

*The operation was successful*

### Example 4

Skip the elements that are not objects, have no non-empty string key or have no value

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object($source_array, 'Name', 'Value')
```

#### Input Event

```json
{
  "source_array": [
    1,
    {
      "Value": "no-key"
    },
    {
      "Name": "",
      "Value": "empty-key"
    },
    {
      "Name": "NoValue"
    },
    {
      "Name": "Keep Me",
      "Value": 2
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    1,
    {
      "Value": "no-key"
    },
    {
      "Name": "",
      "Value": "empty-key"
    },
    {
      "Name": "NoValue"
    },
    {
      "Name": "Keep Me",
      "Value": 2
    }
  ],
  "target_field": {
    "keep_me": 2
  }
}
```

*The operation was successful*

### Example 5

Fail when every element is skipped, here because the key normalizes to an empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object($source_array, 'Name', 'Value')
```

#### Input Event

```json
{
  "source_array": [
    {
      "Name": "***",
      "Value": 1
    }
  ]
}
```

#### Outcome Event

```json
{
  "source_array": [
    {
      "Name": "***",
      "Value": 1
    }
  ]
}
```

*The operation was performed with errors*

### Example 6

Fail when the source array reference is missing

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object($source_array, 'Name', 'Value')
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
# array_to_object_changes

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: array_to_object_changes(source_array, key_path, new_value_path, old_value_path, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source_array | array | reference | Any array |
| key_path | string | value | Any string |
| new_value_path | string | value | Any string |
| old_value_path | string | value | Any string |
| mode (option, optional) | string | value | raw_keys |


## Output

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Builds an object of changes from an array of objects, taking from every element a key, a new value
and an old value at the given dot paths, and maps it to the target field.

Behavior:
- `key_path`, `new_value_path` and `old_value_path` are dot paths relative to each element (for
  example `Name`, `NewValue` and `OldValue`); `.` selects the whole element.
- Every element that is an object and holds a non-empty string at `key_path` and any value at
  `new_value_path` produces one member of the result; the old value is optional. Other elements
  are skipped.
- Each member is an object with the new value stored under the same relative path as
  `new_value_path` and the old value under the one of `old_value_path` (`changes.new` nests it as
  `changes` then `new`): with `Name`, `NewValue` and `OldValue`,
  `[{"Name": "Included Updated Properties", "NewValue": "X", "OldValue": "Y"}]` gives
  `{"included_updated_properties": {"NewValue": "X", "OldValue": "Y"}}`.
- An old value that is an empty string or made of spaces only is dropped.
- Unless `mode` is `raw_keys`, each key is normalized as `array_to_object` does (lowercase, with
  `_` for separators and other punctuation dropped). A key whose normalized form is empty is
  skipped. A later element with the same key overwrites the members it provides: one without an
  old value leaves the previous old value in place.
- On success the whole target value is replaced by the new object.

Build errors:
- Fewer than 4 or more than 5 arguments.
- `source_array` is not a reference, or it is a schema field whose elements are not objects.
- `key_path`, `new_value_path` or `old_value_path` is not a string literal, is empty, or starts with `/`
  (JSON pointers are not accepted).
- `mode` is given and is not the literal `raw_keys`.

Notes:
- The target can be a schema object field or a temporary (`_`) field.
- `array_to_object` maps one value per key, without the nested object and the blank filtering.


## Fails when

- `source_array` is missing or is not an array
- no element produces a member, so the result would be empty

## Examples

### Example 1

Build one object per normalized key with its new and old values, dropping an empty old value

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object_changes($source_array, 'Name', 'NewValue', 'OldValue')
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

Keep the keys verbatim with the mode raw_keys

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object_changes($source_array, 'Name', 'NewValue', 'OldValue', 'raw_keys')
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

Keep an element that only provides a new value

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object_changes($source_array, 'Name', 'NewValue', 'OldValue')
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

Drop an old value made of spaces only

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object_changes($source_array, 'Name', 'NewValue', 'OldValue')
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

Fail when the only element has no new value, so the result would be empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object_changes($source_array, 'Name', 'NewValue', 'OldValue')
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

Fail when the source array reference is missing

#### Asset

```yaml
normalize:
  - map:
      - target_field: array_to_object_changes($source_array, 'Name', 'NewValue', 'OldValue')
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
# one_of

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: one_of($target_field, values)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| values | array | value or reference | [number, string, boolean, object, array] |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the target value is one of the elements of `values`.

Behavior:
- The target may hold any JSON type, `null` included.
- `values` is an array literal, a definition or a reference to an array field.
- Each element is compared with the target using deep JSON equality: the types must match (`"1"` is not
  `1`), numbers compare by value (`1` equals `1.0`), strings byte by byte, arrays element by element in
  order, and objects member by member regardless of the member order.

Build errors:
- `values` is a literal that is not an array.

Notes:
- `array_contains_all` and `array_contains_any` are the reverse check: the target is the array and the
  arguments are the candidates.
- `string_eq`, `number_eq` and `int_eq` compare against a single candidate with type-specific rules.


## Fails when

- The target field does not exist.
- The reference given as `values` does not exist or is not an array.
- No element of `values` is equal to the target value.

## Examples

### Example 1

The reference given as values does not exist.

#### Asset

```yaml
check:
  - target_field: one_of($values)
```

#### Input Event

```json
{
  "values": null,
  "target_field": 10
}
```

*The check was performed with errors*

### Example 2

The target value is not in the array.

#### Asset

```yaml
check:
  - target_field: one_of($values)
```

#### Input Event

```json
{
  "values": [
    1,
    2,
    3,
    4
  ],
  "target_field": 10
}
```

*The check was performed with errors*

### Example 3

The target string is not in the array.

#### Asset

```yaml
check:
  - target_field: one_of(["hello"])
```

#### Input Event

```json
{
  "target_field": "wazuh"
}
```

*The check was performed with errors*

### Example 4

The target object equals an element of the array.

#### Asset

```yaml
check:
  - target_field: one_of($values)
```

#### Input Event

```json
{
  "values": [
    {
      "key": "value"
    }
  ],
  "target_field": {
    "key": "value"
  }
}
```

*The check was successful*

### Example 5

The target array equals an element of the array.

#### Asset

```yaml
check:
  - target_field: one_of([[true,"hello",2]])
```

#### Input Event

```json
{
  "target_field": [
    true,
    "hello",
    2
  ]
}
```

*The check was successful*

### Example 6

Numbers are compared by value, so 2.0 equals the element 2.

#### Asset

```yaml
check:
  - target_field: one_of($values)
```

#### Input Event

```json
{
  "values": [
    1,
    2,
    3
  ],
  "target_field": 2.0
}
```

*The check was successful*

### Example 7

The types must match, so the number 1 does not equal the string "1".

#### Asset

```yaml
check:
  - target_field: one_of(["1","2"])
```

#### Input Event

```json
{
  "target_field": 1
}
```

*The check was performed with errors*



---
# delete

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: delete()
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| [number, string, object, boolean, array] | - |


## Description

Deletes the target field from the event.

Behavior:
- Removes the target field together with its whole subtree, whatever its type.
- Takes no arguments.

Build errors:
- Any argument is given.
- The target field is not a schema field and does not start with `_`.

Notes:
- With the root `.` as target the entire event becomes `null`.
- A failure does not stop the following operations of the map block.
- `delete_fields_with_value` and `delete_custom_fields` delete members of an object by value or by name.


## Fails when

- The target field does not exist.

## Examples

### Example 1

Deletes a string target field

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
  "target_field": "-- Hi wazuh! --"
}
```

*The operation was successful*

### Example 2

Deletes an object target field with its subtree

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
  "target_field": {
    "key": "value"
  }
}
```

*The operation was successful*

### Example 3

Deletes an array target field

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
  "target_field": [
    1,
    2,
    3,
    4
  ]
}
```

*The operation was successful*



---
# delete_custom_fields

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
.: delete_custom_fields()
```

## Target field

| Path | Type | Possible values |
| ---- | ---- | --------------- |
| . | object | Any object |


## Description

Deletes the top-level fields of the event that are not defined in the schema.

Behavior:
- The target field must be the root of the event (`.`); the helper takes no arguments.
- Each top-level key of the event is checked by name against the schema: a key that is not a top-level
  schema field is removed, the temporary fields that start with `_` included.
- The check is not recursive: a custom key nested inside a schema object (for example `host.custom`) is
  kept.
- The operation always succeeds, also when nothing is removed.

Build errors:
- The target field is not the root `.`.
- Any argument is given.

Notes:
- Temporary `_` fields are removed too, so run it after the last use of any temporary field.
- `delete` removes one field and `delete_fields_with_value` removes the members of an object by value.


## Fails when

- Never; once the asset is built the helper always succeeds.

---
# delete_fields_with_value

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: delete_fields_with_value(value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number, string, object, boolean, array | value or reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Deletes the immediate children of the target object whose value equals `value`.

Behavior:
- The target field must be an object.
- `value` is a literal of any JSON type (`null` included) or a reference to a field.
- Every top-level member whose value is equal to `value` is removed. Equality is deep JSON equality: the
  types must match (except that integers and floating-point values compare numerically, so `1` equals
  `1.0`), object member order is ignored and arrays compare element by element.
- The check is not recursive: nested objects are not inspected.
- The operation succeeds even when nothing is deleted.

Build errors:
- A number of arguments other than 1.
- The target field is not a schema field and does not start with `_`.

Notes:
- A reference that does not exist in the event compares with nothing: nothing is deleted and the operation
  succeeds.


## Fails when

- The target field does not exist or is not an object.

## Examples

### Example 1

Deletes the children equal to the given string

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

Deletes the children equal to the integer 1

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

Deletes the children equal to the given floating-point number

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

Numbers compare numerically, so the integer 1 deletes a child holding 1.0

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
    "a": 1.0,
    "b": 2
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

### Example 5

Deletes the children equal to the given boolean

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value(true)
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

### Example 6

Deletes the children equal to the given object

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value({"k":1})
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

### Example 7

Deletes the children equal to the given array

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value([1,2])
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

### Example 8

Succeeds without deleting anything when no child matches

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

### Example 9

A missing reference deletes nothing and the operation succeeds

#### Asset

```yaml
normalize:
  - map:
      - target_field: delete_fields_with_value($value)
```

#### Input Event

```json
{
  "value": null,
  "target_field": {
    "a": "keep",
    "b": 1
  }
}
```

#### Outcome Event

```json
{
  "value": null,
  "target_field": {
    "a": "keep",
    "b": 1
  }
}
```

*The operation was successful*

### Example 10

A null literal deletes nothing when no child holds null

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
# has_only_keys

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: has_only_keys($target_field, keys)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| keys | array | value or reference | Any array |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Checks whether every top-level key of the target object is in `keys`.

Behavior:
- `keys` is an array of strings: a literal, a definition or a reference to an array field.
- True when the set of top-level member names of the target is a subset of `keys`. Entries of `keys` that
  are not in the object are fine, nested keys are not examined, and an empty object passes.

Build errors:
- `keys` is a literal that is not an array, or contains an element that is not a string.
- `keys` is a reference to a schema field whose type is not a string type.
- The target is a schema field whose type is not an object type.

Notes:
- `is_key_of` checks the opposite direction: a target string against the keys of an object.
- An empty target object cannot be exercised by the helper test harness, which leaves such a field unmapped.


## Fails when

- The target field does not exist.
- The target field is not an object.
- The reference given as `keys` does not exist, is not an array, or contains an element that is not a string.
- The target object has a top-level key that is not in `keys`.

## Examples

### Example 1

The reference given as keys does not exist.

#### Asset

```yaml
check:
  - target_field: has_only_keys($keys)
```

#### Input Event

```json
{
  "keys": null,
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z"
  }
}
```

*The check was performed with errors*

### Example 2

Every key of the object is in the list.

#### Asset

```yaml
check:
  - target_field: has_only_keys($keys)
```

#### Input Event

```json
{
  "keys": [
    "ts",
    "host"
  ],
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z",
    "host": "192.168.4.43"
  }
}
```

*The check was successful*

### Example 3

The list may contain entries that are not keys of the object.

#### Asset

```yaml
check:
  - target_field: has_only_keys(["ts","host","other"])
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

### Example 4

The object has a key that is not in the list.

#### Asset

```yaml
check:
  - target_field: has_only_keys($keys)
```

#### Input Event

```json
{
  "keys": [
    "ts",
    "host"
  ],
  "target_field": {
    "ts": "2021-01-03T01:19:32.488179Z",
    "host": "192.168.4.43",
    "other_key": "some_value"
  }
}
```

*The check was performed with errors*

### Example 5

A list element that is not a string is rejected, at build time for a literal and at run time for a reference.

#### Asset

```yaml
check:
  - target_field: has_only_keys(["ts",9999,"other"])
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

*The check was performed with errors*

### Example 6

Nested keys are not examined.

#### Asset

```yaml
check:
  - target_field: has_only_keys($keys)
```

#### Input Event

```json
{
  "keys": [
    "a"
  ],
  "target_field": {
    "a": {
      "b": 1
    }
  }
}
```

*The check was successful*

### Example 7

The target field is a string, not an object.

#### Asset

```yaml
check:
  - target_field: has_only_keys(["ts"])
```

#### Input Event

```json
{
  "target_field": "ts"
}
```

*The check was performed with errors*



---
# is_key_of

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_key_of($target_field, object)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| object | object | value or reference | Any object |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is a key of `object`.

Behavior:
- The target string is matched literally against the top-level member names of `object`: there is no
  dot-path descent, so `a.b` only matches a member literally named `a.b`, never a member `b` nested in
  `a`.
- `object` is an object literal, a definition or a reference to an object field.
- The value stored under the key is irrelevant; a key holding `null` counts.

Build errors:
- `object` is a literal that is not an object.
- `object` is a reference to a schema field whose type is not `object` (`nested` and `flat_object`
  fields are rejected).
- The target is a schema field whose type is not a string type.

Notes:
- `in_kvdb` is the same check against a KVDB.
- `has_only_keys` checks the opposite direction: the keys of a target object against a list.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The reference given as `object` does not exist or is not an object.
- No top-level key of `object` is equal to the target string.

## Examples

### Example 1

The reference given as object does not exist.

#### Asset

```yaml
check:
  - target_field: is_key_of($object)
```

#### Input Event

```json
{
  "object": null,
  "target_field": "key"
}
```

*The check was performed with errors*

### Example 2

The target string is not a key of the object.

#### Asset

```yaml
check:
  - target_field: is_key_of($object)
```

#### Input Event

```json
{
  "object": {
    "key": "value"
  },
  "target_field": "key-not-exist"
}
```

*The check was performed with errors*

### Example 3

The target string is a key of the object.

#### Asset

```yaml
check:
  - target_field: is_key_of({"key":"value"})
```

#### Input Event

```json
{
  "target_field": "key"
}
```

*The check was successful*

### Example 4

A key containing a dot is matched literally.

#### Asset

```yaml
check:
  - target_field: is_key_of($object)
```

#### Input Event

```json
{
  "object": {
    "a.b": 1
  },
  "target_field": "a.b"
}
```

*The check was successful*

### Example 5

The target is not read as a path, so a.b does not match the nested member b of a.

#### Asset

```yaml
check:
  - target_field: is_key_of({"a":{"b":1}})
```

#### Input Event

```json
{
  "target_field": "a.b"
}
```

*The check was performed with errors*

### Example 6

A key holding null counts.

#### Asset

```yaml
check:
  - target_field: is_key_of($object)
```

#### Input Event

```json
{
  "object": {
    "key": null
  },
  "target_field": "key"
}
```

*The check was successful*

### Example 7

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: is_key_of({"key":"value"})
```

#### Input Event

```json
{
  "target_field": 42
}
```

*The check was performed with errors*



---
# lookup

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: lookup(object, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| object | object | value or reference | Any object |
| key | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Copies the value stored under `key` in `object` to the target field.

Behavior:
- `object` is a literal object, a definition, or a reference to a field holding an object.
- `key` is a literal string or a reference to a string field. It is matched literally against the
  top-level keys of the object: `a.b` names the member called `a.b`, it does not descend into `a` and
  then `b`.
- The value may be of any JSON type; it replaces the target field, which is created when missing.
- When the target field is a schema field the value is validated against its type, and an object value
  may only contain fields allowed under the target.

Build errors:
- `object` is a literal that is not an object, or a reference to a schema field that is not an object.
- `key` is a literal that is not a string.
- `key` is an empty literal, or a reference to a schema field that is not a string.
- A number of arguments other than 2.
- The target field is not a schema field and does not start with `_`.

Notes:
- `lookup_merge` merges the value into the target instead of replacing it.
- `kvdb_lookup` does the same lookup against a KVDB.


## Fails when

- The key reference does not exist or is not a string.
- The object reference does not exist or is not an object.
- The key is not a member of the object.
- The value does not pass the schema validation of the target field.

## Examples

### Example 1

A literal key selects the member of a literal object

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup({"key":"name","key2":"surname"}, 'key2')
```

#### Input Event

```json
{
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "target_field": "surname"
}
```

*The operation was successful*

### Example 2

A referenced key selects the member of a referenced object

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup($object, $key)
```

#### Input Event

```json
{
  "object": {
    "key": "name",
    "key2": "surname"
  },
  "key": "key2",
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "object": {
    "key": "name",
    "key2": "surname"
  },
  "key": "key2",
  "target_field": "surname"
}
```

*The operation was successful*

### Example 3

The string value of the key replaces the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup({"key":"name","key2":"surname"}, 'key2')
```

#### Input Event

```json
{
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "target_field": "surname"
}
```

*The operation was successful*

### Example 4

The object value of the key replaces the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup($object, $key)
```

#### Input Event

```json
{
  "object": {
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
  "object": {
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

### Example 5

A dotted key is matched literally against the member named a.b

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup({"a.b":"x","a":{"b":"y"}}, 'a.b')
```

#### Input Event

```json
{
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "target_field": "x"
}
```

*The operation was successful*

### Example 6

Fails when the key is not a member of the object

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup($object, $key)
```

#### Input Event

```json
{
  "object": {
    "key": "name",
    "key2": "surname"
  },
  "key": "missing",
  "target_field": "name"
}
```

#### Outcome Event

```json
{
  "object": {
    "key": "name",
    "key2": "surname"
  },
  "key": "missing",
  "target_field": "name"
}
```

*The operation was performed with errors*



---
# lookup_merge

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: lookup_merge(object, key, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| object | object | value or reference | Any object |
| key | string | value or reference | Any string |
| mode (option, optional) | string | value | deep |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Merges the value stored under `key` in `object` into the target field.

Behavior:
- `object` and `key` work as in `lookup`: a literal object, a definition or a reference to an object,
  and a literal string or a reference to a string matched literally against the top-level keys.
- The target field must already exist and have the same type as the value: both objects, or both arrays.
- Objects, default mode: the top-level members of the value are added to the target; on a shared key the
  value wins and a nested object is replaced as a whole.
- Objects, `deep` mode: a shared key whose value is an object or an array is merged recursively; a scalar
  value overwrites the target member.
- Arrays, both modes: a de-duplicated union; the elements of the value that are not already in the
  target are appended in their order, nothing is removed or duplicated.
- The source object is not modified.
- When the target field is a schema field the value is validated against its type before the merge.

Build errors:
- `object` is a literal that is not an object, or a reference to a schema field that is not an object.
- `key` is a literal that is not a string.
- `key` is an empty literal, or a reference to a schema field that is not a string.
- A third argument other than the literal `deep`, or more than 3 arguments.
- The target field is a schema field that is not an object.

Notes:
- In `deep` mode an object or array in the value whose counterpart in the target has another type fails
  the operation; the members merged before the conflict stay modified.
- `merge` merges a whole field (and deletes it afterwards); `kvdb_lookup_merge` merges a KVDB value.


## Fails when

- The key reference does not exist or is not a string, or the key is not a member of the object.
- The object reference does not exist or is not an object.
- The target field does not exist or its type differs from the type of the value.
- The value is neither an object nor an array.
- In deep mode, a nested member is an object or array in the value and has another type in the target.

## Examples

### Example 1

The members of the selected value are added to the target object

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge({"input_key_1":{"v1":"k1"},"input_key_2":{"v2":"k2"}}, 'input_key_1')
```

#### Input Event

```json
{
  "target_field": {
    "v0": "k0"
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "v0": "k0",
    "v1": "k1"
  }
}
```

*The operation was successful*

### Example 2

Fails when the key is not a member of the object

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge($object, $key)
```

#### Input Event

```json
{
  "object": {
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
  "object": {
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

Without deep a nested object of the value replaces the one of the target as a whole

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge({"input_key_1":{"v1":"k1","nested":{"n1":"value1"}},"input_key_2":{"v2":"k2"}}, 'input_key_1')
```

#### Input Event

```json
{
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

On a shared key the value wins

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge($object, $key)
```

#### Input Event

```json
{
  "object": {
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
  "object": {
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

### Example 5

In deep mode a nested object is merged with the one of the target

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge({"input_key_1":{"v1":"k1","nested":{"n1":"value1"}},"input_key_2":{"v2":"k2"}}, 'input_key_1', 'deep')
```

#### Input Event

```json
{
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

### Example 6

In deep mode a nested object that only exists in the value is added

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge($object, $key, 'deep')
```

#### Input Event

```json
{
  "object": {
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
  "object": {
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

### Example 7

In deep mode the existing members of the target are kept while nested objects are merged

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge({"input_key_1":{"v1":"k1","nested":{"n1":"value1"}},"input_key_2":{"v2":"k2"}}, 'input_key_1', 'deep')
```

#### Input Event

```json
{
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

### Example 8

In deep mode a key that is not a member of the object fails as well

#### Asset

```yaml
normalize:
  - map:
      - target_field: lookup_merge($object, $key, 'deep')
```

#### Input Event

```json
{
  "object": {
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
  "object": {
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
# merge

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: merge(source, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source | object | reference | An object, or an array when the target field is an array |
| mode (option, optional) | string | value | deep |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Merges the field referenced by `source` into the target field and deletes the source field.

Behavior:
- Both fields must exist and have the same type: both objects, or both arrays.
- Objects, default mode: the top-level members of the source are added to the target; on a shared key the
  source wins and a nested object is replaced as a whole.
- Objects, `deep` mode: a shared key whose source value is an object or an array is merged recursively; a
  scalar source value overwrites the target member, even when that member is an object.
- Arrays, both modes: a de-duplicated union; the target keeps its order, the source elements that are not
  already present are appended in source order, and an element repeated in the source is added once.
- After a successful merge the source field is erased from the event.
- When the target field is a schema field, every top-level member of an object source must be a field
  allowed under it (checked at runtime).

Build errors:
- `source` is not a reference (a literal or definition object is rejected).
- A second argument other than the literal `deep`, or more than 2 arguments.
- In `deep` mode, the target field is a schema field that is not an object.
- The target field is not a schema field and does not start with `_`.

Notes:
- The source field is deleted: `a: merge($a)` erases `a` after merging it into itself, and a source nested
  inside the target disappears after the merge.
- In `deep` mode an object or array in the source whose counterpart in the target has another type fails
  the operation; the members merged before the conflict stay modified and the source is not deleted.
- `lookup_merge` merges a value out of an object without deleting anything; `rename` moves a field but
  refuses to overwrite the target.


## Fails when

- The source or the target field does not exist.
- The source and the target field have different types, or are not both objects or both arrays.
- In deep mode, a nested member is an object or array in the source and has another type in the target.

## Examples

### Example 1

The members of the source object are added to the target object

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source)
```

#### Input Event

```json
{
  "source": {
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
  "source": {
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

Without deep a nested object of the source replaces the one of the target as a whole

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source)
```

#### Input Event

```json
{
  "source": {
    "a": {
      "d": "e"
    }
  },
  "target_field": {
    "a": {
      "b": "c"
    }
  }
}
```

#### Outcome Event

```json
{
  "source": {
    "a": {
      "d": "e"
    }
  },
  "target_field": {
    "a": {
      "d": "e"
    }
  }
}
```

*The operation was successful*

### Example 3

Arrays merge as a union that keeps the target order and appends the new elements

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source)
```

#### Input Event

```json
{
  "source": [
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
  "source": [
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

### Example 4

An element repeated in the source array is added once

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source)
```

#### Input Event

```json
{
  "source": [
    1,
    1,
    2
  ],
  "target_field": [
    1
  ]
}
```

#### Outcome Event

```json
{
  "source": [
    1,
    1,
    2
  ],
  "target_field": [
    1,
    2
  ]
}
```

*The operation was successful*

### Example 5

Fails when the source is an array and the target an object

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source)
```

#### Input Event

```json
{
  "source": [
    1
  ],
  "target_field": {
    "a": 1
  }
}
```

#### Outcome Event

```json
{
  "source": [
    1
  ],
  "target_field": {
    "a": 1
  }
}
```

*The operation was performed with errors*

### Example 6

In deep mode nested objects are merged recursively

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source, 'deep')
```

#### Input Event

```json
{
  "source": {
    "a": {
      "d": "e"
    }
  },
  "target_field": {
    "a": {
      "b": "c"
    }
  }
}
```

#### Outcome Event

```json
{
  "source": {
    "a": {
      "d": "e"
    }
  },
  "target_field": {
    "a": {
      "b": "c",
      "d": "e"
    }
  }
}
```

*The operation was successful*

### Example 7

In deep mode a scalar of the source overwrites the member of the target

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source, 'deep')
```

#### Input Event

```json
{
  "source": {
    "key": "new"
  },
  "target_field": {
    "key": "old",
    "other": 1
  }
}
```

#### Outcome Event

```json
{
  "source": {
    "key": "new"
  },
  "target_field": {
    "key": "new",
    "other": 1
  }
}
```

*The operation was successful*

### Example 8

In deep mode arrays merge as the same de-duplicated union

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source, 'deep')
```

#### Input Event

```json
{
  "source": [
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
  "source": [
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

### Example 9

In deep mode fields of different types are not merged either

#### Asset

```yaml
normalize:
  - map:
      - target_field: merge($source, 'deep')
```

#### Input Event

```json
{
  "source": [
    1
  ],
  "target_field": {
    "a": 1
  }
}
```

#### Outcome Event

```json
{
  "source": [
    1
  ],
  "target_field": {
    "a": 1
  }
}
```

*The operation was performed with errors*



---
# rename

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: rename(source)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source | object, array, string, number, boolean | reference | Any value of the listed types |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Moves the field referenced by `source` to the target field.

Behavior:
- The value is copied to the target field, whatever its type, and the source field is erased.
- The target field must not exist: an existing target is never overwritten.
- Direction: `target: rename($source)` moves `source` to `target`.

Build errors:
- `source` is not a reference.
- The source or the target field is not a schema field and does not start with `_`.
- A number of arguments other than 1.

Notes:
- The moved value is not validated against the schema type of the target field.
- To overwrite an existing target, map the value and then `delete` the source.


## Fails when

- The target field already exists.
- The source field does not exist.

## Examples

### Example 1

Fails and keeps the target unchanged because the target field already exists

#### Asset

```yaml
normalize:
  - map:
      - target_field: rename($source)
```

#### Input Event

```json
{
  "source": 42,
  "target_field": "elapsed_time"
}
```

#### Outcome Event

```json
{
  "source": 42,
  "target_field": "elapsed_time"
}
```

*The operation was performed with errors*



---
# snake_case_keys

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: snake_case_keys([mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| mode (option, optional) | string | value | deep |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string] | - |


## Description

Rewrites the keys of the target object as lowercase snake_case; applied to an array it rewrites its
strings and the keys of its objects, and applied to a string it rewrites the string itself.

Behavior:
- Every key or string is normalized the same way: ASCII letters are lowercased and letters and digits are
  kept; a space, `/`, `.`, `-`, `\`, `:` or `_` becomes a single `_` (a run of them collapses into one and
  a leading `_` is never emitted); every other character, non-ASCII bytes included, is dropped; a trailing
  `_` is removed. So `Full Name` becomes `full_name` and `_tmp` becomes `tmp`.
- Object target: its keys are renamed. Nested objects are visited only in `deep` mode, which also visits
  the arrays held by object members (their objects get their keys renamed, their strings are kept).
- Array target: its string elements are normalized and its object elements get their keys renamed; nested
  arrays are always processed, with or without `deep`.
- String target: the string itself is normalized.
- The change is atomic: every key and string is validated first, and the event is rewritten only when all
  of them are accepted.

Build errors:
- An argument other than the literal `deep`.
- More than 1 argument.

Notes:
- Two keys that normalize to the same name make the operation fail; nothing is silently overwritten.
- A key or string that normalizes to an empty string makes the operation fail.
- A visited array that holds a number, a boolean or `null` makes the operation fail; in `deep` mode this
  includes the arrays under object members, such as `{"ports": [80]}`.
- Leading digits are kept: `123abc` stays `123abc`.


## Fails when

- The target field does not exist, or is a number, a boolean or null.
- Two keys normalize to the same name.
- A key or a string normalizes to an empty string.
- A visited array contains a number, a boolean or null.

## Examples

### Example 1

Keys that are already normalized are kept

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

Keys are lowercased and separators become underscores

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

Fails because both keys normalize to hello_world

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": {
    "hello world": 1,
    "hello-world": 2
  }
}
```

*The operation was performed with errors*

### Example 4

A key starting with a digit is kept as it is

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

A leading underscore is never emitted

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
```

#### Input Event

```json
{
  "target_field": {
    "_Tmp Key": 1
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "tmp_key": 1
  }
}
```

*The operation was successful*

### Example 6

Without deep only the top-level keys are renamed

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
```

#### Input Event

```json
{
  "target_field": {
    "Outer Key": {
      "Inner Key": 1
    }
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "outer_key": {
      "Inner Key": 1
    }
  }
}
```

*The operation was successful*

### Example 7

The strings of an array target are normalized

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 8

The keys of the objects of an array target are renamed

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 9

An array mixing strings and objects is supported

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 10

Fails because the array holds a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": [
    1,
    {
      "a": 1
    }
  ]
}
```

*The operation was performed with errors*

### Example 11

Fails because the array holds a boolean

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": [
    true,
    {
      "a": 1
    }
  ]
}
```

*The operation was performed with errors*

### Example 12

Fails because the array holds null

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": [
    null,
    {
      "a": 1
    }
  ]
}
```

*The operation was performed with errors*

### Example 13

Nested arrays are processed without deep

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 14

Strings of an array may normalize to the same value

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 15

Fails because every character of the key is dropped and the key becomes empty

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": {
    "***": 1
  }
}
```

*The operation was performed with errors*

### Example 16

Runs of backslashes, slashes, colons and spaces collapse into single underscores

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 17

A trailing separator does not leave a trailing underscore

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 18

Fails because a key made only of separators normalizes to an empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": {
    ":\\ /- .": 1
  }
}
```

*The operation was performed with errors*

### Example 19

Backslashes and colons inside strings become underscores

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 20

A string target is normalized itself

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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

### Example 21

Fails because the string normalizes to an empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys()
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
  "target_field": "::::"
}
```

*The operation was performed with errors*

### Example 22

In deep mode the keys of nested objects are renamed too

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys('deep')
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

### Example 23

In deep mode the objects inside an array member get their keys renamed

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys('deep')
```

#### Input Event

```json
{
  "target_field": {
    "Items": [
      {
        "Full Name": "Ana"
      }
    ]
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "items": [
      {
        "full_name": "Ana"
      }
    ]
  }
}
```

*The operation was successful*

### Example 24

In deep mode an array member that holds a number makes the operation fail

#### Asset

```yaml
normalize:
  - map:
      - target_field: snake_case_keys('deep')
```

#### Input Event

```json
{
  "target_field": {
    "Ports": [
      80
    ]
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "Ports": [
      80
    ]
  }
}
```

*The operation was performed with errors*



---
# float_calculate

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: float_calculate(operator, operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operator (option) | string | value | mul, div, sub, sum |
| operand_left | number | value or reference | Any number |
| operand_right | number | value or reference | Any number |


## Output

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Applies an arithmetic operator to two or more numeric operands, from left to right in double
precision, and maps the double result to the target field.

Behavior:
- `operator` is one of the literals `sum`, `sub`, `mul` and `div`; it is applied to the first two
  operands, then to that result and the next operand, and so on.
- Operands can be integers or floating-point numbers, as literals or references.
- The result is always a double, even for integer operands: `1 + 1` gives `2.0`.
- A result that is infinite or NaN fails.

Build errors:
- `operator` is not a literal or is not one of the four names.
- An operand literal that is not a number.
- With `div`, a literal `0` in any position after the first operand.

Notes:
- The result is a double: a `long` or `integer` target rejects it at runtime.
- `int_calculate` computes exact 64-bit integers.


## Fails when

- an operand reference is missing or is not a number
- a divisor read from a reference is 0
- the result is infinite or NaN (the double range is exceeded)

## Notes

- Division by zero is not allowed (the function will fail).

- The arithmetic is done in double precision; a result that is infinite or NaN fails.

## Examples

### Example 1

Fail on a sum whose result is infinite

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

Fail on a sum whose result is infinite

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

Fail on a subtraction whose result is infinite

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

Fail on a subtraction whose result is infinite

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

Fail on a multiplication whose result is infinite

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

Fail on a multiplication whose result is infinite

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

Divide a zero numerator, which gives zero as long as the divisor is not zero

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

Fail on a division by zero

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

Add a float and an integer

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

Add two integers, which gives a double

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

Add two floats

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

Subtract an integer from a float

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

Subtract two integers, which gives a double

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

Subtract two floats

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

Multiply a float by an integer

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

Multiply two integers, which gives a double

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
  "target_field": -90.0
}
```

*The operation was successful*

### Example 17

Multiply two floats

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

Divide a float by an integer

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

Divide two integers, which keeps the fraction

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

Divide two floats

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
# has_any_bit

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: has_any_bit($target_field, mask)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| mask | string, number | value | Hexadecimal string, with or without the `0x` prefix, or integer; never 0 and at most 64 bits |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any hexadecimal |


## Description

Checks whether the target value and `mask` have at least one bit in common.

Behavior:
- The target is read as an unsigned 64-bit integer, either from a hexadecimal string, with or without the
  `0x` prefix and in any letter case, or from a JSON integer.
- `mask` is a literal of the same kinds: a hexadecimal string or a JSON integer.
- A string is always read as hexadecimal: `"16"` is 0x16 (decimal 22); write a JSON integer (`16`) for a
  decimal value. Integers from 0 to 2^64-1 are accepted; a negative integer is not.
- True when `(target AND mask)` is not 0: a single common bit is enough, all the mask bits are not
  required.

Build errors:
- `mask` is a reference.
- `mask` is 0, negative, longer than 64 bits, or neither a hexadecimal string nor an integer.

Notes:
- For an equality test on the whole value, convert it with `hex_to_int` and use a numeric comparison.


## Fails when

- The target field does not exist.
- The target field is neither a string nor a non-negative integer.
- The target string is not hexadecimal or does not fit in 64 bits.
- No bit of `mask` is set in the target value.

## Examples

### Example 1

The target and the mask share bit 0.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x4F1')
```

#### Input Event

```json
{
  "target_field": "0x1"
}
```

*The check was successful*

### Example 2

The target and the mask have no bit in common.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x4F1')
```

#### Input Event

```json
{
  "target_field": "0x1000"
}
```

*The check was performed with errors*

### Example 3

The prefix and the digits of the target may be upper case.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x4F1')
```

#### Input Event

```json
{
  "target_field": "0X1F"
}
```

*The check was successful*

### Example 4

The target may omit the 0x prefix.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x4F1')
```

#### Input Event

```json
{
  "target_field": "4f1"
}
```

*The check was successful*

### Example 5

The mask may be given as an integer.

#### Asset

```yaml
check:
  - target_field: has_any_bit(31)
```

#### Input Event

```json
{
  "target_field": "0x10"
}
```

*The check was successful*

### Example 6

The target may be a JSON integer.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x4F1')
```

#### Input Event

```json
{
  "target_field": 16
}
```

*The check was successful*

### Example 7

An integer target with no bit in common with the mask.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x4F1')
```

#### Input Event

```json
{
  "target_field": 2
}
```

*The check was performed with errors*

### Example 8

The target string is not hexadecimal.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0xff')
```

#### Input Event

```json
{
  "target_field": "zz"
}
```

*The check was performed with errors*

### Example 9

The target field is a boolean, neither a string nor an integer.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0xff')
```

#### Input Event

```json
{
  "target_field": true
}
```

*The check was performed with errors*

### Example 10

A zero mask is rejected at build time.

#### Asset

```yaml
check:
  - target_field: has_any_bit('0x0')
```

#### Input Event

```json
{
  "target_field": "0x1"
}
```

*The check was performed with errors*



---
# hex_to_int

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: hex_to_int(hex)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| hex | string | reference | Any hexadecimal |


## Output

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Reads a string of hexadecimal digits as a signed 64-bit integer and maps it to the target field.

Behavior:
- The digits can be in either case and a `0x` prefix is optional: `0xBC763516` gives `3161863446`
  and `48656C` gives `4744556`.
- The whole string must be consumed: trailing characters, whitespace included, fail.

Build errors:
- `hex` is a literal.
- `hex` is a schema field whose type is not a string.

Notes:
- The result is an integer: a `float` or `double` target rejects it at runtime.
- `decode_hex` decodes hexadecimal digits to text instead.


## Fails when

- `hex` is missing or is not a string
- `hex` is not a hexadecimal number that fits in a signed 64-bit integer

## Examples

### Example 1

Convert hexadecimal digits without a prefix

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_int($hex)
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

Convert a number with the 0x prefix that does not fit in 32 bits

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_int($hex)
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

### Example 3

Convert lower-case digits

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_int($hex)
```

#### Input Event

```json
{
  "hex": "ff"
}
```

#### Outcome Event

```json
{
  "hex": "ff",
  "target_field": 255
}
```

*The operation was successful*

### Example 4

Fail on a character that is not a hexadecimal digit

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_int($hex)
```

#### Input Event

```json
{
  "hex": "GG"
}
```

#### Outcome Event

```json
{
  "hex": "GG"
}
```

*The operation was performed with errors*

### Example 5

Fail on trailing whitespace, as the whole string must be consumed

#### Asset

```yaml
normalize:
  - map:
      - target_field: hex_to_int($hex)
```

#### Input Event

```json
{
  "hex": "2A "
}
```

#### Outcome Event

```json
{
  "hex": "2A "
}
```

*The operation was performed with errors*



---
# int_calculate

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: int_calculate(operator, operand_left, operand_right, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| operator (option) | string | value | mul, div, sub, sum |
| operand_left | number | value or reference | Integers between `-2^63` and `2^63-1` |
| operand_right | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Output

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Applies an arithmetic operator to two or more integer operands, from left to right, and maps the
64-bit integer result to the target field.

Behavior:
- `operator` is one of the literals `sum`, `sub`, `mul` and `div`; it is applied to the first two
  operands, then to that result and the next operand, and so on.
- An operand literal must be a JSON integer; an operand reference must hold an integer at runtime.
- `sum`, `sub` and `mul` fail when the result overflows the signed 64-bit range.
- `div` is integer division truncating toward zero: `7 / 2` gives `3` and `-7 / 2` gives `-3`;
  `-2^63 / -1` fails.

Build errors:
- `operator` is not a literal or is not one of the four names.
- An operand literal that is not an integer (`1.0`, `1.1` or `true`).
- An operand schema field whose type is not `integer`, `short` or `long` (`byte`,
  `unsigned_long` and `float` are rejected).
- With `div`, a literal `0` in any position after the first operand.

Notes:
- The result is an integer: a `float` or `double` target rejects it at runtime.
- `float_calculate` computes in double precision and accepts floating-point operands.


## Fails when

- an operand reference is missing or does not hold an integer
- a divisor read from a reference is 0
- the result overflows the signed 64-bit range

## Notes

- Division by zero is not allowed (the function will fail).

- The limit for a 64-bit integer is 2^63-1 and -2^63.

## Examples

### Example 1

Fail on a sum that overflows the 64-bit integer limit

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

Fail on a sum that overflows the 64-bit integer limit

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

Fail on a subtraction that overflows the 64-bit integer limit

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

Fail on a subtraction that overflows the 64-bit integer limit

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

Fail on a multiplication that overflows the 64-bit integer limit

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

Fail on a multiplication that overflows the 64-bit integer limit

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

Divide a zero numerator, which gives zero as long as the divisor is not zero

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

Fail on a division by zero

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

### Example 9

Truncate the quotient of a positive division toward zero

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('div', 7, 2)
```

#### Input Event

```json
{}
```

#### Outcome Event

```json
{
  "target_field": 3
}
```

*The operation was successful*

### Example 10

Truncate the quotient of a negative division toward zero

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('div', $operand_left, $operand_right)
```

#### Input Event

```json
{
  "operand_left": -7,
  "operand_right": 2
}
```

#### Outcome Event

```json
{
  "operand_left": -7,
  "operand_right": 2,
  "target_field": -3
}
```

*The operation was successful*

### Example 11

Fail on the division of the minimum integer by -1, which overflows

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('div', -9223372036854775808, -1)
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

### Example 12

Apply the operator from left to right over more than two operands

#### Asset

```yaml
normalize:
  - map:
      - target_field: int_calculate('sum', $operand_left, $operand_right, 3)
```

#### Input Event

```json
{
  "operand_left": 1,
  "operand_right": 2
}
```

#### Outcome Event

```json
{
  "operand_left": 1,
  "operand_right": 2,
  "target_field": 6
}
```

*The operation was successful*



---
# to_bool

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: to_bool(value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | boolean, number, string | reference | Any value of the listed types |


## Output

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Converts a boolean, a number or a string holding a boolean to a boolean and maps it to the target field.

Behavior:
- A boolean is mapped as it is.
- A number gives `true` when it is not zero and `false` when it is `0` or `0.0`.
- The strings `true` and `false`, in any letter case, give the matching boolean.

Build errors:
- `value` is a literal.
- `value` is a schema field whose type is neither a boolean, a number nor a string.

Notes:
- Other strings (`"1"`, `"yes"`) and `null` are not converted.
- `parse_bool` parses the same strings as a transform helper.


## Fails when

- `value` is missing
- `value` is neither a boolean, a number nor one of the strings `true` and `false`, or it is an integer above 2^63-1

## Examples

### Example 1

A boolean is mapped as it is

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": false
}
```

#### Outcome Event

```json
{
  "value": false,
  "target_field": false
}
```

*The operation was successful*

### Example 2

Convert the integer 1 to true

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": 1
}
```

#### Outcome Event

```json
{
  "value": 1,
  "target_field": true
}
```

*The operation was successful*

### Example 3

Convert the float 1.0 to true

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": 1.0
}
```

#### Outcome Event

```json
{
  "value": 1.0,
  "target_field": true
}
```

*The operation was successful*

### Example 4

Convert the integer 0 to false

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": 0
}
```

#### Outcome Event

```json
{
  "value": 0,
  "target_field": false
}
```

*The operation was successful*

### Example 5

Convert the float 0.0 to false

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": 0.0
}
```

#### Outcome Event

```json
{
  "value": 0.0,
  "target_field": false
}
```

*The operation was successful*

### Example 6

Convert the integer 2 to true, as any non-zero number is true

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": 2
}
```

#### Outcome Event

```json
{
  "value": 2,
  "target_field": true
}
```

*The operation was successful*

### Example 7

Convert the integer -1 to true, as any non-zero number is true

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": -1
}
```

#### Outcome Event

```json
{
  "value": -1,
  "target_field": true
}
```

*The operation was successful*

### Example 8

Convert the float 0.5 to true, as any non-zero number is true

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": 0.5
}
```

#### Outcome Event

```json
{
  "value": 0.5,
  "target_field": true
}
```

*The operation was successful*

### Example 9

Convert the string true to true

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": "true"
}
```

#### Outcome Event

```json
{
  "value": "true",
  "target_field": true
}
```

*The operation was successful*

### Example 10

Convert the string FALSE to false, regardless of the letter case

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": "FALSE"
}
```

#### Outcome Event

```json
{
  "value": "FALSE",
  "target_field": false
}
```

*The operation was successful*

### Example 11

Fail on a string that is not true or false

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_bool($value)
```

#### Input Event

```json
{
  "value": "yes"
}
```

#### Outcome Event

```json
{
  "value": "yes"
}
```

*The operation was performed with errors*



---
# to_int

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: to_int(value, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number | reference | Any number, or a string holding a decimal number |
| mode (option, optional) | string | value | truncate, round |


## Output

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Converts a number, or a string holding a number, to a 64-bit integer and maps it to the target
field.

Behavior:
- An integer is kept as it is.
- A floating-point number is converted according to `mode`: `truncate` (the default) drops the
  fractional part toward zero (`-4.7` gives `-4`); `round` rounds half away from zero (`-4.7`
  gives `-5` and `1.5` gives `2`).
- A string is read as a number first and converted the same way: `"42"` gives `42` and `"4.6"`
  gives `4` with `truncate`.

Build errors:
- `value` is a literal, or `mode` is given and is neither `truncate` nor `round`.
- `value` is a schema field whose type is neither a number nor a string.

Notes:
- The result is an integer: a `float` or `double` target rejects it at runtime.
- `parse_long` and `parse_integer` parse decimal strings as transform helpers.


## Fails when

- `value` is missing, or is neither a number nor a string holding a number

## Examples

### Example 1

Truncate a negative float, dropping the fractional part

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'truncate')
```

#### Input Event

```json
{
  "value": -4.176666736602783
}
```

#### Outcome Event

```json
{
  "value": -4.176666736602783,
  "target_field": -4
}
```

*The operation was successful*

### Example 2

Round a negative float away from zero

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'round')
```

#### Input Event

```json
{
  "value": -4.716666736602783
}
```

#### Outcome Event

```json
{
  "value": -4.716666736602783,
  "target_field": -5
}
```

*The operation was successful*

### Example 3

Round a negative float to the nearest integer

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'round')
```

#### Input Event

```json
{
  "value": -4.176666736602783
}
```

#### Outcome Event

```json
{
  "value": -4.176666736602783,
  "target_field": -4
}
```

*The operation was successful*

### Example 4

Truncate a positive float below 1 to 0

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'truncate')
```

#### Input Event

```json
{
  "value": 0.7124601006507874
}
```

#### Outcome Event

```json
{
  "value": 0.7124601006507874,
  "target_field": 0
}
```

*The operation was successful*

### Example 5

Round a positive float above 0.5 to 1

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'round')
```

#### Input Event

```json
{
  "value": 0.7124601006507874
}
```

#### Outcome Event

```json
{
  "value": 0.7124601006507874,
  "target_field": 1
}
```

*The operation was successful*

### Example 6

Truncate a positive float with a fractional part of 0.5

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'truncate')
```

#### Input Event

```json
{
  "value": 1.5
}
```

#### Outcome Event

```json
{
  "value": 1.5,
  "target_field": 1
}
```

*The operation was successful*

### Example 7

Truncate a positive float just below 1.5 to 1

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'truncate')
```

#### Input Event

```json
{
  "value": 1.49999999
}
```

#### Outcome Event

```json
{
  "value": 1.49999999,
  "target_field": 1
}
```

*The operation was successful*

### Example 8

Round 1.51 to 2

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'round')
```

#### Input Event

```json
{
  "value": 1.51
}
```

#### Outcome Event

```json
{
  "value": 1.51,
  "target_field": 2
}
```

*The operation was successful*

### Example 9

Round a positive float below 1.5 to 1

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'round')
```

#### Input Event

```json
{
  "value": 1.48888888
}
```

#### Outcome Event

```json
{
  "value": 1.48888888,
  "target_field": 1
}
```

*The operation was successful*

### Example 10

Keep an integer unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'round')
```

#### Input Event

```json
{
  "value": 1000
}
```

#### Outcome Event

```json
{
  "value": 1000,
  "target_field": 1000
}
```

*The operation was successful*

### Example 11

Convert a string holding an integer, with the default mode

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value)
```

#### Input Event

```json
{
  "value": "42"
}
```

#### Outcome Event

```json
{
  "value": "42",
  "target_field": 42
}
```

*The operation was successful*

### Example 12

Convert a string holding a float and truncate it

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value, 'truncate')
```

#### Input Event

```json
{
  "value": "4.6"
}
```

#### Outcome Event

```json
{
  "value": "4.6",
  "target_field": 4
}
```

*The operation was successful*

### Example 13

Fail on a string that does not hold a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_int($value)
```

#### Input Event

```json
{
  "value": "abc"
}
```

#### Outcome Event

```json
{
  "value": "abc"
}
```

*The operation was performed with errors*



---
# to_string

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: to_string(value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| value | number, string, boolean | reference | Any value of the listed types |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Converts a number or a boolean to its text and maps the string to the target field; a string is
mapped unchanged.

Behavior:
- An integer is written in decimal: `12345` gives `"12345"`.
- A floating-point number is written with 6 fixed decimals, rounded: `23.565` gives `"23.565000"`
  and `2.33875648` gives `"2.338756"`.
- A boolean gives `"true"` or `"false"`; a string is returned as it is.

Build errors:
- `value` is a literal.

Notes:
- `concat` writes a referenced number with the same text.
- `to_int` and `to_bool` are the conversions in the other direction.


## Fails when

- `value` is missing, or is an object, an array or `null`

## Examples

### Example 1

Write an integer in decimal

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($value)
```

#### Input Event

```json
{
  "value": 12345
}
```

#### Outcome Event

```json
{
  "value": 12345,
  "target_field": "12345"
}
```

*The operation was successful*

### Example 2

Write a float with 6 fixed decimals

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($value)
```

#### Input Event

```json
{
  "value": 23.565
}
```

#### Outcome Event

```json
{
  "value": 23.565,
  "target_field": "23.565000"
}
```

*The operation was successful*

### Example 3

Round a float to 6 decimals

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($value)
```

#### Input Event

```json
{
  "value": 2.33875648
}
```

#### Outcome Event

```json
{
  "value": 2.33875648,
  "target_field": "2.338756"
}
```

*The operation was successful*

### Example 4

Return a string unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($value)
```

#### Input Event

```json
{
  "value": "12345"
}
```

#### Outcome Event

```json
{
  "value": "12345",
  "target_field": "12345"
}
```

*The operation was successful*

### Example 5

Write a boolean as true or false

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($value)
```

#### Input Event

```json
{
  "value": true
}
```

#### Outcome Event

```json
{
  "value": true,
  "target_field": "true"
}
```

*The operation was successful*

### Example 6

Fail on a null value

#### Asset

```yaml
normalize:
  - map:
      - target_field: to_string($value)
```

#### Input Event

```json
{
  "value": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*



---
# date_to_epoch

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: date_to_epoch(date, [format])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| date | string | reference | Any string |
| format (optional) | string | value | Any string |


## Output

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Converts a date string to the number of seconds since the Unix epoch, as a double, and maps it to
the target field.

Behavior:
- `date` is parsed with `format`, a strftime-style format (`%Y-%m-%dT%H:%M:%SZ` by default, where
  the `Z` is a literal character), in the classic locale. The whole input must be consumed, so
  surrounding whitespace is accepted only when the format contains it.
- `%S` accepts fractional seconds. The result keeps microseconds: further digits are truncated.
- A UTC offset is read with `%z` (`-0300`) or `%Ez` (`-03:00`) and subtracted.
- `%Z` reads an IANA time zone name such as `America/New_York`, and the local time is converted
  to UTC with the rules of that zone; a local time inside a DST gap or fold fails.

Build errors:
- `date` is a literal, or it is a schema field whose type is neither `date` nor `date_nanos`.
- `format` is a reference, is not a string, is empty or is longer than 64 characters.

Notes:
- `parse_date` writes an ISO string with milliseconds, accepts named formats and a locale, fills a
  missing year with the current one and resolves DST gaps and folds to the earliest instant.
- `epoch_to_date` is the inverse conversion; `now_epoch` gives the current time as an integer.


## Fails when

- `date` is missing or is not a string
- `date` does not match `format` entirely: a field is invalid or input remains unparsed
- the local time falls in a DST gap or fold, or the zone name is unknown
- the resulting instant is out of range

## Examples

### Example 1

Convert the epoch start with the default format given explicitly

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

Convert a UTC date with the default format, omitting the format argument

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date)
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

Convert a UTC date with a trailing Z

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

### Example 4

Keep the fractional seconds up to the microsecond

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

### Example 5

Truncate the fractional seconds beyond the microsecond

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%Y-%m-%dT%H:%M:%SZ')
```

#### Input Event

```json
{
  "date": "2024-09-24T23:03:00.597629999Z"
}
```

#### Outcome Event

```json
{
  "date": "2024-09-24T23:03:00.597629999Z",
  "target_field": 1727218980.597629
}
```

*The operation was successful*

### Example 6

Convert a date before the epoch to a negative value

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

### Example 7

Fail when the input lacks the Z that the default format requires

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

### Example 8

Subtract an offset with a colon read with %Ez

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

### Example 9

Subtract an offset without a colon read with %z

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

### Example 10

Parse a space instead of the T and a zero offset

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

### Example 11

Parse the basic ISO 8601 format with a Z

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

### Example 12

Parse the basic ISO 8601 format with an offset

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

### Example 13

Read a date without time zone as UTC when the format has none

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

### Example 14

Convert a local time in the IANA zone America/Argentina/Buenos_Aires (UTC-3) to UTC

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

### Example 15

Convert a local time in the IANA zone Europe/Berlin during DST (UTC+2) to UTC

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

### Example 16

Fail on an unknown IANA zone name

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

### Example 17

Fail on a local time inside the DST gap (the spring-forward hour in New York)

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

### Example 18

Fail on a local time inside the DST fold (the repeated fall-back hour in New York)

#### Asset

```yaml
normalize:
  - map:
      - target_field: date_to_epoch($date, '%F %T %Z')
```

#### Input Event

```json
{
  "date": "2024-11-03 01:30:00 America/New_York"
}
```

#### Outcome Event

```json
{
  "date": "2024-11-03 01:30:00 America/New_York"
}
```

*The operation was performed with errors*

### Example 19

Fail when the date is a number

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

### Example 20

Fail when the date is null

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

### Example 21

Fail on a format with an unknown specifier

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

### Example 22

Fail on an empty format

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

### Example 23

Fail on a null format

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

### Example 24

Fail on a format that is not a string

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

### Example 25

Fail when input remains after the format (the format has no time part)

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

### Example 26

Fail when the input ends before the format (the input has no time part)

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

### Example 27

Fail on a malformed date string

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

### Example 28

Fail on an empty date string

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

### Example 29

Fail on an invalid day of month (February 30th)

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

### Example 30

Fail on an invalid month (13)

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

### Example 31

Fail on an invalid day (32)

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
# epoch_to_date

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: epoch_to_date(epoch)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| epoch | number | reference | Any number |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Converts a number of seconds since the Unix epoch to a UTC date string and maps it to the target
field.

Behavior:
- `epoch` is a reference to a number, an integer or a double, read as seconds; negative values and
  fractions are accepted.
- The result has the form `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always with 6 fractional digits: `0`
  gives `1970-01-01T00:00:00.000000Z` and `1727218980.597629` gives
  `2024-09-24T23:03:00.597629Z`.

Build errors:
- `epoch` is a literal.
- `epoch` is a schema field whose type is not a number.

Notes:
- `now` writes the current time with no fractional part; `parse_date` writes 3 fractional digits.
- `date_to_epoch` is the inverse conversion and returns a double.


## Fails when

- `epoch` is missing or is not a number (a numeric string such as "1706172785" fails)
- `epoch` is above 2^63-1

## Examples

### Example 1

Convert the epoch start

#### Asset

```yaml
normalize:
  - map:
      - target_field: epoch_to_date($epoch)
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

Convert an integer number of seconds

#### Asset

```yaml
normalize:
  - map:
      - target_field: epoch_to_date($epoch)
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

### Example 3

Keep the fraction of a double number of seconds, with 6 digits

#### Asset

```yaml
normalize:
  - map:
      - target_field: epoch_to_date($epoch)
```

#### Input Event

```json
{
  "epoch": 1727218980.597629
}
```

#### Outcome Event

```json
{
  "epoch": 1727218980.597629,
  "target_field": "2024-09-24T23:03:00.597629Z"
}
```

*The operation was successful*

### Example 4

Convert a negative number of seconds, before the epoch

#### Asset

```yaml
normalize:
  - map:
      - target_field: epoch_to_date($epoch)
```

#### Input Event

```json
{
  "epoch": -1
}
```

#### Outcome Event

```json
{
  "epoch": -1,
  "target_field": "1969-12-31T23:59:59.000000Z"
}
```

*The operation was successful*

### Example 5

Fail on a string, even when it holds a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: epoch_to_date($epoch)
```

#### Input Event

```json
{
  "epoch": "1715958658"
}
```

#### Outcome Event

```json
{
  "epoch": "1715958658"
}
```

*The operation was performed with errors*



---
# now

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: now()
```

## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Maps the current UTC time to the target field as a date string with second precision.

Behavior:
- The result has the form `YYYY-MM-DDTHH:MM:SSZ`, for example `2024-05-17T15:10:58Z`, with no
  fractional part.
- It is the wall-clock time at which the event is processed, not the event time.

Build errors:
- Any argument.

Notes:
- `now_epoch` gives the same instant as an integer number of seconds.
- `epoch_to_date` writes 6 fractional digits and `parse_date` writes 3.


## Fails when

- never under normal operation: the helper has no input

---
# now_epoch

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: now_epoch()
```

## Output

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Maps the current time to the target field as the integer number of seconds since the Unix epoch.

Behavior:
- The system clock is truncated to whole seconds and written as a 64-bit integer.
- It is the wall-clock time at which the event is processed, not the event time.

Build errors:
- Any argument.
- A target whose schema type does not accept an integer, such as a `date` or `keyword` field.

Notes:
- `now` gives the same instant as a date string.
- `date_to_epoch` converts a date string and returns a double.


## Fails when

- never under normal operation: the helper has no input

---
# asn

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: asn(ip)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Output

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Looks up the autonomous system of an IP address in the GeoLite2-ASN database (MaxMind) and maps
the result object to the target field.

Behavior:
- `ip` is a reference to a string holding an IPv4 or IPv6 address.
- The result is `{"number": <autonomous_system_number>, "organization": {"name":
  <autonomous_system_organization>}}`; each key is present only when the database entry has that
  field.
- On success the whole target value is replaced by the object.

Build errors:
- The number of arguments is not exactly 1, or `ip` is not a reference.
- `ip` is a schema field whose type is not `ip` (for example `keyword` or `text`).
- The ASN database is not available.

Notes:
- `geoip` queries the City database instead.
- The `geo` enrichment maps the same two fields automatically for the IP fields of the schema; it
  writes them leaf by leaf, while `asn` replaces the target object.


## Fails when

- `ip` is missing or is not a string (an array is rejected too)
- the database has no entry for the address, or the string is not a valid IP

## Examples

### Example 1

Look up the autonomous system of a public IP present in the test database

#### Asset

```yaml
normalize:
  - map:
      - target_field: asn($ip)
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
# community_id

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: community_id(source_ip, destination_ip, source_port, destination_port, protocol)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| source_ip | string | reference | Any IP |
| destination_ip | string | reference | Any IP |
| source_port | number | reference | Integers between `-2^63` and `2^63-1` |
| destination_port | number | reference | Integers between `-2^63` and `2^63-1` |
| protocol | number | value or reference | Integers between `-2^63` and `2^63-1` |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Computes the Community ID v1 of a network flow and maps it to the target field as the string
`1:<base64 of the SHA-1>`, with the seed fixed to 0.

Behavior:
- `source_ip` and `destination_ip` are references to strings holding two addresses of the same IP
  family; `source_port` and `destination_port` are references to integers; `protocol` is the IANA
  protocol number, as an integer literal or reference.
- The two endpoints are ordered by address and port before hashing, so both directions of a flow
  give the same id.
- The ports are checked against the protocol: TCP (6), UDP (17) and SCTP (132) need 1..65535;
  ICMP (1) and ICMPv6 (58) take the type and code as 0..255; any other protocol takes 0..65535.
- A missing port reference counts as 0, which fails for TCP, UDP and SCTP. The ICMP values are
  hashed as given: no type-to-counterpart mapping is applied.

Build errors:
- The number of arguments is not 5, or an IP or port argument is not a reference.
- An IP schema field whose type is not a string; a port or protocol schema field whose type is
  not `integer`, `short` or `long`.
- A literal `protocol` that is not an integer in 0..255.

Notes:
- `iana_protocol_number` returns a string, so its result cannot be used as `protocol`; the schema
  field `network.iana_number` is a keyword and is rejected at build time.
- `ip_version` tells the family of an address.


## Fails when

- an IP is missing, is not a string or is not a valid address, or the two addresses are of different families
- the protocol reference is missing or is not an integer
- a port is present but is not an integer, or is outside the range allowed for the protocol

## Examples

### Example 1

Compute the id of a TCP flow over IPv4

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
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

Compute the id of a UDP flow over IPv4

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
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

Compute the id of an IPv6 encapsulation flow, whose ports are 0

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 41)
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

Compute the id of an ICMP echo request, with the type and code as ports

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
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

Fail on a source IP that is not a valid address

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
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

Fail on a protocol number above 255

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
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

Fail on a transport port above 65535

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
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

Fail on an ICMP type above 255

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
```

#### Input Event

```json
{
  "source_ip": "192.0.2.1",
  "destination_ip": "198.51.100.2",
  "source_port": 300,
  "destination_port": 0,
  "protocol": 1
}
```

#### Outcome Event

```json
{
  "source_ip": "192.0.2.1",
  "destination_ip": "198.51.100.2",
  "source_port": 300,
  "destination_port": 0,
  "protocol": 1
}
```

*The operation was performed with errors*

### Example 9

Fail on endpoints of different IP families

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "2001:db8::1",
  "source_port": 12345,
  "destination_port": 80
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "2001:db8::1",
  "source_port": 12345,
  "destination_port": 80
}
```

*The operation was performed with errors*

### Example 10

Fail on a TCP flow whose destination port is 0

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, $protocol)
```

#### Input Event

```json
{
  "source_ip": "222.222.2.22",
  "destination_ip": "222.222.2.22",
  "source_port": 8,
  "destination_port": 0,
  "protocol": 6
}
```

#### Outcome Event

```json
{
  "source_ip": "222.222.2.22",
  "destination_ip": "222.222.2.22",
  "source_port": 8,
  "destination_port": 0,
  "protocol": 6
}
```

*The operation was performed with errors*

### Example 11

Fail on a port given as a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": "12345",
  "destination_port": 80
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": "12345",
  "destination_port": 80
}
```

*The operation was performed with errors*

### Example 12

Fail on a TCP flow whose source port reference is missing, as it counts as 0

#### Asset

```yaml
normalize:
  - map:
      - target_field: community_id($source_ip, $destination_ip, $source_port, $destination_port, 6)
```

#### Input Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": null,
  "destination_port": 80
}
```

#### Outcome Event

```json
{
  "source_ip": "192.168.0.1",
  "destination_ip": "10.0.0.5",
  "source_port": null,
  "destination_port": 80
}
```

*The operation was performed with errors*



---
# geoip

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: geoip(ip)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Output

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Looks up the location of an IP address in the GeoLite2-City database (MaxMind) and maps the result
object to the target field.

Behavior:
- `ip` is a reference to a string holding an IPv4 or IPv6 address.
- The result holds these keys, each present only when the database entry has the field:
  - `city_name`: `city.names.en`
  - `continent_code`: `continent.code`
  - `continent_name`: `continent.names.en`
  - `country_iso_code`: `country.iso_code`
  - `country_name`: `country.names.en`
  - `location.lat`: `location.latitude` (double)
  - `location.lon`: `location.longitude` (double)
  - `postal_code`: `postal.code`
  - `timezone`: `location.time_zone`
  - `region_iso_code`: `subdivisions.0.iso_code`
  - `region_name`: `subdivisions.0.names.en`
- On success the whole target value is replaced by the object.

Build errors:
- The number of arguments is not exactly 1, or `ip` is not a reference.
- `ip` is a schema field whose type is not `ip` (for example `keyword` or `text`).
- The City database is not available.

Notes:
- `asn` queries the ASN database instead.
- The `geo` enrichment maps the same fields automatically for the IP fields of the schema; it
  writes them leaf by leaf, while `geoip` replaces the target object.


## Fails when

- `ip` is missing or is not a string (an array is rejected too)
- the database has no entry for the address, or the string is not a valid IP

## Examples

### Example 1

Look up the location of a public IP present in the test database

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
# iana_protocol_name

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: iana_protocol_name(protocol_number)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| protocol_number | number, string | reference | Any value of the listed types |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Resolves an IANA IP protocol number to its keyword, for example `tcp` for 6, and maps it to the
target field.

Behavior:
- `protocol_number` is a JSON integer in 0..255, or a string of decimal digits that is read in
  full (no sign, whitespace or decimals).
- The result is the lower-case keyword of a built-in table, such as `tcp`, `ipv6-icmp`, `a/n`,
  `ax.25` or `tp++`.

Build errors:
- `protocol_number` is a literal.
- `protocol_number` is a schema field whose type is neither a number nor a string.

Notes:
- A JSON double such as `6.0` fails even when it is integral.
- `iana_protocol_number` is the inverse lookup.


## Fails when

- `protocol_number` is missing, is a boolean or a double, or is a string that is not a plain decimal number
- the number is outside 0..255
- the number is unassigned (148 to 252), experimental (253 and 254), reserved (255) or a generic category (61, 63, 68, 99 and 114)

## Examples

### Example 1

Resolve 6 to tcp

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 6
}
```

#### Outcome Event

```json
{
  "protocol_number": 6,
  "target_field": "tcp"
}
```

*The operation was successful*

### Example 2

Resolve 58 to ipv6-icmp

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 58
}
```

#### Outcome Event

```json
{
  "protocol_number": 58,
  "target_field": "ipv6-icmp"
}
```

*The operation was successful*

### Example 3

Resolve 147, the last assigned number, to bit-emu

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 147
}
```

#### Outcome Event

```json
{
  "protocol_number": 147,
  "target_field": "bit-emu"
}
```

*The operation was successful*

### Example 4

Resolve a number given as a decimal string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "6"
}
```

#### Outcome Event

```json
{
  "protocol_number": "6",
  "target_field": "tcp"
}
```

*The operation was successful*

### Example 5

Resolve a number given as a decimal string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "58"
}
```

#### Outcome Event

```json
{
  "protocol_number": "58",
  "target_field": "ipv6-icmp"
}
```

*The operation was successful*

### Example 6

Resolve a number given as a decimal string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "147"
}
```

#### Outcome Event

```json
{
  "protocol_number": "147",
  "target_field": "bit-emu"
}
```

*The operation was successful*

### Example 7

Fail on a string with decimals

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "6.0"
}
```

#### Outcome Event

```json
{
  "protocol_number": "6.0"
}
```

*The operation was performed with errors*

### Example 8

Fail on a string with a sign

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "+6"
}
```

#### Outcome Event

```json
{
  "protocol_number": "+6"
}
```

*The operation was performed with errors*

### Example 9

Fail on a double, even when it is integral

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 6.0
}
```

#### Outcome Event

```json
{
  "protocol_number": 6.0
}
```

*The operation was performed with errors*

### Example 10

Fail on a negative number given as a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "-1"
}
```

#### Outcome Event

```json
{
  "protocol_number": "-1"
}
```

*The operation was performed with errors*

### Example 11

Fail on a number above 255 given as a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "256"
}
```

#### Outcome Event

```json
{
  "protocol_number": "256"
}
```

*The operation was performed with errors*

### Example 12

Fail on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": "abc"
}
```

#### Outcome Event

```json
{
  "protocol_number": "abc"
}
```

*The operation was performed with errors*

### Example 13

Fail on the generic category 61

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 61
}
```

#### Outcome Event

```json
{
  "protocol_number": 61
}
```

*The operation was performed with errors*

### Example 14

Fail on the generic category 63

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 63
}
```

#### Outcome Event

```json
{
  "protocol_number": 63
}
```

*The operation was performed with errors*

### Example 15

Fail on the generic category 68

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 68
}
```

#### Outcome Event

```json
{
  "protocol_number": 68
}
```

*The operation was performed with errors*

### Example 16

Fail on the generic category 99

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 99
}
```

#### Outcome Event

```json
{
  "protocol_number": 99
}
```

*The operation was performed with errors*

### Example 17

Fail on the generic category 114

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 114
}
```

#### Outcome Event

```json
{
  "protocol_number": 114
}
```

*The operation was performed with errors*

### Example 18

Fail on an unassigned number

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 148
}
```

#### Outcome Event

```json
{
  "protocol_number": 148
}
```

*The operation was performed with errors*

### Example 19

Fail on an experimental number

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 253
}
```

#### Outcome Event

```json
{
  "protocol_number": 253
}
```

*The operation was performed with errors*

### Example 20

Fail on the reserved number

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 255
}
```

#### Outcome Event

```json
{
  "protocol_number": 255
}
```

*The operation was performed with errors*

### Example 21

Fail on a negative number

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": -1
}
```

#### Outcome Event

```json
{
  "protocol_number": -1
}
```

*The operation was performed with errors*

### Example 22

Fail on a number above 255

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": 256
}
```

#### Outcome Event

```json
{
  "protocol_number": 256
}
```

*The operation was performed with errors*

### Example 23

Fail on a null value

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_name($protocol_number)
```

#### Input Event

```json
{
  "protocol_number": null
}
```

#### Outcome Event

```json
{}
```

*The operation was performed with errors*



---
# iana_protocol_number

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: iana_protocol_number(protocol_name)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| protocol_name | string | reference | Any string |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Resolves an IANA IP protocol keyword to its protocol number and maps it to the target field as a
string of decimal digits, for example `"6"` for `tcp`.

Behavior:
- The name is normalized before the lookup: ASCII letters are lowercased, and `_` and every
  whitespace character become `-`; the aliases `icmpv6`, `udp-lite` and `ip-in-ip` stand for
  `ipv6-icmp`, `udplite` and `ipip`.
- The name is not trimmed: `" tcp"` becomes `-tcp` and fails.
- The lookup is exact against a built-in table of the IANA keywords for the numbers 0 to 147,
  without the generic categories 61, 63, 68, 99 and 114 (such as `any-host-internal-protocol`).

Build errors:
- `protocol_name` is a literal.
- `protocol_name` is a schema field whose type is not a string.

Notes:
- The result is a string: `community_id` needs an integer protocol and cannot consume it.
- `iana_protocol_name` is the inverse lookup.


## Fails when

- `protocol_name` is missing or is not a string
- the normalized name is not in the table

## Examples

### Example 1

Resolve a canonical keyword

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

Resolve a keyword regardless of its letter case

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

Resolve a canonical hyphenated keyword

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

Normalize the underscore and the alias udp-lite to udplite

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

Normalize the alias ip-in-ip to ipip

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

Normalize the alias icmpv6 to ipv6-icmp

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

Turn a whitespace character into a hyphen

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": "ipv6 icmp"
}
```

#### Outcome Event

```json
{
  "protocol_name": "ipv6 icmp",
  "target_field": "58"
}
```

*The operation was successful*

### Example 8

Fail on a leading space, as the name is not trimmed

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
```

#### Input Event

```json
{
  "protocol_name": " tcp"
}
```

#### Outcome Event

```json
{
  "protocol_name": " tcp"
}
```

*The operation was performed with errors*

### Example 9

Fail on a generic category that the table does not hold

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

### Example 10

Fail on an application-layer name that is not an IP protocol keyword

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

### Example 11

Fail on an empty string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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

### Example 12

Fail on a reference that is not a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: iana_protocol_number($protocol_name)
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
# in_cidr

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: in_cidr($target_field, cidr, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| cidr | string | value | IPv4 network as `a.b.c.d/nn` (`nn` from 0 to 32) or `a.b.c.d/m.m.m.m` |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks whether the target IPv4 address belongs to at least one of the given networks.

Behavior:
- Each argument is a literal string naming an IPv4 network in CIDR notation, `a.b.c.d/nn` with `nn` from
  0 to 32, or with a dotted-decimal mask, `a.b.c.d/m.m.m.m` (any dotted quad is accepted as a mask,
  non-contiguous ones included).
- The networks are tested in order and the check is true as soon as the target is inside one of them.
- Only IPv4 targets are supported: an IPv6 address gives false.
- The address parser is lenient: leading whitespace and leading zeros (read as decimal) are accepted,
  trailing characters are not.

Build errors:
- No argument is given.
- An argument is a reference or is not a string.
- A network is malformed, or the prefix length is outside 0 to 32.
- The target is a schema field whose type is neither `ip` nor an IP-compatible string type (keyword, text,
  wildcard and the like); date, binary, numeric and object fields are rejected.

Notes:
- `is_ipv4` uses a strict parser, so this helper can accept strings that `is_ipv4` rejects.
- `is_public_ip` is the fixed-range check that also handles IPv6.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The target string is not an IPv4 address (an IPv6 address included).
- The address is outside every given network.

## Examples

### Example 1

The address is inside the network given with a prefix length.

#### Asset

```yaml
check:
  - target_field: in_cidr('192.168.0.0/16')
```

#### Input Event

```json
{
  "target_field": "192.168.1.5"
}
```

*The check was successful*

### Example 2

The address is inside the network given with a dotted-decimal mask.

#### Asset

```yaml
check:
  - target_field: in_cidr('192.168.0.0/255.255.0.0')
```

#### Input Event

```json
{
  "target_field": "192.168.1.5"
}
```

*The check was successful*

### Example 3

The address is outside the only network.

#### Asset

```yaml
check:
  - target_field: in_cidr('192.168.0.0/16')
```

#### Input Event

```json
{
  "target_field": "111.111.1.11"
}
```

*The check was performed with errors*

### Example 4

The address is inside the second of two networks.

#### Asset

```yaml
check:
  - target_field: in_cidr('10.0.0.0/8', '172.16.0.0/12')
```

#### Input Event

```json
{
  "target_field": "172.20.5.9"
}
```

*The check was successful*

### Example 5

The address is outside both networks.

#### Asset

```yaml
check:
  - target_field: in_cidr('10.0.0.0/8', '172.16.0.0/12')
```

#### Input Event

```json
{
  "target_field": "192.168.1.1"
}
```

*The check was performed with errors*

### Example 6

An IPv6 address never matches.

#### Asset

```yaml
check:
  - target_field: in_cidr('192.168.0.0/16')
```

#### Input Event

```json
{
  "target_field": "2001:db8::1"
}
```

*The check was performed with errors*

### Example 7

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: in_cidr('192.168.0.0/16')
```

#### Input Event

```json
{
  "target_field": 3232235781
}
```

*The check was performed with errors*



---
# ip_version

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: ip_version(ip)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Output

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Classifies an IP address and maps the string `IPv4` or `IPv6` to the target field.

Behavior:
- `ip` is a reference to a string holding an address that `inet_pton` accepts: dotted-decimal
  IPv4 or textual IPv6, with no zone id, brackets, port or whitespace.
- The result is exactly `IPv4` or `IPv6`.

Build errors:
- `ip` is a literal.
- `ip` is a schema field whose type is not a string.

Notes:
- The validation is the one of the `is_ipv4` and `is_ipv6` check helpers.
- `parse_ip` validates an address as a transform helper.


## Fails when

- `ip` is missing or is not a string
- the string is not a valid IPv4 or IPv6 address

## Examples

### Example 1

Classify a dotted-decimal address as IPv4

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

Classify a full IPv6 address as IPv6

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

### Example 3

Classify a compressed IPv6 address as IPv6

#### Asset

```yaml
normalize:
  - map:
      - target_field: ip_version($ip)
```

#### Input Event

```json
{
  "ip": "::1"
}
```

#### Outcome Event

```json
{
  "ip": "::1",
  "target_field": "IPv6"
}
```

*The operation was successful*

### Example 4

Fail on an octet above 255

#### Asset

```yaml
normalize:
  - map:
      - target_field: ip_version($ip)
```

#### Input Event

```json
{
  "ip": "300.1.1.1"
}
```

#### Outcome Event

```json
{
  "ip": "300.1.1.1"
}
```

*The operation was performed with errors*

### Example 5

Fail on an address between brackets

#### Asset

```yaml
normalize:
  - map:
      - target_field: ip_version($ip)
```

#### Input Event

```json
{
  "ip": "[2001:db8::1]"
}
```

#### Outcome Event

```json
{
  "ip": "[2001:db8::1]"
}
```

*The operation was performed with errors*



---
# is_ipv4

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_ipv4($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks whether the target string is a valid IPv4 address.

Behavior:
- The target must be a string; it is parsed with `inet_pton(AF_INET)`, so it must be a strict dotted
  quad: four decimal octets from 0 to 255, with no leading zeros, no surrounding whitespace and no prefix
  length.
- Every syntactically valid address passes, private, loopback and reserved ranges included.
- No arguments are accepted.

Build errors:
- The target is a schema field whose type is neither `ip` nor an IP-compatible string type (keyword, text,
  wildcard and the like); date, binary, numeric and object fields are rejected.
- Any argument is given.

Notes:
- `in_cidr` uses a more lenient parser (leading zeros and whitespace are accepted), so it can accept
  strings that this helper rejects.
- `is_public_ip` excludes the private and loopback ranges.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The string is not a valid IPv4 address (an IPv6 address included).

## Examples

### Example 1

An IPv6 address is not an IPv4 address.

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

The loopback address is a valid IPv4 address.

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

A private network address is a valid IPv4 address.

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

A public address is a valid IPv4 address.

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

### Example 5

An octet above 255 is not valid.

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": "256.1.1.1"
}
```

*The check was performed with errors*

### Example 6

A prefix length is not part of an address.

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": "10.0.0.1/8"
}
```

*The check was performed with errors*

### Example 7

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: is_ipv4()
```

#### Input Event

```json
{
  "target_field": 3232235777
}
```

*The check was performed with errors*



---
# is_ipv6

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_ipv6($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks whether the target string is a valid IPv6 address.

Behavior:
- The target must be a string; it is parsed with `inet_pton(AF_INET6)`: compressed forms such as `::1` and
  IPv4-mapped addresses such as `::ffff:1.2.3.4` are accepted, while zone identifiers (`%eth0`), brackets
  and prefix lengths are rejected.
- Every syntactically valid address passes, loopback, link-local and unique-local ranges included.
- No arguments are accepted.

Build errors:
- The target is a schema field whose type is neither `ip` nor an IP-compatible string type (keyword, text,
  wildcard and the like); date, binary, numeric and object fields are rejected.
- Any argument is given.

Notes:
- `is_public_ip` excludes the loopback, link-local and unique-local ranges.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The string is not a valid IPv6 address (an IPv4 address included).

## Examples

### Example 1

An IPv4 address is not an IPv6 address.

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

The compressed loopback address is a valid IPv6 address.

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

A unique-local address is a valid IPv6 address.

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

A public address is a valid IPv6 address.

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

### Example 5

A zone identifier is not accepted.

#### Asset

```yaml
check:
  - target_field: is_ipv6()
```

#### Input Event

```json
{
  "target_field": "fe80::1%eth0"
}
```

*The check was performed with errors*

### Example 6

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: is_ipv6()
```

#### Input Event

```json
{
  "target_field": 42
}
```

*The check was performed with errors*



---
# is_public_ip

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: is_public_ip($target_field)
```

## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any IP |


## Description

Checks whether the target string is an IP address outside the private and loopback ranges.

Behavior:
- The target must be a string holding a valid IPv4 or IPv6 address.
- An IPv4 address is public unless it belongs to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 127.0.0.0/8.
- An IPv6 address is public unless it is `::1` or belongs to fe80::/10 or fc00::/7.
- No arguments are accepted.

Build errors:
- The target is a schema field whose type is neither `ip` nor an IP-compatible string type (keyword, text,
  wildcard and the like); date, binary, numeric and object fields are rejected.
- Any argument is given.

Notes:
- Only those seven ranges are excluded. Link-local IPv4 (169.254.0.0/16), carrier-grade NAT
  (100.64.0.0/10), multicast, reserved and documentation ranges, `::`, ff00::/8 and IPv4-mapped private
  addresses such as `::ffff:10.0.0.1` all count as public.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The string is not a valid IPv4 or IPv6 address.
- The address belongs to one of the excluded private or loopback ranges.

## Examples

### Example 1

A public IPv4 address.

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

A public IPv6 address.

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

The target field is a number, not a string.

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

### Example 4

An address in 10.0.0.0/8 is private.

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "10.1.2.3"
}
```

*The check was performed with errors*

### Example 5

The IPv4 loopback address is excluded.

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "127.0.0.1"
}
```

*The check was performed with errors*

### Example 6

An IPv6 link-local address is excluded.

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "fe80::1"
}
```

*The check was performed with errors*

### Example 7

An IPv4 link-local address is not in the excluded ranges, so it counts as public.

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "169.254.1.1"
}
```

*The check was successful*

### Example 8

The string is not an IP address.

#### Asset

```yaml
check:
  - target_field: is_public_ip()
```

#### Input Event

```json
{
  "target_field": "not-an-ip"
}
```

*The check was performed with errors*



---
# syslog_facility

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: syslog_facility(priority)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| priority | number | reference | Integers between `-2^63` and `2^63-1` |


## Output

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Derives the syslog facility from a PRI value and maps `{"code": <facility>, "name": <name>}` to
the target field.

Behavior:
- `priority` is a JSON integer in 0..191 (`facility * 8 + severity`); the code is `priority / 8`.
- The names by code: 0 kernel, 1 user, 2 mail, 3 daemon, 4 auth, 5 syslog, 6 lpr, 7 news, 8 uucp,
  9 cron, 10 authpriv, 11 ftp, 12 ntp, 13 logaudit, 14 logalert, 15 solaris-cron and 16 to 23
  local0 to local7.

Build errors:
- `priority` is a literal.
- `priority` is a schema field whose type is not a number.

Notes:
- The PRI must already be a number: `"<13>"`, `"13"` and `13.0` all fail.
- The result matches the `log.syslog.facility` schema object.
- `syslog_severity` derives the severity from the same value.


## Fails when

- `priority` is missing or is not an integer
- `priority` is outside 0..191

## Examples

### Example 1

Derive the facility local4 (20) from the priority 165

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_facility($priority)
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

Derive the facility kernel (0) from the priority 0

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_facility($priority)
```

#### Input Event

```json
{
  "priority": 0
}
```

#### Outcome Event

```json
{
  "priority": 0,
  "target_field": {
    "code": 0,
    "name": "kernel"
  }
}
```

*The operation was successful*

### Example 3

Fail on a priority above 191

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_facility($priority)
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

### Example 4

Fail on a negative priority

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_facility($priority)
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

### Example 5

Fail on a priority given as a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_facility($priority)
```

#### Input Event

```json
{
  "priority": "13"
}
```

#### Outcome Event

```json
{
  "priority": "13"
}
```

*The operation was performed with errors*

### Example 6

Fail on a priority given as a double

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_facility($priority)
```

#### Input Event

```json
{
  "priority": 13.0
}
```

#### Outcome Event

```json
{
  "priority": 13.0
}
```

*The operation was performed with errors*



---
# syslog_severity

**Kind:** map helper (used in `map`)

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: syslog_severity(priority)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| priority | number | reference | Integers between `-2^63` and `2^63-1` |


## Output

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Derives the syslog severity from a PRI value and maps `{"code": <severity>, "name": <name>}` to
the target field.

Behavior:
- `priority` is a JSON integer in 0..191 (`facility * 8 + severity`); the code is `priority % 8`.
- The names by code: 0 emergency, 1 alert, 2 critical, 3 error, 4 warning, 5 notice,
  6 informational and 7 debug.

Build errors:
- `priority` is a literal.
- `priority` is a schema field whose type is not a number.

Notes:
- The PRI must already be a number: `"<13>"`, `"13"` and `13.0` all fail.
- The result matches the `log.syslog.severity` schema object.
- `syslog_facility` derives the facility from the same value.


## Fails when

- `priority` is missing or is not an integer
- `priority` is outside 0..191

## Examples

### Example 1

Derive the severity notice (5) from the priority 165

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_severity($priority)
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

Derive the severity emergency (0) from the priority 0

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_severity($priority)
```

#### Input Event

```json
{
  "priority": 0
}
```

#### Outcome Event

```json
{
  "priority": 0,
  "target_field": {
    "code": 0,
    "name": "emergency"
  }
}
```

*The operation was successful*

### Example 3

Fail on a priority above 191

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_severity($priority)
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

### Example 4

Fail on a negative priority

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_severity($priority)
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

### Example 5

Fail on a priority given as a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_severity($priority)
```

#### Input Event

```json
{
  "priority": "13"
}
```

#### Outcome Event

```json
{
  "priority": "13"
}
```

*The operation was performed with errors*

### Example 6

Fail on a priority given as a double

#### Asset

```yaml
normalize:
  - map:
      - target_field: syslog_severity($priority)
```

#### Input Event

```json
{
  "priority": 13.0
}
```

#### Outcome Event

```json
{
  "priority": 13.0
}
```

*The operation was performed with errors*



---
# in_kvdb

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: in_kvdb($target_field, db)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is a key of the KVDB `db`.

Behavior:
- `db` is a literal string naming a KVDB that is declared and enabled in the integration or policy; the
  database is loaded when the asset is built.
- The lookup is an exact, case-sensitive key match; the value stored under the key is ignored.

Build errors:
- `db` is a reference or a literal that is not a string.
- The KVDB is not declared, is not enabled, or cannot be loaded.

Notes:
- During shallow asset validation (dependencies not loaded) the check is a no-op that always passes.
- `is_key_of` is the same check against a JSON object.
- `not_in_kvdb` is not the negation of this helper: both are false for a missing or non-string target.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The target string is not a key of the KVDB.

## Examples

### Example 1

The KVDB cannot be loaded, so the asset is rejected at build time.

#### Asset

```yaml
check:
  - target_field: in_kvdb('non-existing-db')
```

#### Input Event

```json
{
  "target_field": "0x0"
}
```

*The check was performed with errors*

### Example 2

The target string is a key of the KVDB.

#### Asset

```yaml
check:
  - target_field: in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": "0x0"
}
```

*The check was successful*

### Example 3

The value stored under the key is ignored, so a key holding an array also passes.

#### Asset

```yaml
check:
  - target_field: in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": "bitmask_test_values"
}
```

*The check was successful*

### Example 4

The target string is not a key of the KVDB.

#### Asset

```yaml
check:
  - target_field: in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": "0x99"
}
```

*The check was performed with errors*

### Example 5

The target field is a number, not a string.

#### Asset

```yaml
check:
  - target_field: in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": 0
}
```

*The check was performed with errors*



## Test KVDB

The examples for this helper use the following KVDB resource during tests:

```json
{
  "id": "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name",
    "author": "Wazuh Inc.",
    "date": "2025-10-06T13:32:19Z",
    "description": "KVDB resource used by helper function tests."
  },
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "bitmask_test_values": [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ],
    "access_mask": {
      "0": "Create Child",
      "1": "Delete Child",
      "2": "List Contents",
      "3": "SELF",
      "4": "Read Property",
      "5": "Write Property",
      "6": "Delete Tree",
      "7": "List Object",
      "8": "Control Access",
      "16": "DELETE",
      "17": "READ_CONTROL",
      "18": "WRITE_DAC",
      "19": "WRITE_OWNER",
      "20": "SYNCHRONIZE",
      "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
      "31": "ADS_RIGHT_GENERIC_READ",
      "30": "ADS_RIGHT_GENERIC_WRITE",
      "29": "ADS_RIGHT_GENERIC_EXECUTE",
      "28": "ADS_RIGHT_GENERIC_ALL"
    }
  },
  "enabled": true
}
```

---
# kvdb_decode_bitmask

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: kvdb_decode_bitmask(db, table, mask)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db | string | value | Any string |
| table | string | value | Any string |
| mask | string | reference | Any hexadecimal |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Decodes a hexadecimal bit mask with a lookup table stored in a KVDB and appends the values of the set
bits to the target array.

Behavior:
- `db` and `table` are literal strings resolved when the asset is built: the value stored under `table`
  in the KVDB `db` must be a non-empty object whose keys are decimal bit positions from `0` to `63` (`0`
  is the least significant bit) and whose values all share one JSON type. The table does not need to
  define every bit.
- `mask` is a reference to a string field holding a hexadecimal number, with or without a `0x` prefix
  (for example `21` or `0x0A`), read as a 64-bit value.
- For each bit set in the mask, from bit 0 upwards, the table value of that position is appended to the
  target array; a bit without an entry in the table is skipped.
- A missing target field is created; a target that exists but is not an array is overwritten with the
  new array. Values are appended without a duplicate check.
- The lookup table is loaded when the asset is built: the operation works on that snapshot.

Build errors:
- The KVDB does not exist, is not declared by the integration or is disabled.
- `table` is not a key of the KVDB, or its value is not an object with decimal keys in `0..63` and
  values of one type.
- `db` or `table` is not a literal string, or `mask` is not a reference.
- A number of arguments other than 3.
- The target field is a schema field whose elements are not strings.

Notes:
- A mask with no decodable bit (a mask of `0` included) makes the operation fail and leaves the target
  unchanged.
- `kvdb_lookup_append` appends the values of a list of keys instead of the values of the set bits.


## Fails when

- The mask reference does not exist, is not a string or is not a hexadecimal number.
- No bit of the mask has an entry in the table (a mask of 0 included).

## Examples

### Example 1

Rejected at build time because the KVDB does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('non-existing-db', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "1",
  "target_field": []
}
```

#### Outcome Event

```json
{
  "mask": "1",
  "target_field": []
}
```

*The operation was performed with errors*

### Example 2

Rejected at build time because the table is not a key of the KVDB

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'non_existing_table', $mask)
```

#### Input Event

```json
{
  "mask": "1",
  "target_field": []
}
```

#### Outcome Event

```json
{
  "mask": "1",
  "target_field": []
}
```

*The operation was performed with errors*

### Example 3

Decodes a mask with bit 0 set into the corresponding value of the table

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "1",
  "target_field": []
}
```

#### Outcome Event

```json
{
  "mask": "1",
  "target_field": [
    "Create Child"
  ]
}
```

*The operation was successful*

### Example 4

Decodes a mask with several bits set, from the lowest bit upwards

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "11",
  "target_field": []
}
```

#### Outcome Event

```json
{
  "mask": "11",
  "target_field": [
    "Create Child",
    "Read Property"
  ]
}
```

*The operation was successful*

### Example 5

Skips the set bits that have no entry in the table

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "1100",
  "target_field": []
}
```

#### Outcome Event

```json
{
  "mask": "1100",
  "target_field": [
    "Control Access"
  ]
}
```

*The operation was successful*

### Example 6

Appends the decoded values to an existing array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "10000",
  "target_field": [
    "Base"
  ]
}
```

#### Outcome Event

```json
{
  "mask": "10000",
  "target_field": [
    "Base",
    "DELETE"
  ]
}
```

*The operation was successful*

### Example 7

A target that is not an array is replaced by the new array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "1",
  "target_field": "Base"
}
```

#### Outcome Event

```json
{
  "mask": "1",
  "target_field": [
    "Create Child"
  ]
}
```

*The operation was successful*

### Example 8

Fails and leaves the target unchanged when no set bit has an entry in the table

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_decode_bitmask('windows_kerberos_status_code_to_code_name', 'access_mask', $mask)
```

#### Input Event

```json
{
  "mask": "8000",
  "target_field": [
    "Base"
  ]
}
```

#### Outcome Event

```json
{
  "mask": "8000",
  "target_field": [
    "Base"
  ]
}
```

*The operation was performed with errors*



## Test KVDB

The examples for this helper use the following KVDB resource during tests:

```json
{
  "id": "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name",
    "author": "Wazuh Inc.",
    "date": "2025-10-06T13:32:19Z",
    "description": "KVDB resource used by helper function tests."
  },
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "bitmask_test_values": [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ],
    "access_mask": {
      "0": "Create Child",
      "1": "Delete Child",
      "2": "List Contents",
      "3": "SELF",
      "4": "Read Property",
      "5": "Write Property",
      "6": "Delete Tree",
      "7": "List Object",
      "8": "Control Access",
      "16": "DELETE",
      "17": "READ_CONTROL",
      "18": "WRITE_DAC",
      "19": "WRITE_OWNER",
      "20": "SYNCHRONIZE",
      "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
      "31": "ADS_RIGHT_GENERIC_READ",
      "30": "ADS_RIGHT_GENERIC_WRITE",
      "29": "ADS_RIGHT_GENERIC_EXECUTE",
      "28": "ADS_RIGHT_GENERIC_ALL"
    }
  },
  "enabled": true
}
```

---
# kvdb_lookup

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: kvdb_lookup(db, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db | string | value | Any string |
| key | string | value or reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [string, number, boolean, object, array] | - |


## Description

Copies the value stored under `key` in the KVDB `db` to the target field.

Behavior:
- `db` is a literal string naming a KVDB that must exist, be declared by the integration and be enabled.
- `key` is a literal string or a reference to a string field.
- The value may be of any JSON type (string, number, boolean, object, array or null); it replaces the
  target field, which is created when missing.
- When the target field is a schema field the value is validated against its type, and an object value
  may only contain fields allowed under the target.
- The KVDB content is loaded when the asset is built: the operation works on that snapshot.

Build errors:
- The KVDB does not exist, is not declared by the integration or is disabled.
- `db` is not a literal string, or `key` is a literal that is not a string.
- A number of arguments other than 2.
- The target field is not a schema field and does not start with `_`.

Notes:
- A key that is not in the KVDB makes the operation fail and leaves the event unchanged; the following
  operations of the map block still run.
- `kvdb_lookup_merge` merges the value into the target and `kvdb_lookup_append` appends one value per key.


## Fails when

- The key is not present in the KVDB.
- The key reference does not exist or is not a string.
- The value does not pass the schema validation of the target field.

## Examples

### Example 1

The key is read from a referenced field before the lookup

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('windows_kerberos_status_code_to_code_name', $key)
```

#### Input Event

```json
{
  "key": "0x1",
  "target_field": ""
}
```

#### Outcome Event

```json
{
  "key": "0x1",
  "target_field": "KDC_ERR_NAME_EXP"
}
```

*The operation was successful*

### Example 2

Rejected at build time because the KVDB does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('non-existing-db', $key)
```

#### Input Event

```json
{
  "key": "0x0",
  "target_field": "keep-me"
}
```

#### Outcome Event

```json
{
  "key": "0x0",
  "target_field": "keep-me"
}
```

*The operation was performed with errors*

### Example 3

Fails and leaves the target unchanged when the key is not in the KVDB

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('windows_kerberos_status_code_to_code_name', '0x99')
```

#### Input Event

```json
{
  "target_field": "keep-me"
}
```

#### Outcome Event

```json
{
  "target_field": "keep-me"
}
```

*The operation was performed with errors*

### Example 4

Stores a string value of the KVDB in the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('windows_kerberos_status_code_to_code_name', $key)
```

#### Input Event

```json
{
  "key": "0x0",
  "target_field": ""
}
```

#### Outcome Event

```json
{
  "key": "0x0",
  "target_field": "KDC_ERR_NONE"
}
```

*The operation was successful*

### Example 5

Stores another string value of the KVDB in the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('windows_kerberos_status_code_to_code_name', '0x6')
```

#### Input Event

```json
{
  "target_field": ""
}
```

#### Outcome Event

```json
{
  "target_field": "KDC_ERR_C_PRINCIPAL_UNKNOWN"
}
```

*The operation was successful*

### Example 6

Stores an object value of the KVDB in the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('windows_kerberos_status_code_to_code_name', $key)
```

#### Input Event

```json
{
  "key": "access_mask",
  "target_field": {}
}
```

#### Outcome Event

```json
{
  "key": "access_mask",
  "target_field": {
    "0": "Create Child",
    "1": "Delete Child",
    "2": "List Contents",
    "3": "SELF",
    "4": "Read Property",
    "5": "Write Property",
    "6": "Delete Tree",
    "7": "List Object",
    "8": "Control Access",
    "16": "DELETE",
    "17": "READ_CONTROL",
    "18": "WRITE_DAC",
    "19": "WRITE_OWNER",
    "20": "SYNCHRONIZE",
    "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
    "31": "ADS_RIGHT_GENERIC_READ",
    "30": "ADS_RIGHT_GENERIC_WRITE",
    "29": "ADS_RIGHT_GENERIC_EXECUTE",
    "28": "ADS_RIGHT_GENERIC_ALL"
  }
}
```

*The operation was successful*

### Example 7

Stores an array value of the KVDB in the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup('windows_kerberos_status_code_to_code_name', 'bitmask_test_values')
```

#### Input Event

```json
{
  "target_field": []
}
```

#### Outcome Event

```json
{
  "target_field": [
    0,
    1,
    2,
    3,
    4,
    16,
    17,
    18,
    19,
    20,
    24,
    28,
    29,
    30,
    31
  ]
}
```

*The operation was successful*



## Test KVDB

The examples for this helper use the following KVDB resource during tests:

```json
{
  "id": "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name",
    "author": "Wazuh Inc.",
    "date": "2025-10-06T13:32:19Z",
    "description": "KVDB resource used by helper function tests."
  },
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "bitmask_test_values": [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ],
    "access_mask": {
      "0": "Create Child",
      "1": "Delete Child",
      "2": "List Contents",
      "3": "SELF",
      "4": "Read Property",
      "5": "Write Property",
      "6": "Delete Tree",
      "7": "List Object",
      "8": "Control Access",
      "16": "DELETE",
      "17": "READ_CONTROL",
      "18": "WRITE_DAC",
      "19": "WRITE_OWNER",
      "20": "SYNCHRONIZE",
      "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
      "31": "ADS_RIGHT_GENERIC_READ",
      "30": "ADS_RIGHT_GENERIC_WRITE",
      "29": "ADS_RIGHT_GENERIC_EXECUTE",
      "28": "ADS_RIGHT_GENERIC_ALL"
    }
  },
  "enabled": true
}
```

---
# kvdb_lookup_append

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: kvdb_lookup_append(db, keys)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db | string | value | Any string |
| keys | array | value or reference | Any array |


## Target field

| Type | Possible values |
| ---- | --------------- |
| array | [number, string, boolean, object, array] |


## Description

Looks up every key of `keys` in the KVDB `db` and appends the values found to the target array.

Behavior:
- `db` is a literal string naming a KVDB that must exist, be declared by the integration and be enabled.
- `keys` is a literal array of strings or a reference to a field holding an array of strings.
- One value is appended per key, in key order; an array value is appended as a single nested element.
- Every key must exist in the KVDB and all the values must share one JSON type; otherwise nothing is
  appended (all-or-nothing).
- A missing target field is created; a target that exists but is not an array is overwritten with the
  new array and its old value is lost.
- No duplicate check and no type check against the elements already in the array are done.
- When the target field is a schema field the resulting array is validated against it.
- An empty key list succeeds and appends nothing.
- The KVDB content is loaded when the asset is built: the operation works on that snapshot.

Build errors:
- The KVDB does not exist, is not declared by the integration or is disabled.
- `db` is not a literal string, or `keys` is a literal that is not an array.
- A number of arguments other than 2.

Notes:
- Unlike `array_append`, a target that is not an array is replaced instead of failing the operation.


## Fails when

- Any key is not present in the KVDB.
- The keys reference does not exist, is not an array or holds an element that is not a string.
- The values found do not all have the same JSON type.
- The resulting array is rejected by the schema validation of the target field.

## Examples

### Example 1

Appends the value of each key of a referenced array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', $keys)
```

#### Input Event

```json
{
  "keys": [
    "0x0",
    "0x1",
    "0x6"
  ],
  "target_field": []
}
```

#### Outcome Event

```json
{
  "keys": [
    "0x0",
    "0x1",
    "0x6"
  ],
  "target_field": [
    "KDC_ERR_NONE",
    "KDC_ERR_NAME_EXP",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN"
  ]
}
```

*The operation was successful*

### Example 2

Fails and appends nothing when a key of the referenced array is not in the KVDB

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', $keys)
```

#### Input Event

```json
{
  "keys": [
    "0x2",
    "0x99",
    "0x6"
  ],
  "target_field": []
}
```

#### Outcome Event

```json
{
  "keys": [
    "0x2",
    "0x99",
    "0x6"
  ],
  "target_field": []
}
```

*The operation was performed with errors*

### Example 3

Rejected at build time because the KVDB does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('non-existing-db', ["0x0","0x1"])
```

#### Input Event

```json
{
  "target_field": [
    "BASE"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "BASE"
  ]
}
```

*The operation was performed with errors*

### Example 4

Appends one value per key, in key order

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', $keys)
```

#### Input Event

```json
{
  "keys": [
    "0x0",
    "0x1"
  ],
  "target_field": []
}
```

#### Outcome Event

```json
{
  "keys": [
    "0x0",
    "0x1"
  ],
  "target_field": [
    "KDC_ERR_NONE",
    "KDC_ERR_NAME_EXP"
  ]
}
```

*The operation was successful*

### Example 5

Fails and appends nothing when one of the keys is not in the KVDB

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', ["0x0","0x99","0x6"])
```

#### Input Event

```json
{
  "target_field": []
}
```

#### Outcome Event

```json
{
  "target_field": []
}
```

*The operation was performed with errors*

### Example 6

Appends the values to an existing array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', $keys)
```

#### Input Event

```json
{
  "keys": [
    "0x2"
  ],
  "target_field": [
    "LOCAL_BASE"
  ]
}
```

#### Outcome Event

```json
{
  "keys": [
    "0x2"
  ],
  "target_field": [
    "LOCAL_BASE",
    "KDC_ERR_SERVICE_EXP"
  ]
}
```

*The operation was successful*

### Example 7

Fails and leaves the target unchanged when none of the keys is in the KVDB

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', ["0x99","0x98"])
```

#### Input Event

```json
{
  "target_field": [
    "BASE"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "BASE"
  ]
}
```

*The operation was performed with errors*

### Example 8

An array value of the KVDB is appended as a single nested element

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', $keys)
```

#### Input Event

```json
{
  "keys": [
    "bitmask_test_values"
  ],
  "target_field": []
}
```

#### Outcome Event

```json
{
  "keys": [
    "bitmask_test_values"
  ],
  "target_field": [
    [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ]
  ]
}
```

*The operation was successful*

### Example 9

A target that is not an array is replaced by the new array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_append('windows_kerberos_status_code_to_code_name', ["0x0"])
```

#### Input Event

```json
{
  "target_field": "scalar"
}
```

#### Outcome Event

```json
{
  "target_field": [
    "KDC_ERR_NONE"
  ]
}
```

*The operation was successful*



## Test KVDB

The examples for this helper use the following KVDB resource during tests:

```json
{
  "id": "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name",
    "author": "Wazuh Inc.",
    "date": "2025-10-06T13:32:19Z",
    "description": "KVDB resource used by helper function tests."
  },
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "bitmask_test_values": [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ],
    "access_mask": {
      "0": "Create Child",
      "1": "Delete Child",
      "2": "List Contents",
      "3": "SELF",
      "4": "Read Property",
      "5": "Write Property",
      "6": "Delete Tree",
      "7": "List Object",
      "8": "Control Access",
      "16": "DELETE",
      "17": "READ_CONTROL",
      "18": "WRITE_DAC",
      "19": "WRITE_OWNER",
      "20": "SYNCHRONIZE",
      "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
      "31": "ADS_RIGHT_GENERIC_READ",
      "30": "ADS_RIGHT_GENERIC_WRITE",
      "29": "ADS_RIGHT_GENERIC_EXECUTE",
      "28": "ADS_RIGHT_GENERIC_ALL"
    }
  },
  "enabled": true
}
```

---
# kvdb_lookup_merge

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: kvdb_lookup_merge(db, key, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db | string | value | Any string |
| key | string | value or reference | Any string |
| mode (option, optional) | string | value | deep |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [object, array] | - |


## Description

Merges the value stored under `key` in the KVDB `db` into the target field.

Behavior:
- `db` is a literal string naming a KVDB that must exist, be declared by the integration and be enabled.
- `key` is a literal string or a reference to a string field.
- The target field must already exist and have the same type as the value: both objects, or both arrays.
- Objects, default mode: the top-level members of the value are added to the target; on a shared key the
  KVDB value wins and a nested object is replaced as a whole.
- Objects, `deep` mode: a shared key whose KVDB value is an object or an array is merged recursively; a
  scalar overwrites the target member.
- Arrays, both modes: a de-duplicated union; the elements of the KVDB array that are not already in the
  target are appended in KVDB order, nothing is removed or duplicated.
- When the target field is a schema field the KVDB value (not the merged result) is validated against its
  type before the merge.
- The KVDB content is loaded when the asset is built: the operation works on that snapshot.

Build errors:
- The KVDB does not exist, is not declared by the integration or is disabled.
- `db` is not a literal string, or `key` is a literal that is not a string.
- A third argument other than the literal `deep`, or more than 3 arguments.
- The target field is a schema field that is not an object.
- The target field is not a schema field and does not start with `_`.

Notes:
- In `deep` mode an object or array in the KVDB value whose counterpart in the target has another type
  fails the operation; the members merged before the conflict stay modified.
- `lookup_merge` does the same merge with a value taken from an object.


## Fails when

- The key is not present in the KVDB.
- The key reference does not exist or is not a string.
- The target field does not exist or its type differs from the type of the value.
- The value is neither an object nor an array.
- The value does not pass the schema validation of the target field.
- In deep mode, a nested member is an object or array in the value and has another type in the target.

## Examples

### Example 1

Fails when the KVDB value of a referenced key is a string and the target is an object

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', $key)
```

#### Input Event

```json
{
  "key": "0x2",
  "target_field": {
    "status": "INITIAL"
  }
}
```

#### Outcome Event

```json
{
  "key": "0x2",
  "target_field": {
    "status": "INITIAL"
  }
}
```

*The operation was performed with errors*

### Example 2

Rejected at build time because the KVDB does not exist

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('non-existing-db', $key)
```

#### Input Event

```json
{
  "key": "0x0",
  "target_field": {
    "merged": {
      "status": "INITIAL"
    }
  }
}
```

#### Outcome Event

```json
{
  "key": "0x0",
  "target_field": {
    "merged": {
      "status": "INITIAL"
    }
  }
}
```

*The operation was performed with errors*

### Example 3

Fails and leaves the target unchanged when the key is not in the KVDB

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', '0x99')
```

#### Input Event

```json
{
  "target_field": {
    "merged": {
      "status": "INITIAL"
    }
  }
}
```

#### Outcome Event

```json
{
  "target_field": {
    "merged": {
      "status": "INITIAL"
    }
  }
}
```

*The operation was performed with errors*

### Example 4

Fails when the KVDB value is a string and the target is an object

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', $key)
```

#### Input Event

```json
{
  "key": "0x0",
  "target_field": {
    "status": "INITIAL"
  }
}
```

#### Outcome Event

```json
{
  "key": "0x0",
  "target_field": {
    "status": "INITIAL"
  }
}
```

*The operation was performed with errors*

### Example 5

Fails when the KVDB value is a string and the target is an array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', '0x1')
```

#### Input Event

```json
{
  "target_field": [
    "KDC_ERR_OLD"
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    "KDC_ERR_OLD"
  ]
}
```

*The operation was performed with errors*

### Example 6

Merges the KVDB object into the target, the KVDB winning on shared keys and local-only keys kept

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', $key)
```

#### Input Event

```json
{
  "key": "access_mask",
  "target_field": {
    "0": "LOCAL_OVERRIDE",
    "99": "LOCAL_CUSTOM"
  }
}
```

#### Outcome Event

```json
{
  "key": "access_mask",
  "target_field": {
    "0": "Create Child",
    "1": "Delete Child",
    "2": "List Contents",
    "3": "SELF",
    "4": "Read Property",
    "5": "Write Property",
    "6": "Delete Tree",
    "7": "List Object",
    "8": "Control Access",
    "16": "DELETE",
    "17": "READ_CONTROL",
    "18": "WRITE_DAC",
    "19": "WRITE_OWNER",
    "20": "SYNCHRONIZE",
    "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
    "31": "ADS_RIGHT_GENERIC_READ",
    "30": "ADS_RIGHT_GENERIC_WRITE",
    "29": "ADS_RIGHT_GENERIC_EXECUTE",
    "28": "ADS_RIGHT_GENERIC_ALL",
    "99": "LOCAL_CUSTOM"
  }
}
```

*The operation was successful*

### Example 7

Appends the KVDB array elements that are not already in the target array

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', 'bitmask_test_values')
```

#### Input Event

```json
{
  "target_field": [
    -1
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    -1,
    0,
    1,
    2,
    3,
    4,
    16,
    17,
    18,
    19,
    20,
    24,
    28,
    29,
    30,
    31
  ]
}
```

*The operation was successful*

### Example 8

In deep mode the scalar members of the KVDB object overwrite the shared keys as well

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', $key, 'deep')
```

#### Input Event

```json
{
  "key": "access_mask",
  "target_field": {
    "0": "LOCAL_OVERRIDE",
    "99": "LOCAL_CUSTOM"
  }
}
```

#### Outcome Event

```json
{
  "key": "access_mask",
  "target_field": {
    "0": "Create Child",
    "1": "Delete Child",
    "2": "List Contents",
    "3": "SELF",
    "4": "Read Property",
    "5": "Write Property",
    "6": "Delete Tree",
    "7": "List Object",
    "8": "Control Access",
    "16": "DELETE",
    "17": "READ_CONTROL",
    "18": "WRITE_DAC",
    "19": "WRITE_OWNER",
    "20": "SYNCHRONIZE",
    "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
    "31": "ADS_RIGHT_GENERIC_READ",
    "30": "ADS_RIGHT_GENERIC_WRITE",
    "29": "ADS_RIGHT_GENERIC_EXECUTE",
    "28": "ADS_RIGHT_GENERIC_ALL",
    "99": "LOCAL_CUSTOM"
  }
}
```

*The operation was successful*

### Example 9

In deep mode arrays merge as the same de-duplicated union

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', 'bitmask_test_values', 'deep')
```

#### Input Event

```json
{
  "target_field": [
    -1,
    16
  ]
}
```

#### Outcome Event

```json
{
  "target_field": [
    -1,
    16,
    0,
    1,
    2,
    3,
    4,
    17,
    18,
    19,
    20,
    24,
    28,
    29,
    30,
    31
  ]
}
```

*The operation was successful*

### Example 10

In deep mode a key that is not in the KVDB fails as well

#### Asset

```yaml
normalize:
  - map:
      - target_field: kvdb_lookup_merge('windows_kerberos_status_code_to_code_name', $key, 'deep')
```

#### Input Event

```json
{
  "key": "0x99",
  "target_field": {
    "kerberos": {
      "status": "INITIAL"
    }
  }
}
```

#### Outcome Event

```json
{
  "key": "0x99",
  "target_field": {
    "kerberos": {
      "status": "INITIAL"
    }
  }
}
```

*The operation was performed with errors*



## Test KVDB

The examples for this helper use the following KVDB resource during tests:

```json
{
  "id": "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name",
    "author": "Wazuh Inc.",
    "date": "2025-10-06T13:32:19Z",
    "description": "KVDB resource used by helper function tests."
  },
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "bitmask_test_values": [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ],
    "access_mask": {
      "0": "Create Child",
      "1": "Delete Child",
      "2": "List Contents",
      "3": "SELF",
      "4": "Read Property",
      "5": "Write Property",
      "6": "Delete Tree",
      "7": "List Object",
      "8": "Control Access",
      "16": "DELETE",
      "17": "READ_CONTROL",
      "18": "WRITE_DAC",
      "19": "WRITE_OWNER",
      "20": "SYNCHRONIZE",
      "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
      "31": "ADS_RIGHT_GENERIC_READ",
      "30": "ADS_RIGHT_GENERIC_WRITE",
      "29": "ADS_RIGHT_GENERIC_EXECUTE",
      "28": "ADS_RIGHT_GENERIC_ALL"
    }
  },
  "enabled": true
}
```

---
# not_in_kvdb

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: not_in_kvdb($target_field, db)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks whether the target string is not a key of the KVDB `db`.

Behavior:
- `db` is a literal string naming a KVDB that is declared and enabled in the integration or policy; the
  database is loaded when the asset is built.
- The lookup is an exact, case-sensitive key match; the value stored under the key is ignored.
- A missing or non-string target gives false, so this is not the same as `NOT in_kvdb(...)`, which is
  true for a missing field.

Build errors:
- `db` is a reference or a literal that is not a string.
- The KVDB is not declared, is not enabled, or cannot be loaded.

Notes:
- During shallow asset validation (dependencies not loaded) the check is a no-op that always passes.


## Fails when

- The target field does not exist.
- The target field is not a string.
- The target string is a key of the KVDB.

## Examples

### Example 1

The KVDB cannot be loaded, so the asset is rejected at build time.

#### Asset

```yaml
check:
  - target_field: not_in_kvdb('non-existing-db')
```

#### Input Event

```json
{
  "target_field": "0x0"
}
```

*The check was performed with errors*

### Example 2

The target string is a key of the KVDB.

#### Asset

```yaml
check:
  - target_field: not_in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": "0x0"
}
```

*The check was performed with errors*

### Example 3

The value stored under the key is ignored, so a key holding an array also fails the check.

#### Asset

```yaml
check:
  - target_field: not_in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": "bitmask_test_values"
}
```

*The check was performed with errors*

### Example 4

The target string is not a key of the KVDB.

#### Asset

```yaml
check:
  - target_field: not_in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": "0x99"
}
```

*The check was successful*

### Example 5

The target field is a number, not a string, so the check fails although it is not a key.

#### Asset

```yaml
check:
  - target_field: not_in_kvdb('windows_kerberos_status_code_to_code_name')
```

#### Input Event

```json
{
  "target_field": 0
}
```

*The check was performed with errors*



## Test KVDB

The examples for this helper use the following KVDB resource during tests:

```json
{
  "id": "3c7d9b5e-2f4a-4b6a-9c1d-8e7a2b4c5d10",
  "metadata": {
    "title": "windows_kerberos_status_code_to_code_name",
    "author": "Wazuh Inc.",
    "date": "2025-10-06T13:32:19Z",
    "description": "KVDB resource used by helper function tests."
  },
  "content": {
    "0x0": "KDC_ERR_NONE",
    "0x1": "KDC_ERR_NAME_EXP",
    "0x2": "KDC_ERR_SERVICE_EXP",
    "0x3": "KDC_ERR_BAD_PVNO",
    "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
    "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "bitmask_test_values": [
      0,
      1,
      2,
      3,
      4,
      16,
      17,
      18,
      19,
      20,
      24,
      28,
      29,
      30,
      31
    ],
    "access_mask": {
      "0": "Create Child",
      "1": "Delete Child",
      "2": "List Contents",
      "3": "SELF",
      "4": "Read Property",
      "5": "Write Property",
      "6": "Delete Tree",
      "7": "List Object",
      "8": "Control Access",
      "16": "DELETE",
      "17": "READ_CONTROL",
      "18": "WRITE_DAC",
      "19": "WRITE_OWNER",
      "20": "SYNCHRONIZE",
      "24": "ADS_RIGHT_ACCESS_SYSTEM_SECURITY",
      "31": "ADS_RIGHT_GENERIC_READ",
      "30": "ADS_RIGHT_GENERIC_WRITE",
      "29": "ADS_RIGHT_GENERIC_EXECUTE",
      "28": "ADS_RIGHT_GENERIC_ALL"
    }
  },
  "enabled": true
}
```

---
# parse_alphanumeric

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_alphanumeric(input, [extra_chars])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| extra_chars (optional) | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks that the whole input string is alphanumeric and stores it in the target field.

Behavior:
- Accepts one or more ASCII letters or digits, plus any character listed in the optional `extra_chars`
  string; non-ASCII bytes are not accepted.
- The whole input must match; the string is stored unchanged and replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `extra_chars` is not a literal string, or more than 2 arguments are given.
- The target field is a schema field that is not text-like (text, keyword, wildcard and the like).

Notes:
- `regex_match` tests a pattern without writing anything; `regex_extract` extracts a capture group.


## Fails when

- The input field does not exist or is not a string.
- The input is empty or contains a character that is neither alphanumeric nor in extra_chars.

## Examples

### Example 1

An alphanumeric string is stored unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_alphanumeric($input)
```

#### Input Event

```json
{
  "input": "Hello2024",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "Hello2024",
  "target_field": "Hello2024"
}
```

*The operation was successful*

### Example 2

Fails on a character that is not alphanumeric

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_alphanumeric($input)
```

#### Input Event

```json
{
  "input": "Not{isalphanum}",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "Not{isalphanum}",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

The characters listed in extra_chars are accepted too

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_alphanumeric($input, '-')
```

#### Input Event

```json
{
  "input": "Hello-2024",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "Hello-2024",
  "target_field": "Hello-2024"
}
```

*The operation was successful*

### Example 4

Fails on a character that is neither alphanumeric nor in extra_chars

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_alphanumeric($input, '-')
```

#### Input Event

```json
{
  "input": "Hello 2024",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "Hello 2024",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_between

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_between(input, start, end)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| start | string | value | Any string |
| end | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Extracts the text found between the `start` and `end` delimiters of the input string and stores it in
the target field.

Behavior:
- The input must begin with `start`; the extracted text ends at the first occurrence of `end` after it,
  and that occurrence must be the end of the input (for example `[a]b]` fails).
- `start` and `end` are literal strings; they may not both be empty. An empty `end` matches only when
  the input is exactly `start`.
- The text in between, possibly empty, is stored as a string and replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `start` or `end` is not a literal string, both are empty, or the number of arguments is not 3.
- The target field is a schema field that is not text-like (text, keyword, wildcard and the like).

Notes:
- `parse_quoted` handles escaped delimiters; `regex_extract` extracts with a pattern.


## Fails when

- The input field does not exist or is not a string.
- The input does not begin with start.
- The first occurrence of end after start is not the end of the input, or end is absent.

## Examples

### Example 1

Stores the text between the delimiters

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input, '[', ']')
```

#### Input Event

```json
{
  "input": "[Hello, World!]",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "[Hello, World!]",
  "target_field": "Hello, World!"
}
```

*The operation was successful*

### Example 2

Fails because the first end delimiter is not the end of the input

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input, '(', ')')
```

#### Input Event

```json
{
  "input": "(Start) Middle End",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "(Start) Middle End",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

The first occurrence of end is taken, so a later one does not help

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input, '[', ']')
```

#### Input Event

```json
{
  "input": "[a]b]",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "[a]b]",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 4

The delimiters may be strings of several characters

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_between($input, 'Start', 'End')
```

#### Input Event

```json
{
  "input": "Start and End",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "Start and End",
  "target_field": " and "
}
```

*The operation was successful*



---
# parse_binary

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_binary(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks that the input string is valid standard base64 and stores it, unchanged, in the target field.

Behavior:
- Accepts one or more characters of the standard alphabet `A-Z`, `a-z`, `0-9`, `+` and `/`, followed by
  up to two `=` padding characters, with a total length that is a multiple of 4.
- Whitespace and the URL-safe characters `-` and `_` are rejected.
- The string is not decoded: it is stored as it is and replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is neither binary nor text-like.

Notes:
- `decode_hex` decodes hexadecimal text; nothing decodes base64.


## Fails when

- The input field does not exist or is not a string.
- The input is not valid standard base64 (character set, padding or length).

## Examples

### Example 1

A valid base64 string is stored unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "SGVsbG8sIFdvcmxkIQ==",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "SGVsbG8sIFdvcmxkIQ==",
  "target_field": "SGVsbG8sIFdvcmxkIQ=="
}
```

*The operation was successful*

### Example 2

A single padding character is accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "SGVsbG8=",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "SGVsbG8=",
  "target_field": "SGVsbG8="
}
```

*The operation was successful*

### Example 3

Fails because the length is not a multiple of 4

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "SGVsbG8",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "SGVsbG8",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 4

Fails on the URL-safe alphabet

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "SGVs-G8=",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "SGVs-G8=",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

Fails on a space and on characters outside the alphabet

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "not base64",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "not base64",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 6

An array target is left unchanged when the input is not base64

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "not base64",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "not base64",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 7

An object target is left unchanged when the input is not base64

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "not base64",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "not base64",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*

### Example 8

A boolean target is left unchanged when the input is not base64

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_binary($input)
```

#### Input Event

```json
{
  "input": "not base64",
  "target_field": true
}
```

#### Outcome Event

```json
{
  "input": "not base64",
  "target_field": true
}
```

*The operation was performed with errors*



---
# parse_bool

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_bool(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Converts the input string `true` or `false` to a boolean and stores it in the target field.

Behavior:
- The whole input must be `true` or `false`, compared case-insensitively (`TRUE` and `False` are
  accepted).
- `1`, `0`, `yes`, `no` and surrounding spaces are rejected.
- The boolean replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not a boolean.

Notes:
- `to_bool` converts a number (any non-zero value is true) instead of a string.


## Fails when

- The input field does not exist or is not a string.
- The input is not true or false, in any letter case.

## Examples

### Example 1

The string true becomes the boolean true

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "true",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "true",
  "target_field": true
}
```

*The operation was successful*

### Example 2

The comparison is case-insensitive

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "TRUE",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "TRUE",
  "target_field": true
}
```

*The operation was successful*

### Example 3

The string false becomes the boolean false

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "false",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "false",
  "target_field": false
}
```

*The operation was successful*

### Example 4

Fails on a numeric string

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "1",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

Fails on any other string

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 6

An array target is left unchanged when the input is not a boolean

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 7

An object target is left unchanged when the input is not a boolean

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_bool($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_byte

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_byte(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Converts the input string to an 8-bit signed integer and stores it in the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?`: an optional minus sign, digits and an optional fraction; no
  plus sign, exponent or surrounding spaces.
- The fraction is dropped (truncation toward zero): `3.14` gives `3` and `-2.9` gives `-2`.
- The value must be within -128 and 127; otherwise the operation fails ("Number is out of range").
- The integer replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not byte, short, integer or long.

Notes:
- `to_int` converts a number instead of a string; `hex_to_int` converts hexadecimal text.


## Fails when

- The input field does not exist or is not a string.
- The input is not a decimal number in the accepted syntax.
- The value is outside the range -128..127.

## Examples

### Example 1

The upper bound of the range is accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "127",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "127",
  "target_field": 127
}
```

*The operation was successful*

### Example 2

The lower bound of the range is accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "-128",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "-128",
  "target_field": -128
}
```

*The operation was successful*

### Example 3

The fraction is dropped

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "3.14",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "3.14",
  "target_field": 3
}
```

*The operation was successful*

### Example 4

Fails on a value above the range

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "128",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "128",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 6

An array target is left unchanged when the value is out of range

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "130",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "130",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 7

An object target is left unchanged when the value is out of range

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_byte($input)
```

#### Input Event

```json
{
  "input": "130",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "130",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_csv

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_csv(input, out1, out2, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| out1 | string | value | Any string |
| out2 | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Splits the comma-separated input string into the named output fields of the target object.

Behavior:
- Same as `parse_dsv` with `,` as delimiter and `"` as both quote and escape character.
- The whole input is split on `,`; the text between double quotes is one value even when it contains a
  comma, and `""` inside a quoted value is a literal double quote. Unbalanced quotes fail.
- The number of values must be exactly the number of output names; otherwise nothing is stored.
- Every value is stored as a string, without type inference; an empty value becomes null.
- Each output name is a path relative to the target: a name with `.` or `/` creates nested objects.
- The resulting object replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- Fewer than 2 output names, or an output name that is not a literal string.
- The target field is a schema field that is not an object.

Notes:
- `split` produces an array without quoting rules; `parse_kv` reads key-value pairs.


## Fails when

- The input field does not exist or is not a string.
- The number of values differs from the number of output names.
- The quoting is not balanced.

## Examples

### Example 1

Each value is stored as a string under its output name

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input, 'out1', 'out2', 'out3')
```

#### Input Event

```json
{
  "input": "value1,value2,value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "value1,value2,value3",
  "target_field": {
    "out1": "value1",
    "out2": "value2",
    "out3": "value3"
  }
}
```

*The operation was successful*

### Example 2

Output names with dots or slashes create nested objects

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input, 'out1.key', 'out2/key', 'out3.key/subkey')
```

#### Input Event

```json
{
  "input": "value1,value2,value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "value1,value2,value3",
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

A quoted value may contain the comma

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input, 'out1', 'out2')
```

#### Input Event

```json
{
  "input": "\"a,b\",c",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "\"a,b\",c",
  "target_field": {
    "out1": "a,b",
    "out2": "c"
  }
}
```

*The operation was successful*

### Example 4

An empty value is stored as null

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input, 'out1', 'out2', 'out3')
```

#### Input Event

```json
{
  "input": "a,,c",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "a,,c",
  "target_field": {
    "out1": "a",
    "out2": null,
    "out3": "c"
  }
}
```

*The operation was successful*

### Example 5

Fails because the input holds fewer values than output names

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_csv($input, 'out1', 'out2', 'out3')
```

#### Input Event

```json
{
  "input": "valu1=1 value2=2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "valu1=1 value2=2",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_date

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_date(input, format, [locale])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| format | string | value | Any string |
| locale (optional) | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Parses the input date string with `format` and stores it in the target field normalized to UTC.

Behavior:
- `format` is a literal string resolved when the asset is built, in one of three forms: a strftime-like
  format containing `%` (for example `%Y-%m-%dT%H:%M:%S%Ez`); the name of a predefined format: ANSIC,
  UnixDate, RubyDate, RFC822, RFC822Z, RFC850, RFC1123, RFC1123Z, RFC3339, RFC3164, SYSLOG, ISO8601,
  ISO8601Z, HTTPDATE, NGINX_ERROR or POSTGRES; or a sample date, which must match exactly one of the
  predefined formats.
- `locale` is optional: omitted or set to `_auto` it is C/POSIX, otherwise it must exist on the system.
- The whole input must match the format.
- A missing year is replaced by the current year.
- A `%Z` time zone name is resolved as an IANA zone and the local time is converted to UTC (in a daylight
  saving gap or fold the earliest instant is chosen); a `%z` offset is subtracted; without either the
  time is taken as UTC.
- The output is the string `YYYY-MM-DDTHH:MM:SS.mmmZ`, with millisecond precision (for example
  `2025-09-01T15:30:00.000Z`), and replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `format` or `locale` is not a literal string, a sample date matches none or several of the predefined
  formats, or the locale does not exist on the system.
- Fewer than 2 or more than 3 arguments.
- The target field is a schema field that is not date, date_nanos or text-like.

Notes:
- `date_to_epoch` converts a date string to a number and fails in daylight saving gaps and folds;
  `epoch_to_date` and `now` produce date strings.


## Fails when

- The input field does not exist or is not a string.
- The input does not match the format.
- The %Z zone name of the input is not a known IANA zone.

## Examples

### Example 1

The offset of an explicit format is subtracted to produce UTC

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input, '%Y-%m-%dT%H:%M:%S%Ez', '_auto')
```

#### Input Event

```json
{
  "input": "2025-09-01T10:30:00-05:00",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "2025-09-01T10:30:00-05:00",
  "target_field": "2025-09-01T15:30:00.000Z"
}
```

*The operation was successful*

### Example 2

A date without zone is taken as UTC

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input, '%d/%m/%Y %H:%M', '_auto')
```

#### Input Event

```json
{
  "input": "01/09/2025 10:30",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "01/09/2025 10:30",
  "target_field": "2025-09-01T10:30:00.000Z"
}
```

*The operation was successful*

### Example 3

A predefined format is selected by name

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input, 'ISO8601Z')
```

#### Input Event

```json
{
  "input": "2025-09-01T10:30:00Z",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "2025-09-01T10:30:00Z",
  "target_field": "2025-09-01T10:30:00.000Z"
}
```

*The operation was successful*

### Example 4

Fails when the input does not match the format

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_date($input, '%Y-%m-%d %H:%M', '_auto')
```

#### Input Event

```json
{
  "input": "2025/09/01 10:30",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "2025/09/01 10:30",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_double

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_double(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Converts the input string to a 64-bit floating-point number and stores it in the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?([eE][+-]?[0-9]+)?`: an optional minus sign, digits, an
  optional fraction and an optional exponent; no plus sign, no leading `.`, no `inf` or `nan`, no
  surrounding spaces.
- The value is stored as a double, with 64-bit precision.
- The number replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not double, float, half_float or scaled_float.

Notes:
- `parse_float` stores the value with 32-bit precision; `to_int` converts a number to an integer.


## Fails when

- The input field does not exist or is not a string.
- The input is not a number in the accepted syntax.

## Examples

### Example 1

A decimal number is stored with its precision

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_double($input)
```

#### Input Event

```json
{
  "input": "23.45",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "23.45",
  "target_field": 23.45
}
```

*The operation was successful*

### Example 2

An exponent is accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_double($input)
```

#### Input Event

```json
{
  "input": "1.5e2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "1.5e2",
  "target_field": 150.0
}
```

*The operation was successful*

### Example 3

Fails on a leading plus sign

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_double($input)
```

#### Input Event

```json
{
  "input": "+1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "+1",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 4

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_double($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_dsv

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_dsv(input, delimiter, quote, escape, out1, out2, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| delimiter | string | value | Any string |
| quote | string | value | Any string |
| escape | string | value | Any string |
| out1 | string | value | Any string |
| out2 | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Splits the delimiter-separated input string into the named output fields of the target object.

Behavior:
- `delimiter`, `quote` and `escape` are literal single characters.
- The whole input is split on the delimiter; the text between quote characters is one value even when
  it contains the delimiter, and an escaped quote inside a quoted value is a literal character.
  Unbalanced quotes fail.
- The number of values must be exactly the number of output names; otherwise nothing is stored.
- Every value is stored as a string, without type inference; an empty value becomes null.
- Each output name is a path relative to the target: a name with `.` or `/` creates nested objects.
- The resulting object replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `delimiter`, `quote` or `escape` is not a single-character literal string.
- Fewer than 2 output names, or an output name that is not a literal string.
- The target field is a schema field that is not an object.

Notes:
- `parse_csv` is this parser with `,` as delimiter and `"` as quote and escape character.


## Fails when

- The input field does not exist or is not a string.
- The number of values differs from the number of output names.
- The quoting is not balanced.

## Examples

### Example 1

Each value is stored as a string under its output name

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input, '|', "'", '\\', 'out1', 'out2')
```

#### Input Event

```json
{
  "input": "value1|value2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "value1|value2",
  "target_field": {
    "out1": "value1",
    "out2": "value2"
  }
}
```

*The operation was successful*

### Example 2

Output names with dots or slashes create nested objects

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input, '|', "'", '\\', 'out1.key', 'out2/key', 'out3.key/subkey')
```

#### Input Event

```json
{
  "input": "value1|value2|value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "value1|value2|value3",
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

A quoted value may contain the delimiter

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input, '|', "'", '\\', 'out1', 'out2')
```

#### Input Event

```json
{
  "input": "'a|b'|c",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "'a|b'|c",
  "target_field": {
    "out1": "a|b",
    "out2": "c"
  }
}
```

*The operation was successful*

### Example 4

Fails because the input holds fewer values than output names

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_dsv($input, '|', '\\', "'", 'out1', 'out2')
```

#### Input Event

```json
{
  "input": "key1:value1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "key1:value1",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_file

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_file(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Splits the input file path into its parts and writes them as members of the target object.

Behavior:
- The whole non-empty input is the path. The separator is `\` when the input contains any backslash,
  otherwise `/`.
- These members are written into the target field as strings, keeping any other member it has; a target
  that is not an object becomes one:
  - `path`: the text before the last separator; `/` when the separator is the first character; the whole
    input when there is no separator.
  - `name`: the text after the last separator, or the whole input when there is no separator.
  - `ext`: the lowercased text after the last `.` of the name, or an empty string.
  - `drive_letter`: only in backslash mode, the first character when it is an uppercase letter from `B`
    to `Y` (`A` and `Z` are not recognized, and the `:` is not checked).

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not an object.

Notes:
- The input is not validated as a path: any non-empty string is split.


## Fails when

- The input field does not exist or is not a string.
- The input is empty.

## Examples

### Example 1

A Windows path yields the drive letter, path, name and extension

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_file($input)
```

#### Input Event

```json
{
  "input": "C:\\Windows\\System32\\program.exe",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "C:\\Windows\\System32\\program.exe",
  "target_field": {
    "path": "C:\\Windows\\System32",
    "ext": "exe",
    "drive_letter": "C",
    "name": "program.exe"
  }
}
```

*The operation was successful*

### Example 2

A Unix path has no drive letter and the extension is lowercased

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_file($input)
```

#### Input Event

```json
{
  "input": "/var/log/syslog.LOG",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "/var/log/syslog.LOG",
  "target_field": {
    "path": "/var/log",
    "ext": "log",
    "name": "syslog.LOG"
  }
}
```

*The operation was successful*

### Example 3

A file in the root directory has the path /

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_file($input)
```

#### Input Event

```json
{
  "input": "/file.txt",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "/file.txt",
  "target_field": {
    "path": "/",
    "ext": "txt",
    "name": "file.txt"
  }
}
```

*The operation was successful*



---
# parse_float

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_float(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Converts the input string to a 32-bit floating-point number and stores it in the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?([eE][+-]?[0-9]+)?`: an optional minus sign, digits, an
  optional fraction and an optional exponent; no plus sign, no leading `.`, no `inf` or `nan`, no
  surrounding spaces.
- The value is stored with 32-bit precision, so `23.45234` becomes `23.45233917236328`.
- The number replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not float, half_float, scaled_float or double.

Notes:
- `parse_double` keeps 64-bit precision.


## Fails when

- The input field does not exist or is not a string.
- The input is not a number in the accepted syntax.

## Examples

### Example 1

The value is stored with 32-bit precision

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input)
```

#### Input Event

```json
{
  "input": "23.45234",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "23.45234",
  "target_field": 23.45233917236328
}
```

*The operation was successful*

### Example 2

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

An array target is left unchanged when the input is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 4

An object target is left unchanged when the input is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_float($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_fqdn

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_fqdn(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks that the input string is a fully qualified domain name and stores it in the target field.

Behavior:
- Accepts one or more characters from `A-Z`, `a-z`, `0-9`, `.` and `-`, at most 253 characters in
  total, not starting with `.` and without two consecutive dots.
- Label length (63) and leading or trailing hyphens are not checked; underscores are not accepted.
- The whole input must match; the string is stored unchanged and replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not text-like (text, keyword, wildcard and the like).

Notes:
- `parse_uri` extracts the domain of a URL.


## Fails when

- The input field does not exist or is not a string.
- The input has a character outside the accepted set, starts with a dot, has two consecutive dots or is longer than 253 characters.

## Examples

### Example 1

A domain name is stored unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input)
```

#### Input Event

```json
{
  "input": "www.someurl.co",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "www.someurl.co",
  "target_field": "www.someurl.co"
}
```

*The operation was successful*

### Example 2

Fails on a character outside the accepted set

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input)
```

#### Input Event

```json
{
  "input": "www.some~url.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "www.some~url.com",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Fails on a leading dot

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input)
```

#### Input Event

```json
{
  "input": ".example.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": ".example.com",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 4

Fails on two consecutive dots

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input)
```

#### Input Event

```json
{
  "input": "www..example.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "www..example.com",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

An array target is left unchanged when the input is not a domain name

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input)
```

#### Input Event

```json
{
  "input": "www.some~url.com",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "www.some~url.com",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 6

An object target is left unchanged when the input is not a domain name

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_fqdn($input)
```

#### Input Event

```json
{
  "input": "www.some~url.com",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "www.some~url.com",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_half_float

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_half_float(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Any number |


## Description

Converts the input string to a floating-point number within the half-precision range and stores it in
the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?([eE][+-]?[0-9]+)?`: an optional minus sign, digits, an
  optional fraction and an optional exponent; no plus sign, no leading `.`, no `inf` or `nan`, no
  surrounding spaces.
- The value must be within -65504 and 65504 (the half-precision range); otherwise the operation fails.
- The value is stored as a 32-bit float: it is not rounded to 16-bit precision, so `23.45234` becomes
  `23.45233917236328`.
- The number replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not half_float, float, scaled_float or double.

Notes:
- `parse_float` and `parse_double` have no range limit beyond their own precision.


## Fails when

- The input field does not exist or is not a string.
- The input is not a number in the accepted syntax.
- The value is outside the range -65504..65504.

## Examples

### Example 1

The value is stored with 32-bit precision

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_half_float($input)
```

#### Input Event

```json
{
  "input": "23.45234",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "23.45234",
  "target_field": 23.45233917236328
}
```

*The operation was successful*

### Example 2

Fails on a value above the half-precision range

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_half_float($input)
```

#### Input Event

```json
{
  "input": "70000",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "70000",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_half_float($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 4

An array target is left unchanged when the input is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_half_float($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 5

An object target is left unchanged when the input is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_half_float($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_integer

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_integer(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Converts the input string to a 32-bit signed integer and stores it in the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?`: an optional minus sign, digits and an optional fraction; no
  plus sign, exponent or surrounding spaces.
- The fraction is dropped (truncation toward zero): `23.45` gives `23`.
- The value must be within -2147483648 and 2147483647; otherwise the operation fails ("Number is out of
  range").
- The integer replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not integer, byte, short or long.

Notes:
- `parse_long` accepts the 64-bit range; `to_int` converts a number instead of a string.


## Fails when

- The input field does not exist or is not a string.
- The input is not a decimal number in the accepted syntax.
- The value is outside the range -2147483648..2147483647.

## Examples

### Example 1

A negative integer is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_integer($input)
```

#### Input Event

```json
{
  "input": "-2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "-2",
  "target_field": -2
}
```

*The operation was successful*

### Example 2

A positive integer is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_integer($input)
```

#### Input Event

```json
{
  "input": "12345",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "12345",
  "target_field": 12345
}
```

*The operation was successful*

### Example 3

The fraction is dropped

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_integer($input)
```

#### Input Event

```json
{
  "input": "23.45",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "23.45",
  "target_field": 23
}
```

*The operation was successful*

### Example 4

Fails on a value above the 32-bit range

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_integer($input)
```

#### Input Event

```json
{
  "input": "2147483648",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "2147483648",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_integer($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_ip

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_ip(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Checks that the input string is an IPv4 or IPv6 address and stores it in the target field.

Behavior:
- Accepts an IPv4 address (four decimal numbers from 0 to 255 separated by dots) or an IPv6 address in
  any standard notation: eight groups of up to four hexadecimal digits, a form compressed with `::`, or
  a form with an embedded IPv4 address.
- The address is validated with the system's `inet_pton`; zone identifiers (`%eth0`), CIDR suffixes,
  brackets and ports are rejected.
- The string is stored unchanged, without normalization, and replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is neither ip nor text-like.

Notes:
- `is_ipv4` and `is_ipv6` test the target without writing; `ip_version` returns the family.


## Fails when

- The input field does not exist or is not a string.
- The input is not a valid IPv4 or IPv6 address.

## Examples

### Example 1

An IPv4 address is stored unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input)
```

#### Input Event

```json
{
  "input": "192.168.1.1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "192.168.1.1",
  "target_field": "192.168.1.1"
}
```

*The operation was successful*

### Example 2

A full IPv6 address is stored unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input)
```

#### Input Event

```json
{
  "input": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
  "target_field": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}
```

*The operation was successful*

### Example 3

A compressed IPv6 address is accepted and not expanded

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input)
```

#### Input Event

```json
{
  "input": "::1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "::1",
  "target_field": "::1"
}
```

*The operation was successful*

### Example 4

Fails on CIDR notation

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input)
```

#### Input Event

```json
{
  "input": "192.168.1.1/24",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "192.168.1.1/24",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

An array target is left unchanged when the input is not an address

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input)
```

#### Input Event

```json
{
  "input": "999.999.999.999",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "999.999.999.999",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*

### Example 6

An object target is left unchanged when the input is not an address

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_ip($input)
```

#### Input Event

```json
{
  "input": "999.999.999.999",
  "target_field": {
    "key": "value"
  }
}
```

#### Outcome Event

```json
{
  "input": "999.999.999.999",
  "target_field": {
    "key": "value"
  }
}
```

*The operation was performed with errors*



---
# parse_json

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_json(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| [object, array, string, number, boolean] | - |


## Description

Parses the input string as JSON and stores the resulting value in the target field.

Behavior:
- Any JSON value is accepted: object, array, string, number, boolean or null; the nesting depth is
  limited to 256 levels.
- Leading whitespace is accepted, but any character after the value, a trailing space or newline
  included, makes the operation fail.
- The parsed value replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not an object.

Notes:
- A value that is not an object written into an object schema field is not rejected at runtime.


## Fails when

- The input field does not exist or is not a string.
- The input is not valid JSON, or is nested deeper than 256 levels.
- The input has characters after the JSON value.

## Examples

### Example 1

A JSON object replaces the target field

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input)
```

#### Input Event

```json
{
  "input": "{\"key\": {\"innerKey\": \"value\"}}",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "{\"key\": {\"innerKey\": \"value\"}}",
  "target_field": {
    "key": {
      "innerKey": "value"
    }
  }
}
```

*The operation was successful*

### Example 2

A JSON array is accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input)
```

#### Input Event

```json
{
  "input": "[1, 2]",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "[1, 2]",
  "target_field": [
    1,
    2
  ]
}
```

*The operation was successful*

### Example 3

A JSON scalar is accepted

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input)
```

#### Input Event

```json
{
  "input": "42",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "42",
  "target_field": 42
}
```

*The operation was successful*

### Example 4

Fails on a character after the JSON value, a trailing space included

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input)
```

#### Input Event

```json
{
  "input": "{\"a\": 1} ",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "{\"a\": 1} ",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 5

Fails on invalid JSON and leaves the target unchanged

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_json($input)
```

#### Input Event

```json
{
  "input": "{\"key\": \"innerKey\": \"value\"}}",
  "target_field": [
    "any_value"
  ]
}
```

#### Outcome Event

```json
{
  "input": "{\"key\": \"innerKey\": \"value\"}}",
  "target_field": [
    "any_value"
  ]
}
```

*The operation was performed with errors*



---
# parse_kv

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_kv(input, separator, delimiter, quote, escape)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| separator | string | value | Any string |
| delimiter | string | value | Any string |
| quote | string | value | Any string |
| escape | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Parses the input string as a list of key-value pairs and stores them as members of the target object.

Behavior:
- `separator` joins a key to its value and `delimiter` separates the pairs; both are literal strings of
  one or more characters and must differ. `quote` and `escape` are literal single characters.
- The whole input must be a list of pairs with at least one pair. The text between quote characters is
  one value even when it contains the separator or the delimiter, and an escaped quote is kept as a
  literal character; unbalanced quotes fail.
- Every value is stored as a string with its outer quotes removed; an empty value becomes null.
- Keys lose their outer quotes; a key with dots creates nested objects (`a.b=1` gives
  `{"a": {"b": "1"}}`); a key nested deeper than 256 levels fails; when a key is repeated the last
  value wins.
- The resulting object replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `separator` or `delimiter` is empty, or both are equal.
- `quote` or `escape` is not a single character.
- An option is not a literal string, or the number of arguments is not 5.
- The target field is a schema field that is not an object.

Notes:
- `array_to_object` builds an object out of an array of key-value objects.


## Fails when

- The input field does not exist or is not a string.
- The input is not entirely made of key-value pairs, or holds no pair.
- The quoting is not balanced, or a key is nested deeper than 256 levels.

## Examples

### Example 1

Each pair becomes a member of the target object

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input": "key1=value1 key2=value2 key3=value3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "key1=value1 key2=value2 key3=value3",
  "target_field": {
    "key1": "value1",
    "key2": "value2",
    "key3": "value3"
  }
}
```

*The operation was successful*

### Example 2

Fails when the input holds no pair with the given separator

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input": "key1:value1",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "key1:value1",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

The delimiter may have several characters

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', ' || ', "'", '\\')
```

#### Input Event

```json
{
  "input": "k1=v1 || k2=v2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "k1=v1 || k2=v2",
  "target_field": {
    "k1": "v1",
    "k2": "v2"
  }
}
```

*The operation was successful*

### Example 4

The separator may have several characters

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '::=', ',', "'", '\\')
```

#### Input Event

```json
{
  "input": "a::=x,b::=y",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "a::=x,b::=y",
  "target_field": {
    "a": "x",
    "b": "y"
  }
}
```

*The operation was successful*

### Example 5

Both tokens may have several characters

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '::=', ' || ', '"', '\\')
```

#### Input Event

```json
{
  "input": "k1::=v1 || k2::=v2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "k1::=v1 || k2::=v2",
  "target_field": {
    "k1": "v1",
    "k2": "v2"
  }
}
```

*The operation was successful*

### Example 6

A quoted value may contain the delimiter and loses its quotes

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input": "k1='v 1' k2=v2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "k1='v 1' k2=v2",
  "target_field": {
    "k1": "v 1",
    "k2": "v2"
  }
}
```

*The operation was successful*

### Example 7

An empty value is stored as null

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input": "k1= k2=v2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "k1= k2=v2",
  "target_field": {
    "k1": null,
    "k2": "v2"
  }
}
```

*The operation was successful*

### Example 8

Values are stored as strings and a dotted key creates nested objects

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', ' ', "'", '\\')
```

#### Input Event

```json
{
  "input": "n=1 a.b=x",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "n=1 a.b=x",
  "target_field": {
    "n": "1",
    "a": {
      "b": "x"
    }
  }
}
```

*The operation was successful*

### Example 9

Rejected at build time because the separator and the delimiter are equal

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_kv($input, '=', '=', "'", '\\')
```

#### Input Event

```json
{
  "input": "a=b=c",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "a=b=c",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_long

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_long(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Converts the input string to a 64-bit signed integer and stores it in the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?`: an optional minus sign, digits and an optional fraction; no
  plus sign, exponent or surrounding spaces.
- The fraction is dropped (truncation toward zero): `42.23` gives `42`.
- The value must fit in a 64-bit signed integer; otherwise the operation fails ("Number is out of range").
- The integer replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not long, byte, short or integer.

Notes:
- A value written into a byte, short or integer schema field is not range-checked at runtime.
- `to_int` converts a number instead of a string; `hex_to_int` converts hexadecimal text.


## Fails when

- The input field does not exist or is not a string.
- The input is not a decimal number in the accepted syntax.
- The value does not fit in a 64-bit signed integer.

## Examples

### Example 1

A positive integer is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input)
```

#### Input Event

```json
{
  "input": "12345",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "12345",
  "target_field": 12345
}
```

*The operation was successful*

### Example 2

A negative integer is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input)
```

#### Input Event

```json
{
  "input": "-42",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "-42",
  "target_field": -42
}
```

*The operation was successful*

### Example 3

The fraction is dropped

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input)
```

#### Input Event

```json
{
  "input": "42.23",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "42.23",
  "target_field": 42
}
```

*The operation was successful*

### Example 4

Fails on a string with characters that are not digits

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_long($input)
```

#### Input Event

```json
{
  "input": "12a3",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "12a3",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_quoted

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_quoted(input, [quote], [escape])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| quote (optional) | string | value | Any string |
| escape (optional) | string | value | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Extracts the text enclosed in quotes from the input string and stores it in the target field.

Behavior:
- `quote` (default `"`) and `escape` (default `\`) are optional literal single characters and must
  differ.
- The input must start with the quote character and end at the first unescaped quote, which must be
  the end of the input.
- Inside the text the escape character must be followed by the quote or by the escape character;
  anything else makes the operation fail.
- The stored value is the text between the quotes with every escape character removed: `\"` gives `"`
  and an escaped escape `\\` disappears instead of giving one `\`.
- The string replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `quote` or `escape` is not a single-character literal string, or both are equal.
- More than 3 arguments.
- The target field is a schema field that is not text-like (text, keyword, wildcard and the like).

Notes:
- `parse_between` extracts between two different delimiters without escapes.


## Fails when

- The input field does not exist or is not a string.
- The input does not start with the quote character.
- The escape character is followed by something other than the quote or the escape character.
- The closing quote is missing or is not the end of the input.

## Examples

### Example 1

The text between the default double quotes is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input)
```

#### Input Event

```json
{
  "input": "\"Hello, my name is 'Wazuh'.\"",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "\"Hello, my name is 'Wazuh'.\"",
  "target_field": "Hello, my name is 'Wazuh'."
}
```

*The operation was successful*

### Example 2

An escaped quote is kept and the escape character is removed

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input)
```

#### Input Event

```json
{
  "input": "\"a \\\"b\\\" c\"",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "\"a \\\"b\\\" c\"",
  "target_field": "a \"b\" c"
}
```

*The operation was successful*

### Example 3

An escaped escape character disappears entirely

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input)
```

#### Input Event

```json
{
  "input": "\"a\\\\b\"",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "\"a\\\\b\"",
  "target_field": "ab"
}
```

*The operation was successful*

### Example 4

The quote character can be changed

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input, "'")
```

#### Input Event

```json
{
  "input": "'hi'",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "'hi'",
  "target_field": "hi"
}
```

*The operation was successful*

### Example 5

Fails because the input does not start with the default quote character

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input)
```

#### Input Event

```json
{
  "input": "'escaped\\' quotes'",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "'escaped\\' quotes'",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 6

Fails because the input does not start with a quote

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_quoted($input)
```

#### Input Event

```json
{
  "input": "don't start with quotes \"here",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "don't start with quotes \"here",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_short

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_short(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Converts the input string to a 16-bit signed integer and stores it in the target field.

Behavior:
- The input must match `-?[0-9]+(.[0-9]*)?`: an optional minus sign, digits and an optional fraction; no
  plus sign, exponent or surrounding spaces.
- The fraction is dropped (truncation toward zero): `23.45` gives `23`.
- The value must be within -32768 and 32767; otherwise the operation fails ("Number is out of range").
- The integer replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not short, byte, integer or long.

Notes:
- `to_int` converts a number instead of a string.


## Fails when

- The input field does not exist or is not a string.
- The input is not a decimal number in the accepted syntax.
- The value is outside the range -32768..32767.

## Examples

### Example 1

A negative integer is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_short($input)
```

#### Input Event

```json
{
  "input": "-2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "-2",
  "target_field": -2
}
```

*The operation was successful*

### Example 2

Fails on a value above the range

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_short($input)
```

#### Input Event

```json
{
  "input": "32768",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "32768",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 3

The fraction is dropped

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_short($input)
```

#### Input Event

```json
{
  "input": "23.45",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "23.45",
  "target_field": 23
}
```

*The operation was successful*

### Example 4

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_short($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_unsigned_long

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_unsigned_long(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Converts the input string to a 64-bit unsigned integer and stores it in the target field.

Behavior:
- The input must be digits with an optional fraction; no plus sign, exponent or surrounding spaces. A
  minus sign is rejected by the conversion ("Expected a number").
- The fraction is dropped (truncation toward zero): `23.45` gives `23`.
- The value must be within 0 and 2^64-1; otherwise the operation fails.
- The integer replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not unsigned_long.

Notes:
- `parse_long` accepts negative values.


## Fails when

- The input field does not exist or is not a string.
- The input is not a decimal number in the accepted syntax, or is negative.
- The value does not fit in a 64-bit unsigned integer.

## Examples

### Example 1

Fails on a negative value

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_unsigned_long($input)
```

#### Input Event

```json
{
  "input": "-2",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "-2",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 2

The fraction is dropped

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_unsigned_long($input)
```

#### Input Event

```json
{
  "input": "23.45",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "23.45",
  "target_field": 23
}
```

*The operation was successful*

### Example 3

A positive integer is stored

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_unsigned_long($input)
```

#### Input Event

```json
{
  "input": "2345",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "2345",
  "target_field": 2345
}
```

*The operation was successful*

### Example 4

Fails on a string that is not a number

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_unsigned_long($input)
```

#### Input Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "hello",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# parse_uri

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_uri(input)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Parses the input URL and writes its parts as members of the target object.

Behavior:
- The whole input is validated with libcurl; a scheme is required (there is no default scheme).
- These members are written into the target field as strings, keeping any other member it has, each
  one only when the URL contains it: `original` (the URL as normalized by libcurl, for example with the
  `/` path added), `scheme`, `domain`, `port` (a string, not a number), `path`, `query`, `fragment`,
  `username` and `password`.
- A target that is not an object becomes one.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- A number of arguments other than 1.
- The target field is a schema field that is not an object.

Notes:
- `port` is written as a string also when the target is a schema object with a numeric `port` field.
- `parse_fqdn` validates a bare domain name.


## Fails when

- The input field does not exist or is not a string.
- The input is not a URL accepted by libcurl, a missing scheme included.

## Examples

### Example 1

The normalized URL and its parts are written; the missing path becomes /

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input)
```

#### Input Event

```json
{
  "input": "http://someurl.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "http://someurl.com",
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

Every part present in the URL is written, the port as a string

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input)
```

#### Input Event

```json
{
  "input": "https://user:pw@host.com:8080/p?q=1#f",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "https://user:pw@host.com:8080/p?q=1#f",
  "target_field": {
    "original": "https://user:pw@host.com:8080/p?q=1#f",
    "scheme": "https",
    "domain": "host.com",
    "port": "8080",
    "path": "/p",
    "query": "q=1",
    "fragment": "f",
    "username": "user",
    "password": "pw"
  }
}
```

*The operation was successful*

### Example 3

Fails without a scheme

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input)
```

#### Input Event

```json
{
  "input": "www.someurl.com",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "www.someurl.com",
  "target_field": "any_value"
}
```

*The operation was performed with errors*

### Example 4

A boolean target is left unchanged when the input is not a URL

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input)
```

#### Input Event

```json
{
  "input": "www.someurl.com",
  "target_field": true
}
```

#### Outcome Event

```json
{
  "input": "www.someurl.com",
  "target_field": true
}
```

*The operation was performed with errors*

### Example 5

An array target is left unchanged when the input is not a URL

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_uri($input)
```

#### Input Event

```json
{
  "input": "www.someurl.com",
  "target_field": [
    true
  ]
}
```

#### Outcome Event

```json
{
  "input": "www.someurl.com",
  "target_field": [
    true
  ]
}
```

*The operation was performed with errors*



---
# parse_xml

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
target_field: parse_xml(input, [mode])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| input | string | reference | Any string |
| mode (option, optional) | string | value | windows |


## Target field

| Type | Possible values |
| ---- | --------------- |
| object | Any object |


## Description

Parses the input XML document into an object and stores it in the target field.

Behavior:
- Each element becomes a member named after it: its text goes to `#text`, each attribute to `@<name>`,
  an element with neither text nor attributes becomes `{}`, and repeated sibling elements become an
  array of objects. Every value is a string; a document nested deeper than 256 levels fails.
- With the `windows` mode (Windows Event Log XML): the `Event` element is skipped and its children are
  placed at its level, `<Data Name="X">v</Data>` becomes the member `X` of its parent, and a `Data`
  element without `Name` is appended to a string array in its parent.
- The resulting object replaces the target field.

Build errors:
- `input` is not a reference, or references a schema field that is not a string.
- `mode` is not the literal `windows`, or more than 2 arguments are given.
- The target field is a schema field that is not an object.

Notes:
- `parse_json` reads JSON text.


## Fails when

- The input field does not exist or is not a string.
- The input is not a well-formed XML document.
- The document is nested deeper than 256 levels.

## Examples

### Example 1

The text of an element goes to its

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input)
```

#### Input Event

```json
{
  "input": "<greeting>some greeting</greeting>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "<greeting>some greeting</greeting>",
  "target_field": {
    "greeting": {
      "#text": "some greeting"
    }
  }
}
```

*The operation was successful*

### Example 2

Attributes become members prefixed with @

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input)
```

#### Input Event

```json
{
  "input": "<a x=\"1\">t</a>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "<a x=\"1\">t</a>",
  "target_field": {
    "a": {
      "#text": "t",
      "@x": "1"
    }
  }
}
```

*The operation was successful*

### Example 3

Repeated sibling elements become an array

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input)
```

#### Input Event

```json
{
  "input": "<r><i>1</i><i>2</i></r>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "<r><i>1</i><i>2</i></r>",
  "target_field": {
    "r": {
      "i": [
        {
          "#text": "1"
        },
        {
          "#text": "2"
        }
      ]
    }
  }
}
```

*The operation was successful*

### Example 4

In windows mode the Event element is skipped and named Data elements become members

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input, 'windows')
```

#### Input Event

```json
{
  "input": "<Event><System><Provider Name=\"X\"/></System><EventData><Data Name=\"K\">v</Data></EventData></Event>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "<Event><System><Provider Name=\"X\"/></System><EventData><Data Name=\"K\">v</Data></EventData></Event>",
  "target_field": {
    "System": {
      "Provider": {
        "@Name": "X"
      }
    },
    "EventData": {
      "K": "v"
    }
  }
}
```

*The operation was successful*

### Example 5

Fails on a document that is not well-formed

#### Asset

```yaml
normalize:
  - map:
      - target_field: parse_xml($input)
```

#### Input Event

```json
{
  "input": "<greeting>some greeting<greeting>",
  "target_field": "any_value"
}
```

#### Outcome Event

```json
{
  "input": "<greeting>some greeting<greeting>",
  "target_field": "any_value"
}
```

*The operation was performed with errors*



---
# discard_event

**Kind:** map helper (used in `map`)

**Modifies the target in place:** yes

**On failure:** the target field is not written and the decoder continues with the next operation.

## Signature

```
wazuh.space.event_discarded: discard_event()
```

## Target field

| Path | Type | Possible values |
| ---- | ---- | --------------- |
| wazuh.space.event_discarded | boolean | Any boolean |


## Description

Marks the event as discarded by setting `wazuh.space.event_discarded` to `true`.

Behavior:
- The target field must be exactly `wazuh.space.event_discarded`; the helper takes no arguments.
- The policy option `index_discarded_events` is read when the asset is built and decides what happens:
  - `false`: only the flag is set and every other field is kept. In pre-enrichment the discarded-events
    filter drops the event and counts it in `space.<space>.events.discarded`: it is not enriched and
    reaches no output.
  - `true`: the whole event is erased first and then the flag is set, so the event becomes
    `{"wazuh": {"space": {"event_discarded": true}}}`. It is neither dropped nor counted: it goes through
    enrichment and the outputs, carrying the flag plus whatever later operations and enrichment add.
- The helper itself always succeeds and does not stop processing: the operations after it in the same
  asset and the rest of the decoding still run, and a later operation may overwrite the flag.

Build errors:
- The target field is not `wazuh.space.event_discarded`.
- Any argument is given.

Notes:
- The drop happens in pre-enrichment, not where the helper runs; use it in a map block once the discard
  condition is met.
- The policy value is captured at build time: changing `index_discarded_events` needs a rebuild of the
  policy.


## Fails when

- Never; once the asset is built the helper always succeeds.

## Examples

### Example 1

Sets the discard flag of the event to true and succeeds

#### Asset

```yaml
normalize:
  - map:
      - wazuh.space.event_discarded: discard_event()
```

#### Input Event

```json
{
  "wazuh.space.event_discarded": false
}
```

#### Outcome Event

```json
{
  "wazuh.space.event_discarded": false
}
```

*The operation was successful*



---
# index_unclassified_events

**Kind:** check helper (used in `check`)

**On failure:** the check is false.

## Signature

```
check: index_unclassified_events($wazuh.integration.category)
```

## Target field

| Path | Type | Possible values |
| ---- | ---- | --------------- |
| wazuh.integration.category | string | Any string |


## Description

Checks whether the event is an unclassified event that the policy wants indexed.

Behavior:
- The target must be exactly `wazuh.integration.category`.
- True only when the policy was built with `index_unclassified_events` set to true and the target string
  is equal to `unclassified`, byte for byte.
- The policy flag is captured when the asset is built; with the flag off the check is false for every
  event.
- No arguments are accepted.

Build errors:
- The target is any field other than `wazuh.integration.category`.
- Any argument is given.

Notes:
- Used by the indexer output in the `first_of` branch that routes events to the unclassified index; with
  the flag on it is equivalent to `string_eq($wazuh.integration.category, 'unclassified')`.
- The category is `unclassified` when the last decoder that matched belongs to the catch-all
  `unclassified` integration.
- The test cases below assume a policy built with `index_unclassified_events` set to true.


## Fails when

- The policy flag `index_unclassified_events` is false.
- The target field does not exist.
- The target field is not a string.
- The category is not `unclassified` (the comparison is case-sensitive).

## Examples

### Example 1

The category is unclassified.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": "unclassified"
}
```

*The check was successful*

### Example 2

The category is a known one other than unclassified.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": "security"
}
```

*The check was performed with errors*

### Example 3

The category is a known one other than unclassified.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": "system-activity"
}
```

*The check was performed with errors*

### Example 4

The comparison is case-sensitive.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": "Unclassified"
}
```

*The check was performed with errors*

### Example 5

The category is an empty string.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": ""
}
```

*The check was performed with errors*

### Example 6

The target field is a number, not a string.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": 42
}
```

*The check was performed with errors*

### Example 7

The target field is an array, not a string.

#### Asset

```yaml
check:
  - wazuh.integration.category: index_unclassified_events()
```

#### Input Event

```json
{
  "wazuh.integration.category": [
    "unclassified"
  ]
}
```

*The check was performed with errors*



---
