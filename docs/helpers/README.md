# Summary
This documentation provides an overview of the auxiliary functions available. Auxiliary functions are modular components designed to perform specific operations on decoders or rules. Depending on their purpose, they are categorized into transformation, filter, or mapping functions.

# Index
## Filter
- [binary_and](#binary_and)
- [contains](#contains)
- [exists](#exists)
- [exists_key_in](#exists_key_in)
- [int_equal](#int_equal)
- [int_greater](#int_greater)
- [int_less](#int_less)
- [int_less_or_equal](#int_less_or_equal)
- [int_not_equal](#int_not_equal)
- [ip_cidr_match](#ip_cidr_match)
- [is_array](#is_array)
- [is_boolean](#is_boolean)
- [is_not_array](#is_not_array)
- [is_not_boolean](#is_not_boolean)
- [is_not_object](#is_not_object)
- [is_not_string](#is_not_string)
- [is_number](#is_number)
- [is_object](#is_object)
- [is_public_ip](#is_public_ip)
- [is_string](#is_string)
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
## Map
- [active_response_send](#active_response_send)
- [as](#as)
- [concat](#concat)
- [concat_any](#concat_any)
- [date_from_epoch](#date_from_epoch)
- [decode_base16](#decode_base16)
- [downcase](#downcase)
- [geoip](#geoip)
- [hex_to_number](#hex_to_number)
- [int_calculate](#int_calculate)
- [ip_version](#ip_version)
- [join](#join)
- [regex_extract](#regex_extract)
- [send_upgrade_confirmation](#send_upgrade_confirmation)
- [sha1](#sha1)
- [system_epoch](#system_epoch)
- [to_string](#to_string)
- [upcase](#upcase)
- [wdb_query](#wdb_query)
- [wdb_update](#wdb_update)
## Transformation
- [array_append](#array_append)
- [array_append_any](#array_append_any)
- [array_append_unique](#array_append_unique)
- [array_append_unique_any](#array_append_unique_any)
- [delete](#delete)
- [erase_custom_fields](#erase_custom_fields)
- [get_key_in](#get_key_in)
- [kvdb_decode_bitmask](#kvdb_decode_bitmask)
- [kvdb_delete](#kvdb_delete)
- [kvdb_get](#kvdb_get)
- [kvdb_get_array](#kvdb_get_array)
- [kvdb_get_merge](#kvdb_get_merge)
- [kvdb_set](#kvdb_set)
- [merge](#merge)
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
- [sca_decoder](#sca_decoder)
- [split](#split)
- [trim](#trim)
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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `integer` 

- `comparison` 

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


**Keywords**

- `integer` 

- `comparison` 

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


**Keywords**

- `integer` 

- `comparison` 

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


**Keywords**

- `integer` 

- `comparison` 

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


**Keywords**

- `integer` 

- `comparison` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `kvdb` 

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


**Keywords**

- `kvdb` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `string` 

- `comparison` 

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


**Keywords**

- `string` 

- `comparison` 

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


**Keywords**

- `string` 

- `comparison` 

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


**Keywords**

- `string` 

- `comparison` 

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


**Keywords**

- `string` 

- `comparison` 

---
# active_response_send

## Signature

```

field: active_response_send(ar-message)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ar-message | string | value or reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Sends a message through the active response queue and updates the field with the result of the execution
if the message could be sent without any problem it will be set to true, if not to false.
Thre result value doesn`t mean that it checks the correct execution of the Active response.
This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

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


**Keywords**

- `max_min_db` 

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


**Keywords**

- `different_types` 

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


**Keywords**

- `different_types` 

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
Remember epoch, understood as UNIX epoch, is the seconds passed since january first of 1970, so it will fail on negative values.
Floating points numbers will be converted to integers.


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `string` 

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


**Keywords**

- `max_min_db` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `math` 

## Notes

- Division by zero is not allowed (the function will fail).

- The limit for a 64-bit integer is 2^63-1 and -2^63.

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


**Keywords**

- `ip` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

---
# send_upgrade_confirmation

## Signature

```

field: send_upgrade_confirmation(json)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| json | object | reference | Any object |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Receives a JSON object that must contain the agent id, error field and message among other mandatory fields and
send it throug the UPGRADE socket. The result of the communication will be return as a boolean value
being true when sent ok and false otherwise. This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `time` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `string` 

---
# wdb_query

## Signature

```

field: wdb_query(query)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| query | string | value or reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| string | Any string |


## Description

Perform a query to wazuh-db. If it was able to connect to wazuh-db and run a valid query (no errors)
then map the payload response of wazuh-db into field. If the field field already exists, then it will be replaced.
In case of errors target field will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `wdb` 

---
# wdb_update

## Signature

```

field: wdb_update(query)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| query | string | value or reference | Any string |


## Outputs

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Perform a query to wazuh-db. If it was able to connect to wazuh-db and run a valid query (no errors)
then map `true` into field if not, then map `false` into field.
If the field field already exists, then it will be replaced. In case of errors target field will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `wdb` 

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


**Keywords**

- `array` 

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


**Keywords**

- `array` 

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


**Keywords**

- `array` 

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


**Keywords**

- `array` 

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


**Keywords**

- `delete` 

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


**Keywords**

- `delete` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `kvdb` 

---
# kvdb_delete

## Signature

```

field: kvdb_delete(db-name, key)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | Any string |
| key | string | value or reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Removes a key of the database. If the key does not exist, it returns an error.
If it was able to be removed, then map `true` into the field. This helper function is typically used in the map stage


**Keywords**

- `kvdb` 

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


**Keywords**

- `kvdb` 

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


**Keywords**

- `kvdb` 

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


**Keywords**

- `kvdb` 

---
# kvdb_set

## Signature

```

field: kvdb_set(db-name, key, value)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| db-name | string | value | Any string |
| key | string | value or reference | Any string |
| value | object, array, string, number, boolean | value or reference | Any object |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Inserts or updates the value of a key in a KVDB named db-name. If the value already exists, it is updated.
If the database does not exist or the key value can't be inserted or updated, it returns an error.
If it was able to insert the value, then map `true` into field, if not, then map `false` into field.
Value type can be string, number, object, array or null. This helper function is typically used in the map stage


**Keywords**

- `kvdb` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `parser` 

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


**Keywords**

- `undefined` 

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


**Keywords**

- `string` 

---
# sca_decoder

## Signature

```

field: sca_decoder(sca_event, agent_id)
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| sca_event | string | reference | Any string |
| agent_id | string | reference | Any string |


## Target Field

| Type | Possible values |
| ---- | --------------- |
| boolean | Any boolean |


## Description

Special SCA event decoding function, receives an SCA event and the agent id.
The operation also updates the WDB. This helper wasn't developed to be used by the external users
it will only take care of wdb managing. This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

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


**Keywords**

- `string` 

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


**Keywords**

- `string` 

---
