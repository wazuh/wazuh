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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Checks if the target field value is present as a key in the specified object.
This parameter must be a definition object or a reference to a field containing the object.
If the object contains the key, then the function will evaluate to true, otherwise it will be false.
This helper function is typically used in the check stage.


**Keywords**

- `undefined` 

---
# is_not_array

## Signature

```

field: is_not_array()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| [number, boolean, object, string] | - |


## Description

Checks if the value stored in field is not of type array.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
| string | Any hexadecimal |


## Description

Transforms the hexadecimal value into an unsigned integer and performs the AND bit by bit with the field hexadecimal
transformed to unsigned int. If it is other than 0x0 then the operation evaluates to true.


**Keywords**

- `undefined` 

---
# exists

## Signature

```

field: exists()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks whether the key named “field” exists in the event.
If it does, the function will evaluate to true, otherwise it will be false.
This helper function is used in the check stage.


**Keywords**

- `undefined` 

---
# is_number

## Signature

```

field: is_number()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

Checks if the value stored in field is of type numeric.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Checks if the value stored in the field starts with the value provided.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.


**Keywords**

- `undefined` 

---
# is_boolean

## Signature

```

field: is_boolean()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| boolean | Any boolean |


## Description

Checks if the value stored in field is of type boolean.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
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

| Type | Posible values |
| ---- | -------------- |
| array | Integers between `-2^63` and `2^63-1` |


## Description

Checks if the value stored in field is of type array.
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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
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
# is_object

## Signature

```

field: is_object()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Checks if the value stored in field is of type object.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| [number, string, boolean, array, object] | - |


## Description

Checks if the target field value is present in the specified array.
This parameter must be a definition array or a reference to a field containing the array.
If the array contains the value, then the function will evaluate to true, otherwise it will be false.
This helper function is typically used in the check stage.


**Keywords**

- `undefined` 

---
# is_not_boolean

## Signature

```

field: is_not_boolean()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| [number, array, object, string] | - |


## Description

Checks if the value stored in field is not of type boolean.
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

| Type | Posible values |
| ---- | -------------- |
| [number, array, object, boolean] | - |


## Description

Checks if the value stored in field is not of type string.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Checks if the value stored in field is of type string.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Checks if the value stored in the field contains the value provided.
If they're not, the function evaluates to false.
In case of error, the function will evaluate to false.


**Keywords**

- `undefined` 

---
# is_not_object

## Signature

```

field: is_not_object()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
| [number, array, string, boolean] | - |


## Description

Checks if the value stored in field is not of type object.
If they're not, the function evaluates to false. In case of error, the function will evaluate to false.
This helper function is typically used in the check stage


**Keywords**

- `undefined` 

---
