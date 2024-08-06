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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Sends a message through the active response queue and updates the field with the result of the execution
if the message could be sent without any problem it will be set to true, if not to false.
Thre result value doesn`t mean that it checks the correct execution of the Active response.
This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Transforms a number into a string with that number.
This helper function is typically used in the map stage


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

The operation concatenates the elements (strings) of the "array" and separates them with “separator”.
The result of the string concatenation (join) operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Date from epoch will convert the input value, can be a reference or a value representing the epoch time to a human readable date time.
Remember epoch, understood as UNIX epoch, is the seconds passed since january first of 1970, so it will fail on negative values.
Floating points numbers will be converted to integers.


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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

The operation transforms a string of hexa digits into an ASCII string. The result of the operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.


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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Calculates the hash SHA-1 of a string. The result of the hash (sha1) operation is rendered as a hexadecimal number
which is 40 digits long and is mapped to “field”. If the “field” already exists, then it will be replaced.
In case of errors “field” will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| number | Integers between `-2^63` and `2^63-1` |


## Description

The peration transforms a number in hexadecimal format (0x...) to a base 10 number.
The result of the operation is mapped to “field”. If the “field” already exists, then it will be replaced.
In case of errors “field” will not be modified.


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

| Type | Posible values |
| ---- | -------------- |
| boolean | Any boolean |


## Description

Receives a JSON object that must contain the agent id, error field and message among other mandatory fields and
send it throug the UPGRADE socket. The result of the communication will be return as a boolean value
being true when sent ok and false otherwise. This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

---
