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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Maps target field value with the content of some key in the specified object.
Where the key is specified with a reference to another field.
The object parameter must be a definition object or a reference to a field containing the object.
This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| boolean | Any boolean |


## Description

Special SCA event decoding function, receives an SCA event and the agent id.
The operation also updates the WDB. This helper wasn't developed to be used by the external users
it will only take care of wdb managing. This helper function is typically used in the map stage.


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Evaluates if the content of the input field is a string that can be successfully converted into a double-precision
floating-point number. It converts and stores the double-precision number in `field` without truncation
as double-precision floating-point numbers are capable of representing a wide range of decimal numbers with
significant precision.


**Keywords**

- `undefined` 

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

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

Moves existing “input_field” to the field name provided (field). Replace if field exist.
This helper function is used in the map stage.


**Keywords**

- `undefined` 

---
