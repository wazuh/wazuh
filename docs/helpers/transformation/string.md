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

| Type | Posible values |
| ---- | -------------- |
| string |


## Description

The operation removes characters (0 or more) from the start, end or start and end of the field.
The result of the trim (trim) operation is mapped to “field”. In case of errors “field” will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `string` 

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

| Type | Posible values |
| ---- | -------------- |
| [object, array, string, number, boolean] | - |


## Description

The operation splits a string into parts by a separator character.
The parts are put into an array of strings. The result of the split into array (split) operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `string` 

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

| Type | Posible values |
| ---- | -------------- |
| string |


## Description

The operation replaces in “field”, all occurrences of the given string by the new string.
In case of errors “field” will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `string` 

---
