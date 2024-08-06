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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
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
