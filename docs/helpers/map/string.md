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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

Converts any lowercase character to an uppercase character.
The result of the uppercase (upcase) operation is mapped to “field”.
If the “field” already exists, then it will be replaced. In case of errors “field” will not be modified.


**Keywords**

- `string` 

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

| Type | Posible values |
| ---- | -------------- |
| string | Any string |


## Description

The operation converts any uppercase character to an lowercase character.
The result of the lowercase (+downcase) operation is mapped to “field”.
If the field field already exists, then it will be replaced. In case of errors “field” will not be modified.


**Keywords**

- `string` 

---
