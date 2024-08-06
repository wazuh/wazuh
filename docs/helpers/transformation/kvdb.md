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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
| [object, array] | - |


## Description

Gets the value of a given key in the DB named db-name and if its successful it merge this
value with what the field had before.
Key value type can be string, number, object, array or null and it must match with the previous
value type hold by field. This helper function is typically used in the map stage.


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

| Type | Posible values |
| ---- | -------------- |
| boolean | Any boolean |


## Description

Removes a key of the database. If the key does not exist, it returns an error.
If it was able to be removed, then map `true` into the field. This helper function is typically used in the map stage


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

| Type | Posible values |
| ---- | -------------- |
| array | [number, string, boolean, object, array] |


## Description

Looks in the database for each key found in $array_ref, and appends the values to field.
Best effort, if a key is not present in the DB, skip it.


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

| Type | Posible values |
| ---- | -------------- |
| [object, array] | - |


## Description

Gets the value of a given key in the DB named db-name and if its successful it stores it in the given field.
Key value type can be string, number, object, array or null. This helper function is typically used in the map stage


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

| Type | Posible values |
| ---- | -------------- |
| boolean | Any boolean |


## Description

Inserts or updates the value of a key in a KVDB named db-name. If the value already exists, it is updated.
If the database does not exist or the key value can't be inserted or updated, it returns an error.
If it was able to insert the value, then map `true` into field, if not, then map `false` into field.
Value type can be string, number, object, array or null. This helper function is typically used in the map stage


**Keywords**

- `kvdb` 

---
