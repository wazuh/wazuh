# delete

## Signature

```

field: delete()
```

## Target Field

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
| [number, string, object, boolean, array] | - |


## Description

This operation removes all fields that do not belong to the schema.
Typically used with field = ".", the root element.


**Keywords**

- `delete` 

---
