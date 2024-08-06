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

| Type | Posible values |
| ---- | -------------- |
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

| Type | Posible values |
| ---- | -------------- |
| boolean | Any boolean |


## Description

Perform a query to wazuh-db. If it was able to connect to wazuh-db and run a valid query (no errors)
then map `true` into field if not, then map `false` into field.
If the field field already exists, then it will be replaced. In case of errors target field will not be modified.
This helper function is typically used in the map stage


**Keywords**

- `wdb` 

---
