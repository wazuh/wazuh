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

| Type | Posible values |
| ---- | -------------- |
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
