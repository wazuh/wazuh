# as

## Signature

```

field: as(ip, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Outputs

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Performs a query to the maxmind GeoLite2-ASN database (provided by Maxmind Inc.   https://www.maxmind.com ).
In case of errors the target field will not be modified.
In case of success it will return an object with the following fields:
  - number: mapping of the 'autonomous_system_number' field of the mmdb entry.
  - organization.name: mapping of the 'autonomous_system_organization' field of the mmdb entry.


**Keywords**

- `max_min_db` 

---
# geoip

## Signature

```

field: geoip(ip, [...])
```

## Arguments

| parameter | Type | Source | Accepted values |
| --------- | ---- | ------ | --------------- |
| ip | string | reference | Any IP |


## Outputs

| Type | Posible values |
| ---- | -------------- |
| object | Any object |


## Description

Performs a query to the maxmind GeoLite2-City database (provided by Maxmind Inc.   https://www.maxmind.com ).
In case of errors the target field will not be modified.
In case of success it will return an object with the following fields:
  - city_name: mapping of the 'city.names.en' field of the mmdb entry.
  - continent_code: mapping of the 'continent.code' field of the mmdb entry.
  - continent_name: mapping of the 'continent.names.en' field of the mmdb entry.
  - country_iso_code: mapping of the 'country.iso_code' field of the mmdb entry.
  - country_name: mapping of the 'country.names.en' field of the mmdb entry.
  - postal_code: mapping of the 'postal.code' field of the mmdb entry.
  - location.lat: mapping of the 'location.latitude' field of the mmdb entry.
  - location.lon: mapping of the 'location.longitude' field of the mmdb entry.
  - timezone: mapping of the 'location.time_zone' field of the mmdb entry.
  - region_iso_code: mapping of the 'subdivisions.0.iso_code' field of the mmdb entry.
  - region_name: mapping of the 'subdivisions.0.names.en' field of the mmdb entry.


**Keywords**

- `max_min_db` 

---
