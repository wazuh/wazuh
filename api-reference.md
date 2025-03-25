# API Reference

## Events stateless

### Description

This endpoint receives events to be processed by the Wazuh-Engine security policy. It accepts an NDJSON payload, where each line represents an object, following a strict structure:

- Agent Metadata (First JSON Line): Contains agent-related metadata.

- Subheader (Second JSON Line): Includes mandatory module and collector fields.

- Event Logs (Third and Subsequent JSON Lines): Individual log events enriched with the agent metadata and subheader information.

- New Subheader (Optional): If encountered, it replaces the previous subheader for the following event logs.

The subheader's fields are applied to all subsequent event logs until a new subheader is encountered.

---

### Endpoint

`POST /run/wazuh-server/engine.socket/events/stateless`

### Request Body

The request must be a valid **NDJSON** (Newline Delimited JSON).

### Processing Flow

- The server extracts JSON objects from the NDJSON batch.

- It verifies that at least three lines exist (agent metadata, subheader, and at least one event log).

- The agent metadata is stored and used for event enrichment.

- The subheader is validated to ensure it contains both /module and /collector fields.

- Each log event is merged with:

   - The agent metadata.

   - The module and collector values from the subheader.

- If a new subheader appears within the batch, it is applied to subsequent events.

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `error`          | String | Error message if status is ERROR.                            |
| `code`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Equeue a valid NDJSON

##### Request Body

```json
{"agent":{"id":"2887e1cf-9bf2-431a-b066-a46860080f56","name":"javier","type":"endpoint","version":"5.0.0","groups":["group1","group2"],"host":{"hostname":"myhost","os":{"name":"Amazon Linux 2","platform":"Linux"},"ip":["192.168.1.21"],"architecture":"x86_64"}}}
{"module":"logcollector","collector":"file"}
{"log":{"file":{"path":"/var/log/syslog"}},"tags":["production"],"event":{"original":"System started.","created":"2023-12-26T09:22:14.000Z"}}
{"module":"logcollector","collector":"file"}
{"log":{"file":{"path":"/var/log/syslog"}},"tags":["production"],"event":{"original":"System stopped.","created":"2023-12-26T09:27:24.000Z"}}
```

##### Queued events

```json
[
    {
        "agent": {
            "id":"2887e1cf-9bf2-431a-b066-a46860080f56",
            "name":"javier",
            "type":"endpoint",
            "version":"5.0.0",
            "groups":["group1","group2"],
            "host": {
                "hostname":"myhost",
                "os": {
                    "name":"Amazon Linux 2",
                    "platform":"Linux"
                    },
                "ip":["192.168.1.21"],
                "architecture":"x86_64"
            }
        },
        "event": {
            "collector": "file",
            "created":"2023-12-26T09:22:14.000Z",
            "module": "logcollector",
            "original":"System started."
        },
        "log": {
            "file": {
                "path": "/var/log/syslog"
            }
        },
        "tags":["production"]
    },
    {
        "agent": {
            "id":"2887e1cf-9bf2-431a-b066-a46860080f56",
            "name":"javier",
            "type":"endpoint",
            "version":"5.0.0",
            "groups":["group1","group2"],
            "host": {
                "hostname":"myhost",
                "os": {
                    "name":"Amazon Linux 2",
                    "platform":"Linux"
                    },
                "ip":["192.168.1.21"],
                "architecture":"x86_64"
            }
        },
        "event": {
            "collector": "file",
            "created":"2023-12-26T09:27:24.000Z",
            "module": "logcollector",
            "original":"System stopped."
        },
        "log": {
            "file": {
                "path": "/var/log/syslog"
            }
        },
        "tags":["production"]
    }
]
```

##### Response Body
HTTP/1.1 200 OK


### Example of failed cases

#### The header is invalid

##### Request Body

```json
header
{"module":"logcollector","collector":"file"}
{"message": "hello"}
```

##### Response Body
HTTP/1.1 400 Bad Request
```json
{
    "error": "NDJson parser error, invalid header: 'JSON document could not be parsed: Invalid value.'",
    "code": 400
}
```

#### The minimum number of jsons in the NDJSON is not met.

##### Request Body

```json
{"agent":{"id":"2887e1cf-9bf2-431a-b066-a46860080f56"}}
{"module":"logcollector","collector":"file"}
```

##### Response Body
HTTP/1.1 400 Bad Request
```json
{
    "error": "NDJson parser error, invalid batch, expected at least 3 lines",
    "code": 400
}
```

#### After the header there is no subheader

##### Request Body

```json
{"message": "hello"}
{"message": "hello"}
{"module":"logcollector","collector":"file"}
```

##### Response Body
HTTP/1.1 400 Bad Request
```json
{
    "error": "NDJson parser error, invalid subheader, expected '/module' and '/collector' fields",
    "code": 400
}
```

#### One of the events is not a valid json

##### Request Body

```json
{"message": "hello"}
{"module":"logcollector","collector":"file"}
text message
```

##### Response Body
HTTP/1.1 400 Bad Request
```json
{
    "error": "NDJson parser error, invalid ndjson line: 'JSON document could not be parsed: Invalid value.'",
    "code": 400
}
```

#### Invalid subheader

##### Request Body

```json
{"message": "hello"}
{"module":"logcollector"}
{"message": "hello"}
```

##### Response Body
HTTP/1.1 400 Bad Request
```json
{
    "error": "NDJson parser error, invalid subheader, expected '/module' and '/collector' fields",
    "code": 400
}
```

## Post a resource in the catalog

### Description

Retrieve a specific resource stored in the catalog, based on its name, type, and namespace. This endpoint allows querying for different kinds of resources (e.g., rules, decoders, outputs, filters) in a structured way.
It returns the content of the resource if it exists, or an error message if the resource is not found.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/catalog/resource/post`

---

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `type`               | String | Type of the resource (rule, decoder, output, filter, schema,  collection, integration)                              |
| `format`          | String | Format of the resource (yaml, json).                             |
| `content`    | String | Content of the resource |
| `namespaceid`             | String  | Namespace where the resource will be created. |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Post a decoder

##### Request Body

```json
{
    "type": "decoder",
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases

#### Missing any of the fields in the request

##### Request Body
```json
{
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /type parameter or is invalid"
}
```

#### The requested collection does not exist

##### Request Body
```json
{
    "type": "non-exist",
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid collection type \"non-exist\""
}
```

#### The requested format does not exist

##### Request Body
```json
{
    "type": "decoder",
    "format": "non-exist",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing or invalid /format parameter"
}
```

#### The asset content does not have a name

##### Request Body
```json
{
    "type": "decoder",
    "format": "yaml",
    "content": "documentation\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid content name 'documentation': Invalid collection type \"documentation\""
}
```

#### The asset name in the content does not match the asset type

##### Request Body
```json
{
    "type": "decoder",
    "format": "yaml",
    "content": "name: non-exist/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid content name 'non-exist/documentation/0': Invalid type \"non-exist\""
}
```

#### The asset already exists currently

##### Request Body
```json
{
    "type": "decoder",
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Content 'decoder/documentation/0' could not be added to store: Document already exists"
}
```

## Put a resource in the catalog

### Description

This endpoint allows adding or updating a resource in the catalog. The resource is identified by its name and must be provided in a supported format (yaml or json). The resource is stored within a specified namespace, ensuring proper organization and retrieval.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/catalog/resource/put`

---

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the resource                             |
| `format`          | String | Format of the resource (yaml, json).                             |
| `content`    | String | Content of the resource |
| `namespaceid`             | String  | Namespace where the resource will be created. |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Put a decoder

##### Request Body

```json
{
    "name": "decoder/documentation/0",
    "format": "yaml",
    "content": "name: decoder/documentation/0\nmetadata:\n  module: wazuh\n  title: Wazuh documentation decoder\n  description: \"Documentation.\\n\"\n  compatibility: All wazuh events.\n  versions:\n    - Wazuh 5.*\n  author:\n    name: Wazuh, Inc.\n    date: 22/11/2024\n  references:\n    - https://documentation.wazuh.com/\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases

#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /name parameter or is invalid"
}
```

#### The requested format does not exist

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "format": "non-exist",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing or invalid /format parameter"
}
```

#### The new content does not have an asset name

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "format": "yaml",
    "content": "documentation\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field 'name' is missing in content"
}
```

#### The asset does not exist in the indicated namespace

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Could not update resource 'decoder/documentation/0': Does not exist in the 'wazuh' namespace"
}
```

## Get a resource in the catalog

### Description

This endpoint allows retrieving a specific resource stored in the catalog based on its name, format, and namespace. The resources can be of different types, such as decoders, rules, filters, and outputs. By providing the correct parameters, you can query the catalog for the resource and its associated content. If the resource is found, the content is returned; if not, an error message is provided.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/catalog/resource/get`

---

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the resource                              |
| `format`          | String | Format of the resource (yaml, json).                             |
| `namespaceid`             | String  | Namespace where the resource was created. |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `content`          | String | Content of the resource if status is OK.                           |

### Example of success cases

#### Get a collection

##### Request Body

```json
{
    "name": "decoder",
    "format": "yaml",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "content": "- decoder/core-wazuh-message\n- decoder/integrations"
}
```

#### Get a specific asset

##### Request Body

```json
{
    "name": "decoder/core-wazuh-message/0",
    "format": "yaml",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "content": "name: decoder/core-wazuh-message/0\nmetadata:\n  module: wazuh\n  title: Wazuh message decoder\n  description: \"Base decoder to process Wazuh message format, parses location part and enriches the events that comes from a Wazuh agent with the host information.\\n\"\n  compatibility: All wazuh events.\n  versions:\n    - Wazuh 5.*\n  author:\n    name: Wazuh, Inc.\n    date: 22/11/2024\n  references:\n    - https://documentation.wazuh.com/\nnormalize:\n  - map:\n      - \"@timestamp\": get_date()"
}
```

### Example of failed cases

#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "decoder"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing or invalid /format parameter"
}
```

#### The requested collection does not exist

##### Request Body
```json
{
    "name": "non-exist",
    "format": "yaml",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid collection type \"non-exist\""
}
```

#### The requested format does not exist

##### Request Body
```json
{
    "name": "decoder",
    "format": "non-exist",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing or invalid /format parameter"
}
```

#### The requested asset name has an invalid format

##### Request Body
```json
{
    "name": "decoder/core-wazuh-message/0/other",
    "format": "yaml",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid name \"decoder/core-wazuh-message/0/other\" received, a name with 1, 2 or 3 parts was expected"
}
```

## Delete a resource in the catalog

### Description

This endpoint allows the deletion of a specific resource from the catalog based on its name and the namespace it resides in. The resource can be a collection, decoder, rule, or any other catalog asset. Upon successful deletion, the resource is removed from the catalog. If the resource is not found or an invalid request is made, an error message is returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/catalog/resource/delete`

---

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the resource                              |
| `namespaceid`             | String  | Namespace where the resource was created. |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Delete a collection

##### Request Body

```json
{
    "name": "decoder",
    "format": "yaml",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

#### Delete a decoder

##### Request Body

```json
{
    "name": "decoder/documentation/0",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases

#### Delete a collection in a namespace that does not exist

##### Request Body
```json
{
    "name": "decoder",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Could not delete collection 'decoder': Collection does not exist\n"
}
```

#### Delete a decoder in a namespace that does not exist

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Could not delete resource 'decoder/documentation/0': Does not exist in the 'wazuh' namespace"
}
```

#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "decoder/documentation/0",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /namespaceid parameter"
}
```

#### Invalid format of the asset name

##### Request Body
```json
{
    "name": "decoder/documentation/0/0",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid name \"decoder/documentation/0/0\" received, a name with 1, 2 or 3 parts was expected"
}
```

## Validate a resource in the catalog

### Description

This endpoint allows the validation of a specific resource in the catalog. The validation checks the resource's name, format, content, and namespace. If the resource is valid, a success response is returned. If there are any issues, such as missing or incorrect parameters or invalid content, an error message is provided.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/catalog/resource/validate`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the resource                              |
| `format`          | String | Format of the resource (yaml, json).                             |
| `content`    | String | Content of the resource |
| `namespaceid`             | String  | Namespace where the resource will be created. |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Validate a decoder

##### Request Body

```json
{
    "name": "decoder",
    "format": "yaml",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "content": "name: decoder/documentation/0\n",
    "namespaceid": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing or invalid /format parameter"
}
```

#### Invalid helper function

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "format": "yaml",
    "content": "name: decoder/documentation/0\nnormalize:\n  - map:\n      - \"@timestamp\": non-exist()",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "In stage 'normalize' builder for block 'map' failed with error: Failed to build operation '@timestamp: map(\"non-exist()\")': Field '@timestamp' value validation failed: Invalid date"
}
```

#### Invalid map structure

##### Request Body
```json
{
    "name": "decoder/documentation/0",
    "format": "yaml",
    "content": "name: decoder/documentation/0\nnormalize:\n  - map:\n  \"@timestamp\": non-exist()",
    "namespaceid": "wazuh"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Stage 'normalize' expects an array or string but got 'object'"
}
```

## Get namespace a resource in the catalog

### Description
This endpoint retrieves the list of namespaces in which resources are cataloged. It does not require any input parameters in the request body. The response includes the status of the query and a list of available namespaces.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/catalog/namespaces/get`

---

### Request Body

```
empty
```

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `namespaces`          | Array String | List of all namespaces.                            |

### Example of success cases

#### Validate a decoder

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "namespaces": ["system"]
}
```

### Example of failed cases

```
No errors occur
```

## Create a policy

### Description

This endpoint allows the creation of a new policy in the catalog. The user specifies the policy name, and the system will process the request accordingly. If successful, it will return an OK status. If any issues occur (such as missing or invalid fields), an error message will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/store/post`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Validate a decoder

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy already exists

##### Request Body
```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Policy already exists: policy/wazuh/0"
}
```

## Get a policy

### Description

This endpoint retrieves the details of a specific policy from the catalog, based on the policy name and an optional list of namespaces. It returns information about the assets associated with the policy in the indicated namespaces or an error if any issues are found with the request.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/store/get`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `namespaces`               | Arry String | List of namespaces to filter in the policy                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `data`          | String | Information about the assets associated with the policy in the indicated namespaces                            |

### Example of success cases

#### Validate a decoder

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespaces": ["system"]
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "data":"policy: policy/wazuh/0\nhash: 6142509188972423790\n"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other",
    "namespaces": ["system"]
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Empty namespaces

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "namespaces": [""]
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Error in namespace name: Name cannot be empty"
}
```

## Delete a policy

### Description

This endpoint allows you to delete a specific policy stored in the catalog, based on its name. If the policy exists, it will be deleted. If the policy doesn't exist, an error message will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/store/delete`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Validate a decoder

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

## Post asset in policy

### Description

This endpoint allows posting an asset into a specific policy. It requires the policy name, the asset name, and the namespace of the asset. If the asset is valid and the policy exists, it will be added to the policy. If the asset doesn't exist, a warning message will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/asset/post`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `asset`               | String | Asset name                              |
| `namespace`               | String | Namespace of the asset                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `warning`          | String | Warning message if validation errors.                            |


### Example of success cases

#### Post an existing asset

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

#### Post an non-existent asset

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "warning":"Saved invalid policy: Could not find namespace for asset 'decoder/documentation/0'"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

## Get assets in policy

### Description

This endpoint retrieves a list of assets in a specific policy. It requires the policy name and the namespace of the asset. If the policy and namespace exist, it will return a list of the assets. If any errors occur, an appropriate error message will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/asset/get`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `namespace`               | String | Namespace of the asset                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `data`          | Array String | List of assets.                            |


### Example of success cases

#### Post an existing asset

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "data":["decoder/documentation/0"]
}
```

#### Post an non-existent asset

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "warning":"Saved invalid policy: Could not find namespace for asset 'decoder/documentation/0'"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "name": "policy/wazuh/0",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### Asset does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Clean the policy, it contains deleted assets: decoder/documentation/0",
    "data":[]
}
```

## Delete assets in policy

### Description

This endpoint is used to delete an asset from a specific policy. It requires the policy name, asset name, and namespace. If the asset and policy exist, the asset will be deleted. If any errors occur, an appropriate error message will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/asset/delete`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `asset`               | String | Asset name                              |
| `namespace`               | String | Namespace of the asset                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `warning`          | String | Warning message if validation errors.                            |


### Example of success cases

#### Delete an existing asset

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "asset": "decoder/documentation/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "asset": "decoder/documentation/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other",
    "asset": "decoder/documentation",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "asset": "decoder/documentation",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### Asset does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "asset": "decoder/documentation",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Asset not found"
}
```

## Clean policy

### Description

This endpoint is used to clean up a policy by removing any deleted assets that are still listed within it. It requires the policy name and returns a list of assets that were successfully cleaned, or validation errors if any occurred.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/asset/clean_deleted`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `data`          | String | Assets deleted and validation errors.                            |


### Example of success cases

#### Clean an existing policy

##### Request Body

```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "data": "\nDeleted assets: decoder/documentation/0"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "asset": "decoder/documentation",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### There are no deleted assets to be cleaned from the policy

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "asset": "decoder/documentation",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "No deleted assets to clean"
}
```


## Add default parent

### Description

This endpoint allows you to set the default parent for a specific namespace within a given policy. The default parent must be a valid decoder or rule. If the parent is not a valid type, the system will return a warning but still save the policy.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/default_parent/post`

---

### Request Body

### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `namespace`               | String | Namespace of the assets                              |
| `parent`               | String | Default parent of the namespace                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `warning`          | String | Warning message if validation errors.                            |


### Example of success cases

#### Add default parent

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system",
    "parent": "decoder/documentation-parent/0"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

#### Set a default parent that is neither a rule nor a decoder

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "parent": "filter/documentation/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "OK",
    "warning": "Saved invalid policy: Default parent 'filter/documentation/0' in namespace 'system' is neither a decoder or a rule"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "namespace": "system",
    "parent": "decoder/documentation-parent/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other",
    "namespace": "system",
    "parent": "decoder/documentation-parent/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "parent": "decoder/documentation-parent/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

## Get default parent

### Description

This endpoint retrieves the default parent for a specific namespace within a given policy. The default parent must be set previously in the system, and the response will return the associated parent for the namespace.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/default_parent/get`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `namespace`               | String | Namespace of the assets                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `namespace`               | Array String | Default parent of the namespace                              |


### Example of success cases

#### Get default parent

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "data": ["decoder/documentation-parent/0"]
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

## Delete default parent

### Description

This endpoint deletes the default parent for a specific namespace within a given policy. The default parent to be deleted must be previously set in the system, and this operation removes it from the namespace configuration.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/default_parent/delete`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                              |
| `namespace`               | String | Namespace of the assets                              |
| `parent`               | String | Namespace of the parent                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `warning`          | String | Warning message if validation errors.                            |


### Example of success cases

#### Delete default parent

##### Request Body

```json
{
    "policy": "policy/wazuh/0",
    "parent": "decoder/documentation-parent/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "parent": "decoder/documentation-parent/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

#### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other",
    "parent": "decoder/documentation-parent/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

#### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "parent": "decoder/documentation-parent/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### Default parent does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0",
    "parent": "decoder/documentation-parent-non-exist/0",
    "namespace": "system"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Namespace system not found"
}
```

## List policies

### Description

This endpoint retrieves the list of available policies. It returns all the policies that are stored within the system.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/list`

---


### Request Body

```
empty
```

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `data`          | Array String | List of policies.                            |


### Example of success cases

#### List policies

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "data": ["policy/wazuh/0"]
}
```

### Example of failed cases

```
No errors occur
```

## List namespaces in the policy

### Description

This endpoint retrieves the list of namespaces available in a given policy. It returns all the namespaces associated with the specified policy.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/policy/namespaces/list`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `policy`               | String | Policy name                             |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `data`          | Array String | List of policies.                            |


### Example of success cases

### List namespaces

##### Request Body

```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "data": ["system", "user"]
}
```


### Example of failed cases


### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /policy"
}
```

### Invalid policy name

##### Request Body
```json
{
    "policy": "policy/wazuh/0/other"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid policy name: policy/wazuh/0/0, expected 3 parts"
}
```

### Policy does not exist

##### Request Body
```json
{
    "policy": "policy/wazuh/0"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

## Add a mmdb to the geo manager

### Description

This endpoint allows you to add a new MMDB (MaxMind Database) file to the geo manager. It supports two types of databases: ASN (Autonomous System Number) and City databases.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/geo/db/add`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `path`               | String | Path of the MMDB database file to add.                              |
| `type`       | String | MMDB database type [city|asn].                              |



### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Add a asn mmddb

This is assuming that there is an mmdb database in the indicated path.

##### Request Body

```json
{
    "path": "/tmp/base.mmdb",
    "type": "asn"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

#### Add a city mmddb

This is assuming that there is an mmdb database in the indicated path.

##### Request Body

```json
{
    "path": "/tmp/other-base.mmdb",
    "type": "city"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```


### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Path cannot be empty"
}
```

#### Type non-exist

##### Request Body
```json
{
    "path": "/tmp/other-base.mmdb",
    "type": "non-exist"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid geo::Type name string 'non-exist'"
}
```

#### Name repeated in databases

Assuming a database called base.mmdb already exists

##### Request Body
```json
{
    "path": "/tmp/base.mmdb",
    "type": "city"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Database with name 'base.mmdb' already exists"
}
```

#### The type already exists in some database

Assuming a database called base.mmdb of type city already exists

##### Request Body
```json
{
    "path": "/tmp/other-base.mmdb",
    "type": "city"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Type 'city' already has the database 'base.mmdb'"
}
```

#### The specified path does not contain an mmdb

Assuming there is no mmdb called base.mmdb nor a database of type city

##### Request Body
```json
{
    "path": "/tmp/base.mmdb",
    "type": "city"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Cannot add database '/tmp/base.mmdb': An attempt to read data from the MaxMind DB file failed"
}
```

## Remote upsert

### Description

This endpoint allows for the addition or update of a geolocation MMDB (MaxMind Database) on the server from a remote location. It requires the path to the MMDB file, the type of database (either "city" or "asn"), and URLs for the database and its integrity hash. This operation ensures that the geolocation data is up-to-date by either adding a new MMDB or replacing an existing one, depending on whether the type and name match with the current database configuration.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/geo/db/remoteUpsert`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `path`               | String | Path of the MMDB database file to add.                              |
| `type`       | String | MMDB database type [city|asn].                              |
| `dbUrl`               | String | URL of the remote database.                              |
| `hashUrl`       | String | Hash URL for integrity verification..                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Add a asn mmddb

This is assuming that there is an mmdb database in the indicated path.

##### Request Body

```json
{
    "path": "/tmp/base.mmdb",
    "type": "asn",
    "dbUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.mmdb",
    "hashUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.md5"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{
    "type": "asn"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Path is mandatory"
}
```

### Type non-exist

##### Request Body
```json
{
    "path": "/tmp/other-base.mmdb",
    "type": "non-exist",
    "dbUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.mmdb",
    "hashUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.md5"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid geo::Type name string 'non-exist'"
}
```

#### Update an mmdb with an incorrect type

Assuming that base.mmdb exists and is of type asn

##### Request Body
```json
{
    "path": "/tmp/base.mmdb",
    "type": "city",
    "dbUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.mmdb",
    "hashUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.md5"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The name 'base.mmdb' does not correspond to any database for type 'city'. If you want it to correspond, please delete the existing database and recreate it with this name."
}
```

#### The type already exists in some database

Assuming a database called base.mmdb of type city already exists

##### Request Body
```json
{
    "path": "/tmp/other-base.mmdb",
    "type": "city"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Type 'city' already has the database 'base.mmdb'"
}
```

#### The specified path does not contain an mmdb

Assuming there is no mmdb called base.mmdb nor a database of type city

##### Request Body
```json
{
    "path": "/tmp/base.mmdb",
    "type": "city",
    "dbUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.mmdb",
    "hashUrl": "https://raw.githubusercontent.com/wazuh/wazuh/main/src/engine/test/integration_tests/geo/data/base.md5"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Cannot download database from 'https://raw.githubusercontent.com/wazuh/wazuh/blob/main/src/engine/test/integration_tests/geo/data/base.mmdb': Failed to download file from 'https://raw.githubusercontent.com/wazuh/wazuh/blob/main/src/engine/test/integration_tests/geo/data/base.mmdb', error: HTTP response code said error, status code: 404."
}
```

## Delete mmdb

### Description

This endpoint allows for the removal of a geolocation MMDB (MaxMind Database) from the server. This operation requires the path of the MMDB file to be deleted. If the specified MMDB does not exist or the path is invalid, the operation will return an error.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/geo/db/del`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `path`               | String | Path of the MMDB database file to add.                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Delete a asn mmddb

This is assuming that there is an mmdb database in the indicated path.

##### Request Body

```json
{
    "path": "/tmp/base.mmdb"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Path cannot be empty"
}
```

#### Database does not exist

Assuming that base.mmdb exists and is of type asn

##### Request Body
```json
{
    "path": "/tmp/base.mmdb"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Database 'base.mmdb' not found"
}
```

## List mmdb

### Description

This endpoint provides a list of all the geolocation MMDB databases currently stored in the server. It returns a collection of entries, each representing a database with its associated name, path, and type (either ASN or CITY). This operation does not require any parameters in the request body.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/geo/db/list`

---


### Request Body

```
empty
```

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `entries`          | Object | List of entries of a db in the geo manager.                            |

## Entries object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Database name.                             |
| `path`          | String | Path of the MMDB database file to add.                            |
| `type`          | String | MMDB database type [city|asn].                           |


### Example of success cases

#### List databases

This is assuming that there are two databases, one of type ASN and one of type CITY.

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "entries": [
        {
            "name": "base.mmdb",
            "path": "/tmp/base.mmdb",
            "type": "asn"
        },
        {
            "name": "other-base.mmdb",
            "path": "/tmp/other-base.mmdb",
            "type": "city"
        }
    ]
}
```

### Example of failed cases

```
No errors occur
```

## Create a route

### Description

This endpoint allows the creation of a new route in the Wazuh Engine API. A route is a rule that determines how requests are processed based on a specified policy, filter, and priority. The route must have a unique name, an associated policy, and a filter to define its behavior. The priority value determines the order of execution when multiple routes exist. The API validates the request to ensure that the policy and filter exist before allowing the creation of a route.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/route/post`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `route`               | Object | Route to add                              |


## Route Object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Route name                              |
| `policy`               | String | Policy to end of the route                              |
| `filter`               | String | Filter to apply to the route                              |
| `priority`               | Unsigned Integer | Priority of the route                              |
| `description`               | String | Description of the route                              |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Create a route

##### Request Body

```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /route"
}
```

##### Request Body
```json
{
    "route": {
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Policy does not exist

The error occurs when sending the route creation request without first creating the policy.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to create the route: Failed to create environment with policy 'policy/wazuh/0' and filter 'filter/allow-all/0': File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### Policy has not assets

The error occurs when sending the route creation request without first having loaded any asset into the policy.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to create the route: Failed to create environment with policy 'policy/wazuh/0' and filter 'filter/allow-all/0': Policy 'policy/wazuh/0' has no assets"
}
```

#### Filter does not exist

The error occurs when sending the route creation request without first creating the filter.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to create the route: Failed to create environment with policy 'policy/wazuh/0' and filter 'filter/allow-all/0': Engine utils: 'filter/allow-all/0' could not be obtained from the store: Document does not exist."
}
```

#### Set priority to 0

This error occurs considering that there is no route with the same name.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 0
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Priority cannot be 0"
}
```

#### Set priority to 1000

This error occurs considering that there is no route with the same name.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 1000
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Priority cannot be greater than 1000"
}
```

#### Create a route with a priority in use

This error occurs because the policy and filter have already been created and a route with the same priority already exists.

##### Request Body
```json
{
    "route": {
        "name": "documentation-copy",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The priority of the route  is already in use"
}
```

#### Route name already exist

This error occurs considering that the policy and filter have already been created and there is a route with the same name created.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The name of the route is already in use"
}
```

## Get a route

### Description

This endpoint allows retrieving detailed information about a specific route in the Wazuh Engine API. The user must provide the name of the route, and if it exists, the API will return its details, including policy, filter, priority, status, and other metadata.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/route/get`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the route to get                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `route`          | Object | Route queried if status is OK                            |

## Route Object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Route name                              |
| `policy`               | String | Policy to end of the route                              |
| `filter`               | String | Filter to apply to the route                              |
| `priority`               | Unsigned Integer | Priority of the route                              |
| `description`               | String | Description of the route                              |
| `policy_sync`               | String | Status of the policy [SYNC_UNKNOWN|UPDATED|OUTDATED|ERROR]                              |
| `entry_status`               | String | Status of the entry [STATE_UNKNOWN|DISABLED|ENABLED]                              |
| `uptime`               | Unsigned Integer | Last update of the route                              |

### Example of success cases

#### Get a route

##### Request Body

```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "filter": "filter/allow-all/0",
        "priority": 250,
        "policy_sync": "UPDATED",
        "entry_status": "ENABLED",
        "uptime": 1809
    }
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Route does not exist

This error occurs considering that the route has not yet been created.

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The route not exist"
}
```

## Delete a route

### Description

This endpoint allows deleting a specific route in the Wazuh Engine API. The user must provide the name of the route to be deleted. If the route exists, it will be removed, and the API will return a success response.


---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/route/delete`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the route to get                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Delete a route

##### Request Body

```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Route does not exist

This error occurs considering that the route has not yet been created.

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The route not exist"
}
```

## Reload a route

### Description

This endpoint allows reloading a specific route in the Wazuh Engine API. The user must provide the name of the route to be reloaded. If the route exists and is valid, it will be reloaded successfully, and the API will return a success response. Otherwise, an error message will be returned indicating the issue, such as a missing route or validation errors in its associated assets.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/route/reload`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the route to get                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Delete a route

##### Request Body

```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Route does not exist

This error occurs considering that the route has not yet been created.

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The route not exist"
}
```

#### Some asset has validation errors

This error occurs considering that there was a change in some asset of the policy or filter that was not validated correctly.
In this case, the 'name' attribute was misspelled.

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to reload the route: Failed to create environment with policy 'policy/wazuh/0' and filter 'filter/allow-all/0': Expected 'name' key in asset document but got 'n'"
}
```

## Patch priority

### Description

This endpoint allows updating the priority of a specific route in the Wazuh Engine API. The user must provide the name of the route along with the new priority value. If the route exists and the priority value is within the allowed range, the update will be successful. Otherwise, an error message will be returned indicating the issue, such as an invalid priority value or a non-existent route.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/route/patchPriority`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the route to update                              |
| `priority`               | Unsigned Integer | Priority of the route to update                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Delete a route

##### Request Body

```json
{
    "name": "documentation",
    "priority": 10
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Route does not exist

This error occurs considering that the route has not yet been created.

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The route not exist"
}
```

#### Set priority to 1000

This error occurs when trying to update an existing route.

##### Request Body
```json
{
    "name": "documentation",
    "priority": 1000
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Priority cannot be greater than 1000"
}
```

#### Set priority to 0

This error occurs when trying to update an existing route.

##### Request Body
```json
{
    "name": "documentation",
    "priority": 0
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Priority cannot be 0"
}
```

## Get table

### Description

This endpoint retrieves the list of existing routes in the Wazuh Engine API. The response includes details such as the route name, associated policy and filter, priority, status, and last update time. If no routes are available, the response will return an empty table. The request does not require any parameters.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/table/get`

---


### Request Body

```
empty
```


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `table`          | Array Object | Routes queried if status is OK and table is not empty.                            |

## table Object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Route name                              |
| `policy`               | String | Policy to end of the route                              |
| `filter`               | String | Filter to apply to the route                              |
| `priority`               | Unsigned Integer | Priority of the route                              |
| `description`               | String | Description of the route                              |
| `policy_sync`               | String | Status of the policy [SYNC_UNKNOWN|UPDATED|OUTDATED|ERROR]                              |
| `entry_status`               | String | Status of the entry [STATE_UNKNOWN|DISABLED|ENABLED]                              |
| `uptime`               | Unsigned Integer | Last update of the route                              |

### Example of success cases

#### Get table

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "table": [
        {
            "name": "documentation-copy",
            "policy": "policy/wazuh/0",
            "filter": "filter/allow-all/0",
            "priority": 250,
            "policy_sync": "UPDATED",
            "entry_status": "ENABLED",
            "uptime": 233
        }
    ]
}
```

### Example of failed cases

```
No errors occur
```

## Change EPS setting

### Description

This endpoint allows users to change the Event Per Second (EPS) limit and the refresh interval for the system. The EPS limit defines the maximum number of events that the system can process per second. The refresh interval determines how frequently the system will update or refresh the configuration. This change is crucial for adjusting system performance and ensuring efficient event processing.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/eps/changeSettings`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `eps`               | Unsigned Integer | New EPS limit                              |
| `refresh_interval`   | Unsigned Integer | New refresh interval                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Change setting

##### Request Body

```json
{
    "eps": 10,
    "refresh_interval": 1000
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases

#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "EPS Limit must be greater than 0"
}
```

#### Set eps less than 0

##### Request Body
```json
{
    "eps": -10,
    "refresh_interval": 10000
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to parse protobuff json request: INVALID_ARGUMENT:(eps): invalid value -10 for type TYPE_UINT32"
}
```

#### Set refresh_interval less than 0

##### Request Body
```json
{
    "eps": 10,
    "refresh_interval": -10000
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to parse protobuff json request: INVALID_ARGUMENT:(refresh_interval): invalid value -10000 for type TYPE_UINT32"
}
```

## Get EPS setting

### Description

This endpoint allows users to retrieve the current Event Per Second (EPS) limit and the refresh interval settings of the system. It also provides the status of the EPS limiter, indicating whether the EPS limiter is currently enabled or not.
---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/eps/getSettings`

---


### Request Body

```
empty
```

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `eps`               | Unsigned Integer | New EPS limit                              |
| `refresh_interval`   | Unsigned Integer | New refresh interval                              |
| `enable`   | Bool | EPS limiter status                              |

### Example of success cases

#### Get setting

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "eps": 1000,
    "refresh_interval": 10,
    "enabled": false
}
```

### Example of failed cases

```
No errors occur
```

## EPS activate

### Description

This endpoint allows users to activate the Event Per Second (EPS) limiter in the system. When activated, the system starts enforcing the EPS limit, ensuring that no more than the specified number of events are processed per second.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/eps/activate`

---


### Request Body

```
empty
```

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### EPS activate

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases

#### EPS already activate

This error occurs if the EPS is already active

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "EPS counter is already active"
}
```

## EPS deactivate

### Description

This endpoint allows users to deactivate the Event Per Second (EPS) limiter in the system. When deactivated, the system will no longer enforce the EPS limit, allowing the system to process events without restriction. This operation is useful when the user no longer needs to restrict the event processing rate.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/router/eps/deactivate`

---


### Request Body

```
empty
```

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### EPS deactivate

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases

#### EPS already deactivate

This error occurs if the EPS is already deactive

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "EPS counter is already inactive"
}
```

## Create a session

### Description

This endpoint allows users to create a new testing session in the system. A session is associated with a policy and includes a lifetime duration, as well as a description for the session. The session will be used for testing purposes, and its configuration can be customized according to specific needs.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/tester/session/post`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `session`               | Object | Session to add                              |


## Session Object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Session name                              |
| `policy`               | String | Policy to end of the session                              |
| `lifetime`               | Unsigned Integer | Lifetime of the session                              |
| `description`               | String | Description of the session                             |

### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Create a session

This query assumes that a policy is already created

##### Request Body

```json
{
    "session": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "lifetime": 1000,
        "priority": 250
    }
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /session"
}
```

##### Request Body
```json
{
    "route": {
        "policy": "policy/wazuh/0",
        "lifetime": 10000
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Policy does not exist

The error occurs when sending the session creation request without first creating the policy.

##### Request Body
```json
{
    "session": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "lifetime": 10000
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to create the testing environment: File '/var/lib/wazuh-server/engine/store/policy/wazuh/0' does not exist"
}
```

#### Policy has not assets

The error occurs when sending the route creation request without first having loaded any asset into the policy.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "lifetime": 10000
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to create the testing environment: Policy 'policy/wazuh/0' has no assets"
}
```

#### Session name already exist

This error occurs considering that a session with the same name already exists.

##### Request Body
```json
{
    "route": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "lifetime": 10000
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The name of the testing environment already exist"
}
```

## Get a session

### Description

This endpoint allows users to retrieve the details of an existing testing session by providing the session's name. The session information returned includes details such as the associated policy, the session's lifetime, the synchronization status of the policy, the entry status, and the last time the session was used.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/tester/session/get`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Test session name                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `session`          | Object | Session data if status is OK                          |

## Session Object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Session name                              |
| `policy`               | String | Policy to end of the session                              |
| `lifetime`               | Unsigned Integer | Lifetime of the session                              |
| `description`               | String | Description of the session                             |
| `policy_sync`               | String | Status of the policy [SYNC_UNKNOWN|UPDATED|OUTDATED|ERROR]                              |
| `entry_status`               | String | Status of the entry [STATE_UNKNOWN|DISABLED|ENABLED]                              |
| `last_use`               | Unsigned Integer | Last use of the session                              |

### Example of success cases

#### Get a session

It is assumed that a session called "documentation" was created previously

##### Request Body

```json
{
    "name": "documentation",
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "session": {
        "name": "documentation",
        "policy": "policy/wazuh/0",
        "lifetime": 1000,
        "policy_sync": "UPDATED",
        "entry_status": "ENABLED",
        "last_use": 0
    }
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Name cannot be empty"
}
```

#### Session non-exist

##### Request Body
```json
{
    "name": "non-exist-session",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The testing environment not exist"
}
```

## Delete a session

### Description

This endpoint allows users to delete a testing session by specifying the session's name. If the session exists, it will be removed, and the response will indicate a successful deletion. If the session does not exist or the name is missing, the response will return an error message specifying the issue, such as "The testing environment does not exist" or "Name cannot be empty."
---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/tester/session/delete`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Test session name                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Delete a session

It is assumed that a session called "documentation" was created previously

##### Request Body

```json
{
    "name": "documentation",
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid name name: Name cannot be empty"
}
```

#### Session non-exist

##### Request Body
```json
{
    "name": "non-exist-session",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The testing environment not exist"
}
```

## Reload a session

### Description

This endpoint allows users to reload a testing session by specifying the session's name. If the session exists, the system will reload it and return a successful response with the status "OK." If the session does not exist or the name is missing, an error message will be returned specifying the issue. Additionally, if there are validation errors in the session's associated assets, such as a misspelled attribute, the response will indicate a failure to reload the session due to those validation errors.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/tester/session/reload`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Test session name                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Reload a session

It is assumed that a session called "documentation" was created previously

##### Request Body

```json
{
    "name": "documentation",
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Invalid name name: Name cannot be empty"
}
```

#### Session non-exist

##### Request Body
```json
{
    "name": "non-exist-session",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The testing environment not exist"
}
```

#### Some asset has validation errors

This error occurs considering that there was a change in some asset of the policy that was not validated correctly.
In this case, the 'name' attribute was misspelled.

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Failed to create the testing environment: Expected 'name' key in asset document but got 'n'"
}
```

## Get table

### Description

This endpoint allows the user to retrieve information about the current sessions in the system. It queries the active sessions and provides their details, such as name, associated policy, synchronization status, and last usage.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/tester/table/get`

---


### Request Body

```
empty
```


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `table`          | Array Object | Sessions queried if status is OK and table is not empty.                            |

## table Object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Route name                              |
| `policy`               | String | Policy to end of the route                              |
| `description`               | String | Description of the route                              |
| `policy_sync`               | String | Status of the policy [SYNC_UNKNOWN|UPDATED|OUTDATED|ERROR]                              |
| `entry_status`               | String | Status of the entry [STATE_UNKNOWN|DISABLED|ENABLED]                              |
| `last_use`               | Unsigned Integer | Last use of the session                              |

### Example of success cases

#### Get table

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "sessions": [
        {
            "name": "documentation",
            "policy": "policy/wazuh/0",
            "lifetime": 1000,
            "policy_sync": "UPDATED",
            "entry_status": "ENABLED",
            "last_use": 0
        }
    ]
}
```

### Example of failed cases

```
No errors occur
```

## Run test

### Description

This endpoint allows the execution of a test on an event with configurable trace levels. The results of the test, including any asset traces, will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/tester/run/post`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Test session name                              |
| `ndjson_event`       | String | Event to test in NDJSON format                              |
| `trace_level`               | String | Level of traces [NONE|ASSET_ONLY|ALL]                              |
| `asset_trace`               | Array String | Asset of which you only want to have details                              |
| `namespaces`               | Array String | Namespaces where are the assets to test                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `result`          | Object | Result of the test.                            |

## Result object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `output`               | String | JSON output of the event                             |
| `asset_traces`       | Object | Asset traces                              |

## Asset trace object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `asset`               | String | Asset name                             |
| `success`       | Bool | If the asset was successfully decoded                              |
| `traces`       | Array String | Traces of the asset                              |


### Example of success cases

#### Run test without trace level

It is assumed that a session called "documentation" was created previously

##### Request Body

```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}\n{\"module\":\"logcollector\",\"collector\":\"file\"}\n{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\"}}",
    "trace_level": "None"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "result": {
        "output": "{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\",\"module\":\"logcollector\",\"collector\":\"file\"},\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}},\"@timestamp\":\"2025-03-18T20:52:44Z\"}",
        "asset_traces": []
    }
}
```

#### Run test with only asset trace level

It is assumed that a session called "documentation" was created previously

##### Request Body

```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}\n{\"module\":\"logcollector\",\"collector\":\"file\"}\n{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\"}}",
    "trace_level": "ASSET_ONLY",
    "namespaces": ["system"]
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "result": {
        "output": "{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\",\"module\":\"logcollector\",\"collector\":\"file\"},\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}},\"@timestamp\":\"2025-03-19T00:52:00Z\"}",
        "asset_traces": [
            {
                "asset": "decoder/documentation/0",
                "success": true,
                "traces": []
            }
        ]
    }
}
```

#### Run test with all trace level

It is assumed that a session called "documentation" was created previously

##### Request Body

```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}\n{\"module\":\"logcollector\",\"collector\":\"file\"}\n{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\"}}",
    "trace_level": "ALL",
    "namespaces": ["system"]
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "result": {
        "output": "{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\",\"module\":\"logcollector\",\"collector\":\"file\"},\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}},\"@timestamp\":\"2025-03-19T00:55:20Z\"}",
        "asset_traces": [
            {
                "asset": "decoder/documentation/0",
                "success": true,
                "traces": [
                    "@timestamp: get_date -> Success"
                ]
            }
        ]
    }
}
```

### Example of failed cases


#### Missing any of the fields in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Error parsing events: NDJson parser error, empty batch"
}
```

#### Session non-exist

##### Request Body
```json
{
    "name": "non-exist-session",
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The testing environment not exist"
}
```

#### Some asset has validation errors

Assuming we have a session document created, this error occurs when a store asset is modified incorrectly and then when restarting the engine the session is set to inactive state waiting for a correction of the asset and the subsequent reload.

##### Request Body
```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}\n{\"module\":\"logcollector\",\"collector\":\"file\"}\n{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\"}}",
    "trace_level": "None"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The testing environment is not enabled"
}
```

#### Namespace not found when requesting traces

Assuming we have a session document created, this error occurs when we set a trace level different from NONE and do not set a namespace.

##### Request Body
```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}\n{\"module\":\"logcollector\",\"collector\":\"file\"}\n{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\"}}",
    "trace_level": "ASSET_ONLY"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Error: Namespaces parameter is required"
}
```

#### Errors with the protocol

Assuming we have a session document created, this error occurs when the minimum batch size of 3 is not respected.
That is, there must be at least 3 NDJSONs.

##### Request Body
```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}}"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Error parsing events: NDJson parser error, invalid batch, expected at least 3 lines"
}
```

Assuming we have a session document created, this error occurs when the subheader is not correct, since the presence of the collector and module fields in the second NDJSON is mandatory.

##### Request Body
```json
{
    "name": "documentation",
    "ndjson_event": "{\"agent\":{\"id\":\"2887e1cf-9bf2-431a-b066-a46860080f56\",\"name\":\"javier\",\"type\":\"endpoint\",\"version\":\"5.0.0\",\"groups\":[\"group1\",\"group2\"],\"host\":{\"hostname\":\"myhost\",\"os\":{\"name\":\"Amazon Linux 2\",\"platform\":\"Linux\"},\"ip\":[\"192.168.1.21\"],\"architecture\":\"x86_64\"}}}\n{\"non-module\":\"logcollector\",\"non-collector\":\"file\"}\n{\"log\":{\"file\":{\"path\":\"/var/log/syslog\"}},\"tags\":[\"production\"],\"event\":{\"original\":\"System started.\",\"created\":\"2023-12-26T09:22:14.000Z\"}}"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Error parsing events: NDJson parser error, invalid subheader, expected '/module' and '/collector' fields"
}
```

## Add key-value to database

### Description

This endpoint allows adding a new key-value database (kvdb) by specifying the database name and, optionally, a JSON file to define the key-value pairs. If a JSON file is provided, it will be used to create the database. If a database with the same name already exists, the request will return an error.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/manager/post`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to create.                              |
| `path`       | String | Path of the json file used to create the db.                              |



### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Add a empty kvdb

This is assuming that there is no kvdb with the same name.

##### Request Body

```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

#### Add a kvdb using a file

This is assuming that there is no kvdb with the same name.

##### Request Body

```json
{
    "name": "documentation",
    "path": "/tmp/kvdb.json"
}
```

##### kvdb file content
```json
{
    "key": {
        "documentation": "engine"
    }
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```


### Example of failed cases


#### Missing name attribute in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /name"
}
```

#### Indicate in the path a file that is not a json

Assuming there is no other database with the same name

##### Request Body
```json
{
    "name": "documentation",
    "path": "/tmp/kvdb.txt"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The database could not be created. Error: An error occurred while parsing the JSON file '/tmp/kvdb.txt'"
}
```

#### Database already exist

Assuming there is another database with the same name

##### Request Body
```json
{
    "name": "documentation",
    "path": "/tmp/kvdb.json"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The Database already exists."
}
```

#### The path does not exist

Assuming there is no other database with the same name

##### Request Body
```json
{
    "name": "documentation",
    "path": "/tmp/non-exist.json"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The database could not be created. Error: An error occurred while opening the file '/tmp/non-exist.json'"
}
```

## Delete key-value database

### Description

This operation allows deleting an existing key-value database (kvdb) by specifying the database name. If the database exists, it will be removed. If the database does not exist, the operation will return an error.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/manager/delete`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to delete.                              |



### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |


### Example of success cases

#### Delete database

Assuming a database with the required name exists

##### Request Body

```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```


### Example of failed cases


#### Missing name attribute in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /name"
}
```

#### Indicate in the path a file that is not a json

Assuming there is no other database with the same name

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The KVDB 'documentation' does not exist."
}
```


## Get key-value database

### Description

This API allows you to retrieve a list of key-value databases that are currently managed by the system. You can optionally filter the databases by their name or only return those that are currently loaded.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/manager/get`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `must_be_loaded`               | Bool | If true, only the loaded DBs will be returned.                              |
| `filter_by_name`               | String | If not empty, only the DBs with this name will be returned.                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `dbs`          | Array String | List of DBs if status is OK (only the name).|

### Example of success cases

#### Get all databases

Assuming I have two databases loaded

##### Request Body

```json
{}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "dbs": [
        "documentation",
        "other-documentation"
    ]
}
```


### Example of failed cases

```
No errors occur
```

## Dump key-value database

### Description

This API allows you to dump the contents of a specific key-value database. It supports pagination to retrieve the data in chunks, making it easier to handle large databases. Each entry in the database is returned with its key and value in JSON format.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/manager/dump`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to dump.                              |
| `page`               | Unsigned Integer | Page number for pagination.                              |
| `records`               | Unsigned Integer | Number of records per page.                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `entries`          | Array Object | List of entries if status is OK (Empty on error).                            |

## Entry object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `key`               | String | Key of the entry                             |
| `value`          | Json | JSON value of the entry                            |

### Example of success cases

#### Dump database

Assuming a database with the required name exists

##### Request Body

```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "entries": [
        {
            "key": "key",
            "value": "value"
        }
    ]
}
```


### Example of failed cases


#### Missing name attribute in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries": [],
    "error": "Missing /name"
}
```

#### Field page must be greater than 0

Assuming a database with that name exists

##### Request Body
```json
{
    "name": "documentation",
    "page": 0
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field /page must be greater than 0"
}
```

#### Field page must be greater than 0

Assuming a database with that name exists

##### Request Body
```json
{
    "name": "documentation",
    "records": 0
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field /records must be greater than 0"
}
```

#### Database does not exist

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "records": 0
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries":[],
    "error": "The KVDB 'documentation' does not exist."
}
```

## Get an entry from a DB

### Description

This API allows you to retrieve a specific entry from a given key-value database by specifying the database name and the key of the entry you want to retrieve. The entry is returned as a JSON object associated with the provided key.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/db/get`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to get the entry.                              |
| `key`               | String | Key of the entry to get.                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `value`          | Json | JSON value of the entry.|

### Example of success cases

#### Get all databases

Assuming that the database consulted has the following content:

```json
{
    "key": {
        "innerKey": "value"
    }
}
```

##### Request Body

```json
{
    "name": "documentation",
    "key": "key"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "value": {
        "innerKey": "value"
    }
}
```


### Example of failed cases

#### Missing name attribute in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries": [],
    "error": "Missing /name"
}
```

#### Database does not exist

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "key": "key"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries":[],
    "error": "The KVDB 'documentation' does not exist."
}
```

## Delete an entry from a DB

### Description

This API allows you to delete a specific entry from a given key-value database by specifying the database name and the key of the entry you want to delete. If the entry exists, it will be removed from the database. If the entry does not exist, no action will be performed.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/db/delete`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to delete the entry.                              |
| `key`               | String | Key of the entry to delete.                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Get all databases

Assuming that the database consulted has the following content:

```json
{
    "key": {
        "innerKey": "value"
    },
    "otherKey": "other-value"
}
```

##### Request Body

```json
{
    "name": "documentation",
    "key": "key"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

#### Key does not exist

Assuming that the key in the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "key": "non-exist"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK"
}
```

### Example of failed cases

#### Missing name attribute in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /name"
}
```

#### Database does not exist

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "key": "key"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The KVDB 'documentation' does not exist."
}
```

## Put an entry from a DB

### Description

This API allows you to insert a new entry or update an existing entry in a specified key-value database. The entry is identified by its key, and it is associated with a JSON value. If the entry with the same key already exists, it will be overwritten with the new value.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/db/put`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to insert the entry.                              |
| `entry`               | Object | Entry to insert                              |


## Entry object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `key`               | String | Key of the entry.                              |
| `value`               | Json | JSON value of the entry                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |

### Example of success cases

#### Get all databases

Assuming that the database consulted has the following content:

```json
{
    "key": {
        "innerKey": "value"
    },
    "otherKey": "other-value"
}
```

##### Request Body

```json
{
    "name": "documentation",
    "entry": {
        "key": "key",
        "value": {
            "otherInnerKey": "other-value"
        }
    }
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
}
```

### Example of failed cases

#### Missing name attribute in the request

##### Request Body
```json
{}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries": [],
    "error": "Missing /name"
}
```

#### Key is empty

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "entry": {
        "key": "",
        "value": {
            "otherInnerKey": "other-value"
        }
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field /key is empty"
}
```

#### Value is not present

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "entry": {
        "key": "key"
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Missing /entry/value"
}
```

#### Database does not exist

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "entry": {
        "key": "key",
        "value": {
            "otherInnerKey": "other-value"
        }
    }
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "The KVDB 'documentation' does not exist."
}
```

## Get an entries filtered from a DB

### Description

This API allows you to search for entries in a specified key-value database by using a prefix filter. The response will contain the entries that match the prefix. If no entries match the filter, an empty list will be returned.

---

### Endpoint

`POST /run/wazuh-server/engine-api.socket/kvdb/db/search`

---


### Request Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `name`               | String | Name of the db to get the entry.                              |
| `prefix`               | String | prefix of the entries to get                              |
| `page`               | Unsigned Integer | Page number for pagination.                              |
| `records`               | Unsigned Integer | Number of records per page.                              |


### Response Body

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `status`               | String | Status of the query (OK, ERROR)                             |
| `error`          | String | Error message if status is ERROR.                            |
| `entries`          | Array Object | List of entries if status is OK (Empty on error).                            |

## Entry object

| Field               | Type   | Description                                    |
|---------------------|--------|------------------------------------------------|
| `key`               | String | Key of the entry.                              |
| `value`               | Json | JSON value of the entry                              |

### Example of success cases

#### Get all databases

Assuming that the database consulted has the following content:

```json
{
    "key": {
        "innerKey": "value"
    },
    "otherKey": "other-value"
}
```

##### Request Body

```json
{
    "name": "documentation",
    "prefix": "o"
}
```

##### Response Body
```json
HTTP/1.1 200 OK
{
    "status": "OK",
    "entries": [
        {
            "key": "other-key",
            "value": "other-value"
        }
    ]
}
```

### Example of failed cases

#### Missing name attribute in the request

##### Request Body
```json
{
    "name": "documentation"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries": [],
    "error": "Missing /prefix"
}
```

#### Prefix is empty

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "prefix": ""
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field /prefix is empty"
}
```

#### Field page must be greater than 0

Assuming a database with that name exists

##### Request Body
```json
{
    "name": "documentation",
    "prefix": "some",
    "page": 0
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field /page must be greater than 0"
}
```

#### Field page must be greater than 0

Assuming a database with that name exists

##### Request Body
```json
{
    "name": "documentation",
    "prefix": "some",
    "records": 0
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "error": "Field /records must be greater than 0"
}
```

#### Database does not exist

Assuming that the queried database does not exist

##### Request Body
```json
{
    "name": "documentation",
    "prefix": "some"
}
```

##### Response Body
```json
HTTP/1.1 400 Bad Request
{
    "status": "ERROR",
    "entries":[],
    "error": "The KVDB 'documentation' does not exist."
}
```
