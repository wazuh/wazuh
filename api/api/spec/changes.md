## General
* Changed parameter **status** type *string* to *array*
* Date type use a standard format ISO-8601 defined by date-time format.
* Changed parameter **agent_id** type *integer* to *string* with minLength=3
* Changed all return parameters **agent_id** type *integer* to *string*
* Deleted all return parameters **path**, new API don't show any absolute path in responses.
* `error` field has been removed. Now error status is shown in HTTP status code (400 for client error and 500 for server error)
* `data` is never showing a human readable message. To be consistent, it will only contain an object or list of objects. In case
a human readable message is shown, the new field `message` will be used instead.
* Changed search negation from `!` to `-`.

## Active Response
### /active-response/:agent_id
* Parameters **command**, **Custom** and **Arguments** must be in body.
* **command** description changed.
* In response, `data` key is now moved to new `message` key

## Agents


### DELETE /agents
* Parameter **ids** must be in query, not in body because DELETE operations can't have a requestBody in OpenAPI 3
* Parameter **status** renamed to **agent_status**
* In response, `msg` key is now moved to new `message` key

### GET /agents
* Parameter **status** renamed to **agent_status**
* Parameter **os.name** renamed to **os_name**
* Parameter **os.platform** renamed to **os_platform**
* Parameter **os.version** renamed to **os_version**

### GET /agents/groups/{group_id}
* Parameter **status** renamed to **agent_status**

### POST /agents/groups/{group_id}
* In response, `msg` key is now moved to new `message` key

### POST /agents
* Changed parameter **force** name to **force_time**

### DELETE /agents/:agent_id
* Error: parameter **purge** type must be *boolean*, not *string*
* In response, `msg` key is now moved to new `message` key

### DELETE /agents/:agent_id/group
* In response, `data` key is now moved to new `message` key

### DELETE /agents/group/:group_id
* Parameter **agent_id** must be in query, not in body because DELETE operations can't have a requestBody in OpenAPI 3
* Changed parameter **agent_id** name to **list_agents**
* In response, `msg` key is now moved to new `message` key

### DELETE /agents/{agent_id}/group/{group_id}
* In response, `data` key is now moved to new `message` key

### PUT /agents/{agent_id}/group/{group_id}
* In response, `data` key is now moved to new `message` key

### DELETE /agents/groups
* Changed parameter **ids** name to **list_groups**
* Changed request parameters **ids** and **failed_ids** to **affected_groups** and **failed_groups**
* In response, `msg` key is now moved to new `message` key

### DELETE /agents/groups/:group_id
* In response, `msg` key is now moved to new `message` key

### PUT /agents/groups/:group_id
* In response, `data` key is now moved to new `message` key

### POST /agents/groups/:group_id/configuration
* In response, `data` key is now moved to new `message` key

### POST /agents/groups/{group_id}/files/{file_name}
* In response, `data` key is now moved to new `message` key

### PUT /agents/{agent_id}/upgrade
* Changed parameter type **force** from integer to boolean
* In response, `data` key is now moved to new `message` key

### PUT /agents/{agent_id}/upgrade_custom
* In response, `data` key is now moved to new `message` key

### GET /agents/{agent_id}/upgrade_result
* In response, `data` key is now moved to new `message` key

### PUT /agents/:agent_id/restart
* In response, `msg` key is now moved to new `message` key

### POST/agents/insert
* Parameter **force** renamed to **force_after**

### GET/agents/:agent_id/key
* Response structure changed from `{"data": "agent_key"}` to `{"data": {"key": "agent_key"}}`

### POST/agents/restart
* In response, `msg` key is now moved to new `message` key

### PUT/agents/restart
* In response, `data` key is now moved to new `message` key

## Cache
### DELETE /cache 
### GET /cache 
### DELETE /cache{group} (Clear group cache)
### GET /cache/config 
* All cache endpoints have been removed

### GET /lists
* Parameter **status** renamed to **list_status**

## Cluster
### GET /cluster/{node_id}/stats
* Changed date format from YYYYMMDD to YYYY-MM-DD

### GET /cluster/{node_id}/files
* Now file contents are return in a structure like `{"data": {"contents": "file contents"}}`

### POST /cluster/{node_id}/files
* In response, `data` key is now moved to new `message` key

### DELETE /cluster/{node_id}/files
* In response, `data` key is now moved to new `message` key

### PUT /cluster/restart
* In response, `data` key is now moved to new `message` key

### PUT /cluster/{node_id}/restart
* In response, `data` key is now moved to new `message` key

### GET /cluster/configuration/validation
* Now errors are shown in a different schema with a HTTP status 400. See spec for more details.

### GET /cluster/{node_id}/configuration/validation
* Now errors are shown in a different schema with a HTTP status 400. See spec for more details.

## Decoders
### GET /decoders
* In response, `regex` key is now an array

### GET /decoders/{decoders_name}
* In response, `regex` key is now an array

### GET /decoders/files
* Parameter **download** removed

### GET /decoders/files/{file_id}/download
* This endpoint provides the functionality of GET /decoders/files with the old removed **download** param 

### GET /decoders/parents
* In response, `regex` key is now an array

## Experimental
### General
* Changed **ram_free**, **ram_total**, **cpu_cores** type to integer and **cpu_mhz** type to number float
* Deleded all parameters **agent_id** from all endpoints

### DELETE/experimental/syscheck
* In response, `data` key is now moved to new `message` key

### /experimental/syscollector/netiface
* Changed **mtu**, **tx_packets**, **rx_packets**, **tx_bytes**, **rx_bytes**, **tx_errors**, **rx_errors**, **tx_dropped** and **rx_dropped** parameters to type integer.

### /experimental/syscollector/processes
* Parameter **pid** renamed to **process_pid**
* Parameter **status** renamed to **process_status**
* Parameter **name** renamed to **process_name**

## Manager

### GET /manager/files
* Now file contents are return in a structure like `{"data": {"contents": "file contents"}}`

### POST /manager/files
* In response, `data` key is now moved to new `message` key

### DELETE /manager/files
* In response, `data` key is now moved to new `message` key

### GET /manager/stats
* Changed date format from YYYYMMDD to YYYY-MM-DD

### GET/manager/info
* Parameter `openssl_support` is now a boolean.

### PUT/manager/restart
* In response, `data` key is now moved to new `message` key

### GET/manager/stats/weekly
* Parameter **hours** changed to **averages**.

## Rootcheck
### PUT/rootcheck
* In response, `data` key is now moved to new `message` key

### DELETE/rootcheck
* In response, `data` key is now moved to new `message` key

### PUT/rootcheck/:agent_id
* In response, `data` key is now moved to new `message` key

### DELETE/rootcheck/:agent_id
* In response, `data` key is now moved to new `message` key

### GET/rules/files
* Parameter **download** removed

### GET/rules/files/:file/download
* This endpoint provides the functionality of GET /rules/files with the old removed **download** param 

## Syscheck
### PUT/syscheck
* In response, `data` key is now moved to new `message` key

### PUT/syscheck/{agent_id}
* In response, `data` key is now moved to new `message` key

### DELETE/syscheck/{agent_id}
* In response, `data` key is now moved to new `message` key

## Syscollectior
### /syscollector/:agent_id/netaddr
* Added **agent_id** parameter.

### /syscollector/:agent_id/netiface
* Added **agent_id** parameter.

## Version
### GET /version 
* Removed endpoint