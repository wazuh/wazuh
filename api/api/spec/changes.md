## General
* Changed parameter **status** type *string* to *array*
* Date type use a standard format ISO-8601 defined by date-time format.
* Changed parameter **agent_id** type *integer* to *string* with minLength=3
* Changed all return parameters **agent_id** type *integer* to *string*
* Deleted all return parameters **path**, new API don't show any absolute path in responses.

## Active Response
### /active-response/:agent_id
* Parameters **command**, **Custom** and **Arguments** must be in body.
* **command** description changed.

## Agents


### DELETE /agents
* Parameter **ids** must be in query, not in body because DELETE operations can't have a requestBody in OpenAPI 3
* Parameter **status** renamed to **agent_status**

### GET /agents
* Parameter **status** renamed to **agent_status**

### GET /agents/groups/{group_id}
* Parameter **status** renamed to **agent_status**

### POST /agents
* Changed parameter **force** name to **force_time**

### DELETE /agents/:agent_id
* Error: parameter **purge** type must be *boolean*, not *string*

### DELETE /agents/group/:group_id
* Parameter **agent_id** must be in query, not in body because DELETE operations can't have a requestBody in OpenAPI 3
* Changed parameter **agent_id** name to **list_agents**

### DELETE /agents/groups
* Changed parameter **ids** name to **list_groups**
* Changed request parameters **ids** and **failed_ids** to **affected_groups** and **failed_groups**

### POST/agents/insert
* `force` parameter set to boolean.

## Cache
### DELETE /cache (Clear group cache)
* Changed path to **/cache/:group_id** because this path is used in other endpoint.

### GET /lists
* Parameter **status** renamed to **list_status**

## Manager/Cluster
### GET/manager/info
* Parameter `openssl_support` is now a boolean.

### GET/manager/stats/weekly
* Parameter **hours** changed to **averages**.

## Experimental
### General
* Changed **ram_free**, **ram_total**, **cpu_cores** type to integer and **cpu_mhz** type to number float
* Deleded all parameters **agent_id** from all endpoints

### /experimental/syscollector/netiface
* Changed **mtu**, **tx_packets**, **rx_packets**, **tx_bytes**, **rx_bytes**, **tx_errors**, **rx_errors**, **tx_dropped** and **rx_dropped** parameters to type integer.

### /experimental/syscollector/processes
* Parameter **pid** renamed to **process_pid**
* Parameter **status** renamed to **process_status**
* Parameter **name** renamed to **process_name**

## Syscollectior
### /syscollector/:agent_id/netaddr
* Added **agent_id** parameter.

### /syscollector/:agent_id/netiface
* Added **agent_id** parameter.
