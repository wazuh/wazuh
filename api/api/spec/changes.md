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

## Cache
### DELETE /cache (Clear group cache)
* Changed path to **/cache/:group_id** because this path is used in other endpoint.

### GET /lists
* Parameter **status** renamed to **list_status**

## Experimental
### General
* Changed ram_free, ram_total, cpu_cores type to integer and **cpu_mhz** type to number float
* Deleded all parameters **agent_id** from all endpoints
