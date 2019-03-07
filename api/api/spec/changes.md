## General
* Changed parameter **status** type *string* to *array*

## Active Response
### /active-response/:agent_id
* Parameters **command**, **Custom** and **Arguments** must be in body.
* **command** description changed.

## Agents
### DELETE /agents
* Parameter **ids** must be in query, not in body because DELETE operations can't have a requestBody in OpenAPI 3

### POST /agents
* Changed parameter **force** name to **force_time**

### DELETE /agents/:agent_id
* Error: parameter **purge** type must be *boolean*, not *string*

### DELETE /agents/group/:group_id
* Parameter **agent_id** must be in query, not in body because DELETE operations can't have a requestBody in OpenAPI 3
* Changed parameter **agent_id** name to **list_agents**

### DELETE /agents/groups
* Changed parameter **ids** name to **list_groups**

##Experimental

### GET /experimental/ciscat/results
* Changed path to **/experimental/ciscat/:agent_id/results** because parameter **agent_id** must be on path, it's more correct.
* Response mustn't show agent_id information if we use the previous change.

### GET /experimental/syscollector/hardware
* If summary say that the endpoint return hardware info of **all agents** the parameter **agent_id** isn't necessary
* Parameters **ram_free**, **ram_total**, **cpu_cores**, **cpu_mhz**
