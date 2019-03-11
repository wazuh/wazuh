## General
* Changed parameter **status** type *string* to *array*

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

### GET /lists
* Parameter **status** renamed to **list_status**
