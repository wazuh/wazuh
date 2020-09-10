## General
* Changed DELETE endpoints of some resources so if nothing is specified, nothing is removed. If the user wants to remove all of the resources, he can specify it with the "all" keyword.
* Date type use a standard format ISO-8601 defined by date-time format.
* Deleted all return parameters **path**, new API don't show any absolute path in responses.
* Changed search negation from `!` to `-`.
* Changed nested fields from `a_b` to `a.b`
* Changed parameter **query** to allow reserved characters.
* The endpoint's responses has been changed accordingly to the new RBAC standard. See spec schema responses carefully.
* The responses no longer will have `items` and `totalitems` fields, instead most responses will have the following structure:
```
{
  "data": {
    "affected_items": [],
    "total_affected_items": 0,
    "total_failed_items": 0,
    "failed_items": [],
    "message": ""
  }
}
```
* Errors follow the generic error format and are shown in `dapi_errors` key

## Default
### GET     /
* New endpoint. Returns basic information about the API.

## Active Response
### PUT     /active-response
* New endpoint. Run commands in all agents by default. 
* Use **list_agents** parameter in query to specify which agents must run the command.

### PUT     /active-response/{agent_id}
* Endpoint removed. Use `PUT /active-response?list_agents=agent_id` instead.

## Agents
### DELETE  /agents
* Nothing removed by default, it must be specified with the "all" keyword.
* Removed **ids** query parameter. Use **list_agents** instead.
* Added **list_agents** parameter in query used to specify which agents must be deleted. 
* If no **list_agents** is provided in query all agents will be removed.

### DELETE  /agents/{agent_id}
* Endpoint removed. Use `DELETE /agents?list_agents=agent_id` instead

### DELETE  /agents/{agent_id}/group
* Added **list_groups** parameter in query to specify an array of group IDs to remove from the agent.
* Removes the agent from all groups by default or a list of them if **list_groups** parameter is found.	

### DELETE  /agents/group
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Remove all agents assignment or a list of them from the specified group.
* Use `group_id` parameter in query to specify the group.

### DELETE  /agents/group/{group_id}
* Endpoint removed. Use `DELETE /agents/group?group_id=id` instead.

### DELETE  /agents/groups
* Endpoint removed. Use `DELETE /groups` instead.

### DELETE  /agents/groups/{group_id}
* Endpoint removed. Use `DELETE /groups?list_groups=group_id` instead.

### GET     /agents
* Return information about all available agents or a list of them.
* Added parameter **list_agents** in query used to specify a list of agent IDs (separated by comma) from which agents get the information.
* Added parameter **registerIP** in query used to filter by the IP used when registering the agent.
* With this new endpoint, you won't get a 400 response if agent name cannot be found,
you will get a 200 response with 0 items in the result.

### GET     /agents/{agent_id}
* Endpoint removed. Use `GET /agents?list_agents=agent_id` instead.

### GET     /agents/groups
* Endpoint removed. Use `GET /groups` instead.

### GET     /agents/groups/{group_id}
* Endpoint removed. Use `GET /groups?list_groups=group_id` instead.
To get all agents in a group use `GET /groups/{group_id}/agents`.

### GET     /agents/groups/{group_id}/configuration
* Endpoint removed. Use `GET /groups/{group_id}/configuration` instead.

### GET     /agents/groups/{group_id}/files
* Endpoint removed. Use `GET /groups/{group_id}/files` instead.

### GET     /agents/groups/{group_id}/files/{file_name}
* Endpoint removed. Use `GET /groups/{group_id}/files/{filename}/json` or 
`GET /groups/{group_id}/files/{filename}/xml` instead.

### GET     /agents/name/{agent_name}
* Endpoint removed. Use `GET /agents?name=agent_name` instead.

### GET     /agents/outdated
* Added **search** parameter in query used to look for elements with the specified string.

### GET     /agents/summary
* Endpoint removed. Use `GET /agents/summary/status` instead.

### GET     /agents/summary/os
* Removed **offset** parameter.
* Removed **limit** parameter.
* Removed **sort** parameter.
* Removed **search** parameter.
* Removed **q** parameter.

### GET     /agents/summary/status
* New endpoint. Returns a summary of the status of available agents.

### POST    /agents
* Renamed **force** parameter in request body to **force_time**.

### POST    /agents/{agent_name}
* Endpoint removed. Use `POST /agents/insert/quick` instead.

### POST    /agents/group/{group_id}
* Endpoint removed. Use `PUT /agents/group` instead.

### POST    /agents/groups/{group_id}/configuration
* Endpoint removed. Use `PUT /groups/{group_id}/configuration` instead.

### POST    /agents/groups/{group_id}/files/{file_name}
* Endpoint removed. Use `PUT /groups/{group_id}/configuration` instead.

### POST    /agents/insert
* Renamed **force** parameter in request body to **force_time**.

### POST    /agents/insert/quick
* New endpoint. Adds a new agent with the name specified by **agent_name** parameter.
This agent will use **any** as IP.

### POST    /agents/restart
* Endpoint removed. Use `PUT /agents/restart` instead.

### PUT     /agents/{agent_id}/upgrade
* Changed parameter type **force** in request body from integer to boolean.

### PUT     /agents/{agent_name}
* Endpoint removed. Use `POST /agents/insert/quick?agent_name=name`.

### PUT     /agents/group
* New endpoint. Assign all agents or a list of them to the specified group.

### PUT     /agents/groups/{group_id}
* Endpoint removed. Use `POST /groups?group_id=group_id` instead.

### PUT     /agents/groups/{group_id}/configuration
* Endpoint removed. Use `PUT /groups/{group_id}/configuration` instead.

### PUT     /agents/groups/{group_id}/files/{file_name}
* Endpoint removed. Use `PUT /groups/{group_id}/files/{file_name}` instead.

### PUT     /agents/groups/{group_id}/restart
* Endpoint removed. Use `PUT /agents/group/{group_id}/restart` instead.

### PUT     /agents/restart
* Added **list_agents** parameter in query to specify which agents must be restarted.
* Restarts all agents by default or a list of them if **list_agents** parameter is used.

### PUT     /agents/node/{node_id}/restart
* New endpoint. Restart all agents belonging to a node.

## Cache
### DELETE  /cache 
### GET     /cache 
### DELETE  /cache{group} (Clear group cache)
### GET     /cache/config 
* All cache endpoints have been removed.

## Cluster
### DELETE  /cluster/api/config
* New endpoint. Restore default API configuration.

### GET     /cluster/api/config
* New endpoint. Returns the API configuration in JSON format.

### GET     /cluster/config
* Endpoint removed. Use `GET /cluster/local/config` instead.

### GET     /cluster/configuration/validation
* Added **list_nodes** parameter in query.
* Return whether the Wazuh configuration is correct or not in all cluster nodes 
or a list of them if parameter **list_nodes** is used.

### GET     /cluster/healthcheck
* Renamed **node** parameter in query to **list_nodes**.

### GET     /cluster/local/config
* New endpoint. Get local node cluster configuration

### GET     /cluster/local/info
* New endpoint. Get information about the local node.

### GET     /cluster/node
* Endpoint removed. Use `GET /cluster/nodes?list_agents=agent_id` instead.

### GET     /cluster/{node_id}/configuration/validation
* Endpoint removed. Use `GET /cluster/configuration/validation?list_nodes=node_id` instead.

### GET     /cluster/{node_id}/files
* Removed **validation** parameter in query. Use `GET /cluster/configuration/validation?list_nodes=node_id` instead.

### GET ​   /cluster/{node_id}/logs
* Renamed **category** parameter to **tag**.
* Renamed **type_log** parameter to **level**.

### GET     /cluster/{node_id}/stats
* Changed response in order to use an affected_items and failed_items response type.
* Changed date format from YYYYMMDD to YYYY-MM-DD for **date** parameter in query.

### GET ​   /cluster/{node_id}/stats/hourly
* Changed response in order to use an affected_items and failed_items response type.

### GET ​   /cluster/{node_id}/stats/weekly
* Changed response in order to use an affected_items and failed_items response type.
* Parameter **hours** changed to **averages** in response body.

### GET ​   /cluster/{node_id}/stats/analysisd
* Changed response in order to use an affected_items and failed_items response type.

### GET ​   /cluster/{node_id}/stats/remoted
* Changed response in order to use an affected_items and failed_items response type.

### GET     /cluster/nodes
* Get information about all nodes in the cluster or a list of them
* Added **list_nodes** parameter in query used to specify from which nodes get the information.

### GET     /cluster/nodes/{node_name}
* Endpoint removed. Use `GET /cluster/nodes?list_nodes=node_id` instead.

### POST    /cluster/{node_id}/files
* Endpoint removed. Use `PUT /cluster/{node_id}/files` instead.

### PUT     /cluster/api/config
* New endpoint. Updates API configuration with the data contained in the API request.

### PUT     /cluster/{node_id}/files
* New endpoint. Replaces file contents with the data contained in the API request in a specified cluster node.

### PUT     /cluster/{node_id}/restart
* Endpoint removed. Use `PUT /cluster/restart?list_nodes=node_id` instead.

### PUT     /cluster/restart
* Added **list_nodes** parameter in query 
* Restarts all nodes in the cluster by default or a list of them if **list_nodes** is found.

## Decoders
### GET     /decoders
* Added **select** parameter.
* Added **decoder_name** parameter in query used to specify a list of decoder's names to get.
* Renamed **file** parameter in query to **filename**.
* Renamed **path** parameter in query to **relative_dirname**.
* The response has been changed to the new RBAC generic response.

### GET     /decoders/parents
* Added **select** parameter.

### GET     /decoders/{decoder_name}
* Endpoint removed. Use `GET /decoders?decoder_name=name` instead.

### GET     /decoders/files
* Removed **download** parameter. Use `GET /decoders/files/{filename}/download` instead.
* Renamed **file** parameter in query to **filename**.
* Renamed **path** parameter in query to **relative_dirname**.
* The response has been changed to the new RBAC generic response.

### GET     /decoders/files/{filename}/download
* New endpoint. Download an specified decoder file.
* The response has been changed to the new RBAC generic response. 

## Experimental
### General
* Added **list_agents** parameter in query to all experimental endpoints.
* Removed **agent_id** parameter from all endpoints.

### GET ​   /experimental/ciscat/results
* Removed **agent_id** parameter in query.

### GET     /experimental/syscollector/hardware
* Renamed **ram_free** parameter in query to **ram.free** and changed it's type to integer.
* Renamed **ram_total** parameter in query to **ram.total** and changed it's type to integer.
* Renamed **cpu_cores** parameter in query to **cpu.cores** and changed it's type to integer.
* Renamed **cpu_mhz** parameter in query to **cpu.mhz** and changed it's type to number.
* Renamed **cpu_name**  parameter in query to **cpu.name**.

### GET ​   /experimental/syscollector/hotfixes
* New endpoint. Get the hotfixes info of all agents or a list of agents.

### GET     /experimental/syscollector/netiface
* Changed the type of **mtu** parameter to integer.
* Renamed **tx_packets** parameter in query to **tx.packets** and changed it's type to integer.
* Renamed **rx_packets** parameter in query to **rx.packets** and changed it's type to integer.
* Renamed **tx_bytes** parameter in query to **tx.bytes** and changed it's type to integer.
* Renamed **rx_bytes** parameter in query to **rx.bytes** and changed it's type to integer.
* Renamed **tx_errors** parameter in query to **tx.errors** and changed it's type to integer.
* Renamed **rx_errors** parameter in query to **rx.errors** and changed it's type to integer.
* Renamed **tx_dropped** parameter in query to **tx.dropped**  and changed it's type to integer.
* Renamed **rx_dropped** parameter in query to **rx.dropped** and changed it's type to integer.

### GET ​   /experimental/syscollector/os
* Renamed **os_name** parameter in query to **os.name**.
* Renamed **os_version** parameter in query to **os.version**.

### GET     /experimental/syscollector/ports
* Renamed **local_ip** parameter to **local.ip**.
* Renamed **local_port** parameter to **local.port**.
* Renamed **remote_ip**  parameter to **remote.ip**. 

### DELETE /experimental/syscheck
* Nothing removed by default, it must be specified with the "all" keyword.

## Groups
### DELETE ​/groups
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Deletes all groups or a list of them.

### GET ​   /groups
* New endpoint. Get information about all groups or a list of them. 
Returns a list containing basic information about each group such as number of agents belonging 
to the group and the checksums of the configuration and shared files.
* Removed **q** parameter in query.

### GET ​   /groups/{group_id}/agents
* New endpoint. Returns the list of agents that belongs to the specified group.

### GET ​   /groups/{group_id}/configuration
* New endpoint. Returns the group configuration defined in the agent.conf file.

### GET ​   /groups/{group_id}/files
* New endpoint. Return the files placed under the group directory.

### GET ​   /groups/{group_id}/files/{file_name}/json
* New endpoint. Returns the contents of the specified group file parsed to JSON.

### GET ​   /groups/{group_id}/files/{file_name}/xml
* New endpoint. Returns the contents of the specified group file parsed to XML.

### POST ​  /groups
* New endpoint. Creates a new group.

### PUT ​   /groups/{group_id}/configuration
* New endpoint. Update an specified group's configuration. 
This API call expects a full valid XML file with the shared configuration tags/syntax.

## Lists
### GET     /lists
* Added **select** parameter.
* Added **filename** parameter in query used to filter by filename.
* Renamed **path** parameter in query to **relative_dirname**.

### GET     /lists/files 
* Added **filename** parameter in query used to filter by filename.
* added **relative_dirname** parameter in query used to filter by relative directory name.

## Manager
### DELETE ​/manager/api/config
* New endpoint. Replaces API configuration with the original one.

### GET ​   /manager/api/config
* New endpoint. Returns the API configuration in JSON format.

### GET     /manager/files
* Removed **validation** parameter in query. Use `GET /manager/configuration/validation` instead.

### GET     /manager/info
* Parameter `openssl_support` in response is now a boolean.

### GET ​   /manager/logs
* Renamed **category** parameter to **tag**.
* Renamed **type_log** parameter to **level**.

### GET ​   /manager/logs/summary
* Return a summary of the last 2000 wazuh log entries instead of the last three months.

### GET     /manager/stats
* Changed response in order to use an affected_items and failed_items response type.
* Changed date format from YYYYMMDD to YYYY-MM-DD for **date** parameter in query.

### GET     /manager/stats/hourly
* Changed response in order to use an affected_items and failed_items response type.

### GET     /manager/stats/weekly
* Changed response in order to use an affected_items and failed_items response type.
* Parameter **hours** changed to **averages** in response body.

### GET     /manager/stats/analysisd
* Changed response in order to use an affected_items and failed_items response type.

### GET     /manager/stats/remoted
* Changed response in order to use an affected_items and failed_items response type.

### POST    /manager/files
* Endpoint removed. Use `PUT /manager/files` instead.

### PUT ​   /manager/api/config
* New endpoint. Updates API configuration with the data contained in the API request.

### PUT     /manager/files
* New endpoint. Replaces file contents with the data contained in the API request.

## Overview
### GET     /overview/agents
* New endpoint. Returns a dictionary with a full agents overview.

## Rootcheck
* Removed all rootcheck endpoints.

## Rules
### GET     /rules
* Added **rule_ids** parameter in query.
* Added **select** parameter.
* Renamed **file** parameter to **filename**.
* Renamed **pci** parameter in query to **pci_dss**.

### GET     /rules/gdpr
* Endpoint removed. Use `GET /rules/requirement/gdpr` instead.

### GET     /rules/gpg13
* Endpoint removed. Use `GET /rules/requirement/gpg13` instead.

### GET     /rules/files
* Renamed **path** parameter in query to **relative_dirname**.
* Renamed **file** parameter in query to **filename**.
* Removed **download** parameter in query. Use `GET /rules/files/{file}/download` instead.

### GET     /rules/files/{file}/download
* New endpoint. Download an specified rule file.

### GET     /rules/hipaa
* Endpoint removed. Use `GET /rules/requirement/hipaa` instead.

### GET     /rules/nist-800-53
* Endpoint removed. Use `GET /rules/requirement/nist-800-53` instead.

### GET     /rules/pci
* Endpoint removed. Use `GET /rules/requirement/pci_dss` instead.

### GET     /rules/requirement/{requirement}
* New endpoint. Returns all specified requirement names defined in the Wazuh ruleset.

### GET     /rules/{rule_id}
* Endpoint removed. Use `GET /rules?rule_ids=rule_id` instead.

## Security
* These endpoints provide the functionality of RBAC and authentication.

### GET ​   /security/actions
* New endpoint. Get all RBAC actions.

### GET     /security/policies
* New endpoint. Get all policies in the system.

### POST    /security/policies
* New endpoint. Add a new policy.

### DELETE  /security/policies
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete a list of policies or all policies in the system.

### PUT     /security/policies/{policy_id}
* New endpoint. Modify a specified policy.

### GET ​   /security/resources
* New endpoint. Get RBAC resources.

### GET     /security/roles
* New endpoint. Gets a list of roles or all roles in the system without specifying anything.

### POST    /security/roles
* New endpoint. Add a new role to the system.

### DELETE  /security/roles
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete a list of roles or all roles in the system.

### PUT     /security/roles/{role_id}
* New endpoint. Modify a specified role.

### GET     /security/rules
* New endpoint. Get a list of security rules or all rules in the system if no ids are specified.

### POST    /security/rules
* New endpoint. Add a new security rule to the system.

### DELETE  /security/rules
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete a list of security rules or all rules in the system.

### PUT     /security/rules/{rule_id}
* New endpoint. Modify a specified security rule.

### POST ​  /security/roles/{role_id}/policies
* New endpoint. Create a relation between one role and one or more policies.

### DELETE ​/security/roles/{role_id}/policies
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete a specify relation role-policy.

### POST ​  /security/roles/{role_id}/rules
* New endpoint. Create a relation between one role and one or more security rules.

### DELETE ​/security/roles/{role_id}/rules
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete a specific role-rule relation.

### GET     /security/user/authenticate
* New endpoint. User/password authentication to get an access token.

### POST    /security/user/authenticate/run_as
* New endpoint. Auth_context based authentication to get an access token.

### PUT ​   /security/user/revoke
* New endpoint. Revoke all active JWT tokens.

### GET ​   /security/users
* New endpoint. Get user information.

### POST ​  /security/users
* New endpoint. Create new user.

### DELETE ​/security/users
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete an user.

### PUT ​   /security/users/{username}
* New endpoint. Modify a user.

### POST    /security/users/{username}/roles
* New endpoint. Create a specify relation between one user and one role.

### DELETE  /security/users/{username}/roles
* Nothing removed by default, it must be specified with the "all" keyword.
* New endpoint. Delete a specify relation user-roles.

## Summary
### GET     /summary/agents
* Endpoint removed. Use the new `GET /overview/agents` endpoint instead.

## Syscheck
### PUT     /syscheck
* Added **list_agents** parameter in query used to specify which agents must perform a syscheck scan.

### PUT     /syscheck/{agent_id}
* Endpoint removed. Use `PUT /syscheck?list_agents=agent_id` instead.

## Syscollector
### GET     /syscollector/{agent_id}/netiface
* Changed the type of **mtu** parameter to integer.
* Renamed **tx_packets** parameter in query to **tx.packets** and changed it's type to integer.
* Renamed **rx_packets** parameter in query to **rx.packets** and changed it's type to integer.
* Renamed **tx_bytes** parameter in query to **tx.bytes** and changed it's type to integer.
* Renamed **rx_bytes** parameter in query to **rx.bytes** and changed it's type to integer.
* Renamed **tx_errors** parameter in query to **tx.errors** and changed it's type to integer.
* Renamed **rx_errors** parameter in query to **rx.errors** and changed it's type to integer.
* Renamed **tx_dropped** parameter in query to **tx.dropped**  and changed it's type to integer.
* Renamed **rx_dropped** parameter in query to **rx.dropped** and changed it's type to integer.

### GET     /syscollector/{agent_id}/ports
* Added **process** parameter used to filter by process name.
* Renamed **local_ip** parameter to **local.ip**.
* Renamed **local_port** parameter to **local.port**.
* Renamed **remote_ip**  parameter to **remote.ip**. 
 
## Version
### GET     /version 
* Endpoint removed. Use `GET /` instead.
