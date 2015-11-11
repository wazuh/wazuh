# OSSEC Wazuh RESTful API

OSSEC RESTful API is a service to control OSSEC Manager using REST requests. RESTful petitions will allow you to execute OSSEC commands like agents management (add, restart, info, key export) or rootcheck and syscheck information (restart, check last scan...)

## OSSEC Wazuh API RESTful Capatibilites

* Agent full list
* Agent status, rootcheck and syscheck info.
* Restart agent
* Add agent
* Get agent key
* SSL Certificates
* HTTPS Secure
* Authentication capabilites


## Goal

The goal is pretty simple, stop using the command line to manage OSSEC. What if you could manage OSSEC just with some URL's in your browser? What if OSSEC could have different privilegies levels depending of what command is executed? What if you could deploy thousand of OSSEC agents just calling a POST request?

We are currently working on it and with the open source community we will create a magnific OSSEC API.

## Documentation

* Full documentation and install guide at [documentation.wazuh.com](http://documentation.wazuh.com/en/latest/installing_ossec_api.html)


## Example requests

**/agents/sysrootcheck/restart**

Restart syscheck and rootcheck on all agents

**/agents**

List all agents info

**/agents/:agent_id**

Display agent info

**/agents/:agent_id/restart**

Restart agents

**/agents/:agent_id/sysrootcheck/restart**

Restart syscheck and rootcheck on one agent

**/agents/:agent_id/key**

Get Agent Key

**/agents/add/:agent_name**

Add agent.
