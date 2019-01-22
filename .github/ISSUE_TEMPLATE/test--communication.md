---
name: 'Test: Communication'
about: Test suite for host communication.

---

# Communication test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Manager - agent

- [ ] Connect an agent by UDP successfully  and verify alerts and services work properly. (1)
- [ ] Connect an agent by TCP successfully and verify alerts and services work properly. (1)
- [ ] Connect an agent with a different port. (1)
- [ ] Agent re-connects succesfully after a manager recovery.
- [ ] Test both crypto methods available (AES and blowfish).
- [ ] Configure several managers to an agent, check if it works. (1)
- [ ] Test large messages (up to 64K) (3).
- [ ] Test large labels (up to 20K).
- [ ] Connect to a manager by resolving its domain with DNS. (1)
- [ ] Use legacy configuration (server-ip, server-hostname, protocol, port).
- [ ] Check statistics files for analysisd, remoted and agentd.

(1) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/client.html
(3) You have to write the alert in a monitorized log, for example: **active-response.log**

## Syslog events

Send syslog events from an agent to the manager (UDP/TCP). (2)
Deny the IP of an agent and check that is not allowed to send events. (2)
Specify a local_ip in the manager for receive syslog events. (2)

(2) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/remote.html
