---
name: 'Test: Agent key polling'
about: Test suite for key polling.

---

# Agent key polling test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Configuration

- [ ] Configure and enable the agent key polling module. (1) 
- [ ] Set up a MySQL Database with a table named "agent" and the fields required in the JSON output. (2) 
- [ ] Copy the Python script found at (2).
- [ ] Adjust the script path <exec_path> in you ossec.conf file.

## Test

- [ ] Make sure Authd daemon is running.
- [ ] Register an agent and connect it to the manager.
- [ ] Insert the client.keys line for the agent into our database required fields.
- [ ] Delete the agent from the manager (You should see the message _Message from 'xxx.yyy.zzz.www' not allowed._).
- [ ] The agent should be registered again by the module (check the client.keys file).

(1) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/wodle-key-polling.html
(2) https://documentation.wazuh.com/3.x/user-manual/capabilities/key-polling.html
