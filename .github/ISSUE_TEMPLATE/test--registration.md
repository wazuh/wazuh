---
name: 'Test: Registration'
about: Test suite for agent registration.

---

# Registration test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Auth system

- [ ] Check the auth daemon is running by default. (Since v3.8.0)
- [ ] Check registration with `-m`.
- [ ] Check registration with `-m` and `-A`.
- [ ] Test force insertion to re-register an agent. (1)
- [ ] Check client keys on manager and agent are equal.
- [ ] Check registration with `-m wrong-IP`. **Must fail.**
- [ ] Assign agent to an existing group.
- [ ] Get a descriptive error when trying to assign an agent to an non-existing group.
- [ ] Set the agent IP manually by the `-I` option.
- [ ] Enable the "use source IP" feature by the `-i` option.
- [ ] Mix incompatible options like `-I <IP>` and `-i` to see the error retrieved.
- [ ] Register an agent using on Windows with `agent_auth`.

(1) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/auth.html#force-insert

### Secure methods

- [ ] Register an agent using a password. (2)
- [ ] Register an agent using SSL. (2)

(2) https://documentation.wazuh.com/3.x/user-manual/registering/use-registration-service.html#secure-methods

## Tool _manage_agents_

- [ ] Check same test as using Authd. (3)
- [ ] Use -F option to remove duplicated agents. (3)

(3) https://documentation.wazuh.com/3.x/user-manual/reference/tools/manage_agents.html
