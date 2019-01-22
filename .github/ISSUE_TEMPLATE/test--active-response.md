---
name: 'Test: Active response'
about: Test suite for Active response

---

# Testing: Active response

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Active response

- [ ] Insert 2 times same config
- [ ] Test active-response from wrong SO
- [ ] Test active-response from correct SO
- [ ] Check that the execution of the active response respects the location
- [ ] Specifies more than one agent_id
- [ ] Check level filter
- [ ] Check rules_group filter
- [ ] Check rules_id filter
- [ ] Check the period of the reverse command (timeout option)
- [ ] Check incremental timeouts (repeated_offenders)
- [ ] Check the exec daemon runs when active-response is disabled.

## Command

- [ ] Insert 2 times same config
- [ ] Configure a command that does not exist
- [ ] Same command for multiple active-response
- [ ] Check that the extra_args option works for any field
- [ ] Check that the expect option works for any field
- [ ] Verify that the return command can be enabled and disabled (timeout_allowed)
- [ ] Set the command below the active response that uses it
- [ ] Test firewall-drop command


## agent_control

- [ ] Send an active-response to an agent using agent_control

## Custom A-R

- [ ] Test custom active-response explained at https://github.com/wazuh/wazuh/issues/1116
