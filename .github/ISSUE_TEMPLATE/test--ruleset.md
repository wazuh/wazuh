---
name: 'Test: Ruleset'
about: Test suite for the ruleset.

---

# Ruleset test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Analysisd performance

- [ ] Check the manager starts with an empty `ossec.conf`.
- [ ] Change the number of threads used by analysisd in the internal options. Check the performance at `var/run/ossec-analysisd.state` depending on the threads.
- [ ] Change the value of the queues size of analysisd. Check its behavior when flooded.
- [ ] Check the refresh interval of `ossec-analysisd.state` matches with the defined `analysisd.state_interval` at internal options.
- [ ] Check every file is written correctly when enabling/disabling `alerts_log`, `jsonout_output`, `logall` and `logall_json` options.

## Ruleset

- [ ] Trigger alerts which depend on `frequency`, `timeframe`, `ignore`.
- [ ] Trigger alerts which depend on `if_matched_sid`, `if_matched_group`, `same_source_ip`, etc.
- [ ] Trigger a custom decoder and rule set at `etc/decoders`/`etc/rules`.
- [ ] Overwrite a rule.
- [ ] Make the manager fails when starting by setting a duplicated rule ID, as well as other invalid fields.
- [ ] Decode static and dynamic fields and use them into a rule.
- [ ] Trigger a rule depending on a CDB list.
- [ ] Trigger an alert by using `ossec-logtest`.

https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

## Ruleset unit tests

- [ ] Run unit tests.

## *update_ruleset*

- [ ] Check *major.minor.x*.
- [ ] From specific branch.
- [ ] Every argument.
