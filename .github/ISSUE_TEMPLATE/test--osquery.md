---
name: 'Test: osquery'
about: Test suite for the integration with osquery.

---

# osquery test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## On Linux

- [ ] Enable / disable daemon.
- [ ] Check invalid configuration. The module should log a warning and continue.
- [ ] Pack file definitions.
- [ ] Pack folder definition: `<pack name="*">/usr/share/osquery/packs/*</pack>`.
- [ ] Enrich existing decorators with agent labels.
- [ ] Add labels, no previous decorators defined.
- [ ] Combine `<add_labels>` and `<pack>` options.
- [ ] Invalid permissions (owner) for *osqueryd* binary. It **should log an error and stop**.
- [ ] *osqueryd* already running when agent is started. It should log a message every minute.
- [ ] If it tries to start *osqueryd* before the previous dies on restart, t should reattempt to run one minute later.
- [ ] Try an Invalid path for `<log_path>` or unexisting log file. The module should reattempt up to one minute delay.
- [ ] Truncate results log (`echo -n > osquery.results.log`). The module should go back to the file begin, no data lost.
- [ ] Remove results log. The module should finish reading the current file and reload the new one, no data lost.
- [ ] Add query pack folder to a shared folder. That folder should appear in the agent.
- [ ] Agent labels with single quotes: `<label key="node">Node for 'nginx'</label>`. No SQL code injection.
- [ ] Insert C/C++ comments to JSON configuration. The module should be able to insert decorators and packs.
- [ ] Kill *osqueryd* while being run by the agent. The module should restart it only if it ran during 10 seconds at less.
- [ ] Unexisting folder */var/osquery*. The module **should report the error** and the manager should create an alert.
- [ ] Declaring osquery module multiple times (*ossec.conf* and another in *agent.conf*). Only the last one applies
- [ ] Unexisting configuration with `<add_labels>` disabled and no `<pack>`. The module should log it, wait 10 minutes and retry.

## On Windows

- [ ] Invalid permissions (owner) for *osqueryd* binary. It **should log an error and stop**.
- [ ] *osqueryd* already running when agent is started. It should log a message every minute.
- [ ] If it tries to start *osqueryd* before the previous dies on restart, t should reattempt to run one minute later.
- [ ] Truncate results log (`echo -n > osquery.results.log`). The module should go back to the file begin, no data lost.
- [ ] Remove *results log*. The module should finish reading the current file and reload the new one, no data lost.
- [ ] Add query pack folder to a shared folder. That folder should appear in the agent.
- [ ] Kill *osqueryd* while being run by the agent. The module should restart it only if it ran during 10 seconds at less.
