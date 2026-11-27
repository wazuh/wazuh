# Data Provider Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-use-the-tool)

## Purpose
The Data Provider Testing Tool was created to test and validate the data obtained by the module's execution. This tool works as a black box where an user will be able execute it and analyze the output data as desired.

## Compile Wazuh
The data provider is built only with an agent target, in release or debug mode:
```
make TARGET=agent|winagent <DEBUG=1>
```

## How to use the tool
The `sysinfo_test_tool` binary is written to the `src/build/bin` folder.
```
Usage: sysinfo_test_tool [options]
```

It prints one indented JSON object whose keys are the categories collected: `hw`, `networks`, `os`, `packages`, `processes`, `ports`, `hotfixes`, `users`, `groups`, `services` and `browser_extensions` without arguments, or the one key of the option given (`packages_cb` and `processes_cb` for the callback options). The values are the raw data provider fields, before Syscollector maps them to the event fields.

The information output will vary based on the Operating System the tool is being executed.

### Optional arguments:

Only one option is accepted. An unknown option, or more than one, prints `Error getting system information: ` followed by the reason, then the usage text.

|Argument|Description|
|---|---|
| `--hardware`     			| Prints the current Operating System hardware information only. Example: `sysinfo_test_tool --hardware`                               |
| `--networks`     			| Prints the current Operating System networks information only. Example: `sysinfo_test_tool --networks`                               |
| `--packages`     			| Prints the current Operating System packages information only. Example: `sysinfo_test_tool --packages`                               |
| `--processes`    			| Prints the current Operating System processes information only. Example: `sysinfo_test_tool --processes`                             |
| `--packages-cb`  			| Prints the current Operating System packages information only with callbacks mechanism. Example: `sysinfo_test_tool --packages-cb`   |
| `--processes-cb` 			| Prints the current Operating System processes information only with callbacks mechanism. Example: `sysinfo_test_tool --processes-cb` |
| `--ports`        			| Prints the current Operating System ports information only. Example: `sysinfo_test_tool --ports`                                     |
| `--os`           			| Prints the current Operating System information only. Example: `sysinfo_test_tool --os`                                              |
| `--hotfixes`     			| Prints the current Operating System hotfixes information only. Example: `sysinfo_test_tool --hotfixes`                               |
| `--groups`       			| Prints the current Operating System groups information only. Example: `sysinfo_test_tool --groups`                                   |
| `--users`        			| Prints the current Operating System users information only. Example: `sysinfo_test_tool --users`                                     |
| `--services`     			| Prints the current Operating System services information only. Example: `sysinfo_test_tool --services`                               |
| `--browser-extensions`    | Prints the current Operating System browser extensions information only. Example: `sysinfo_test_tool --browser-extensions`                                     |
