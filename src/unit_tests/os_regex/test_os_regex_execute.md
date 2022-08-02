# os_regex_execute tests framework

The `test suites` set of **os_regex_execute** is defined in [test_os_regex_execute.json](test_os_regex_execute.json) as an array as follows:

```json
[
    test_suite_1,
    test_suite_2,
    .
    .
    .
    test_suite_n
]
```

Each `test suite` uses a [regex_matching](https://github.com/wazuh/wazuh/blob/v4.3.5/src/os_regex/os_regex.h#L45-L49) structure, which is initially empty and is shared between its `unit tests`, allowing to test the memory usage. These suites are JSON objects with the following structure:

```json
{
  "description": "Here it should be explained what is the functionality or use case that is being tested.",
  "batch_test": [
           UT_1,
           UT_2,
           .
           .
           .
           UT_m
  ]
}
```

Where `batch_test` contains a `unit tests` array grouped by functionality.
The `unit tests` are also JSON objects that have a format similar to the following one:
```json
{
  "description": "Optional description of the unit test",
  "skip_test": false,
  "ignore_result": false,
  "debug": false,
  "pattern": "^Some pattern in a (\\w+) ",
  "log": "Some pattern in a Wazuh log.",
  "end_match": " log.",
  "captured_groups": [
    "Wazuh"
  ]
}
```

Where:
- `description` (string/optional): Unit test description.
- `skip_test` (bool/optional): If true, the test is skipped. This allows developing tests that should work but are not, until fixed, given known buggy cases. This option is used in tests that produce segmentation faults or conditions that abort the tests and can not be handled.
- `ignore_result` (bool/optional): If true, the test is executed but if it fails then such failures are ignored. This allows having tests for known buggy cases but prevents them to fail. This option is used in tests that fail but still can be bypassed.
- `debug` (bool/optional): If true, it prints a verbose description of the errors.
- `pattern` (string) : OS Regex pattern.
- `log` (string): Log to be analyzed.
- `end_match` (string): When the regex matches, it should return a pointer to the last matched character. This parameter would be the string that is conformed starting from this character to the end of the log.
- `captured_groups`: An array with the expected capture groups.
