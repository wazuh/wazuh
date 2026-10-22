# Engine helper test

1. [End to end tests for helper functions](#end-to-end-tests-for-helper-functions)
1. [Directory structure](#directory-structure)
1. [Install](#install)
1. [Usage](#usage)
    1. [init](#init)
    1. [validate](#validate)
    1. [generate-tests](#generate-tests)
    1. [run](#run)
    1. [generate-doc](#generate-doc)
1. [Running all tests](#running-all-tests)
1. [How to write a test](#how-to-write-a-test)
    1. [Schema](#schema)
    2. [Arguments property](#arguments-property)
        1. [Types](#types)
        2. [Subsets](#subsets)
        3. [Source](#source)
        4. [Restrictions](#restrictions)
    3. [General restrictions property](#general-restrictions-property)
    4. [Target field property](#target-field-property)
    5. [Output property](#output-property)
    6. [Skipped property](#skipped-property)
    7. [Test property](#test-property)
1. [How generate helper functions documentation](#how-generate-helper-functions-documentation)
    1. [Generate documentation for a particular helper function](#generate-documentation-for-a-particular-helper-function)
    2. [Generate documentation for a particular type of helper function](#generate-documentation-for-a-particular-type-of-helper-function)
    3. [Generate documentation for all helper functions](#generate-documentation-for-all-helper-functions)


# End to end tests for helper functions
This tool automates the generation of test cases to verify the correct end-to-end operation of the helper functions used
in the assets. It uses YAML files to describe the parameters of helper functions and generates corresponding test cases.
The tool automatically generates test cases from these YAML files. Each test case includes:
- Asset containing the helper to test.
- Test entries (if there are references)
- Description detailing what is being tested.
- Expected result
- Test result

The same helper descriptions generate the published
[helper functions reference](../../../../docs/ref/modules/engine/ref-helper-functions.md) (see
[How generate helper functions documentation](#how-generate-helper-functions-documentation)).

CI runs `init`, `validate`, `generate-tests`, `run` and `generate-doc` in the `helper_tests` job of
[5_testintegration_engine.yml](../../../../.github/workflows/5_testintegration_engine.yml).

# Directory structure

```plaintext
helper_tests/
├── configuration_files
│   └── config.env           # Engine configuration copied into the environment by `init`
├── engine-helper-test       # The engine-helper-test Python package
├── helpers_description      # One YAML description per helper function
│   ├── filter
│   ├── map
│   └── transformation
├── mmdb
│   ├── testdb-asn.mmdb
│   └── testdb-city.mmdb
└── README.md
```

# Install

The `engine-helper-test` python package contains various scripts to help to create and run helper function tests.


Requires Python 3.8 or newer. It depends on `api-communication` and `engine-test-utils`, and imports
`engine-suite`'s shared settings; none of them is published, so install them first (see the
[test suite installation](../README.md#installation)). From `src/engine/`:

```bash
pip install test/helper_tests/engine-helper-test
```

To modify the scripts, install it in editable mode (`pip install -e test/helper_tests/engine-helper-test`).

# Usage
```bash
$ engine-helper-test -h
usage: engine-helper-test [-h] -e ENVIRONMENT {init,validate,generate-tests,run,generate-doc} ...

Utility to perform the helper test on the Engine

positional arguments:
  {init,validate,generate-tests,run,generate-doc}
    init                Update configuration, create kvdbs and mmdbs
    validate            Validates that the helper descriptions comply with the schema
    generate-tests      Generates files containing test cases for a given helper
    run                 Runs the generated test cases and validates their results
    generate-doc        Generates files containing documentation for a given helper

options:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Environment directory
```

## init

```bash
$ engine-helper-test init -h
usage: engine-helper-test init [-h] --mmdb MMDB --conf CONF

options:
  -h, --help   show this help message and exit
  --mmdb MMDB  Directory path where the as and geo databases are located
  --conf CONF  File path where the engine configuration file is
```

`init` copies the configuration file into `<environment>/config.env` (replacing the path placeholder with
the environment directory), seeds the enrichment and geo store documents, copies `testdb-asn.mmdb` and
`testdb-city.mmdb` into `<environment>/geo/`, creates the test KVDB, and starts and stops the engine binary
`<environment>/wazuh-engine` (placed there by `setupEnvironment.py`) once.

## validate

```bash
$ engine-helper-test validate -h
usage: engine-helper-test validate [-h] (--input-file INPUT_FILE | --input-dir INPUT_DIR)

options:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        Absolute or relative path where the description of the helper function is located
  --input-dir INPUT_DIR
                        Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located
```

## generate-tests

```bash
$ engine-helper-test generate-tests -h
usage: engine-helper-test generate-tests [-h] (--input-file INPUT_FILE | --input-dir INPUT_DIR) -o OUTPUT_PATH

options:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        Absolute or relative path where the description of the helper function is located
  --input-dir INPUT_DIR
                        Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located
  -o OUTPUT_PATH, --output-path OUTPUT_PATH
                        Absolute or relative path of the directory where the generated test files will be located
```

## run

```bash
$ engine-helper-test run -h
usage: engine-helper-test run [-h] (--input-file INPUT_FILE | --input-dir INPUT_DIR) [--show-failure]

options:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        Absolute or relative path to the test case file
  --input-dir INPUT_DIR
                        Absolute or relative path to the directory containing test case files
  --show-failure        Shows only the failure test cases that occurred
```

## generate-doc

```bash
$ engine-helper-test generate-doc -h
usage: engine-helper-test generate-doc [-h] (--input-file INPUT_FILE | --input-dir INPUT_DIR) [--exporter EXPORTER] -o OUTPUT_PATH

options:
  -h, --help            show this help message and exit
  --input-file INPUT_FILE
                        Absolute or relative path where the description of the helper function is located
  --input-dir INPUT_DIR
                        Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located
  --exporter EXPORTER   Absolute or relative path of the directory where the generated test files will be located
  -o OUTPUT_PATH, --output-path OUTPUT_PATH
                        Absolute or relative path of the directory where the generated documentation files will be located
```

# Running all tests

After completing the installation, run `setupEnvironment.py` to build the environment (it needs the
manager tree built: see the [test suite README](../README.md#environment-setup-script)).

```bash
cd src/engine
python3 test/setupEnvironment.py -e /tmp/environment
engine-helper-test -e /tmp/environment init --mmdb test/helper_tests/mmdb/ --conf test/helper_tests/configuration_files/config.env
engine-helper-test -e /tmp/environment validate --input-dir test/helper_tests/helpers_description/
engine-helper-test -e /tmp/environment generate-tests --input-dir test/helper_tests/helpers_description/ -o /tmp/helper_tests
engine-helper-test -e /tmp/environment run --input-dir /tmp/helper_tests
```

# How to write a test

## Schema

Each helper descriptor file is verified before the construction of the test cases to ensure that it contains exactly the format and information expected by the generator.
Below are the mandatory properties that the file should have:

- name: Details the name of the helper function that will be evaluated for the construction of the test cases.
- metadata: An object with a mandatory `description` and the `keywords` list (read by `generate-doc`).
- helper_type: It is only possible to set one of the types supported by the engine [map, filter, transformation]
- is_variadic: Indicates whether or not the helper function admits a number of variable arguments.
- output: Mandatory for `map` helpers (see [Output property](#output-property)).

Once the minimum necessary for the helper descriptor has been defined, optional properties can be added:

- arguments: Includes information about the helper arguments such as accepted types and allowed fonts, among other things.
- general_restrictions: This property is useful when there is some type of restriction between the values that the helper arguments can take.
- target_field: This property is useful for the filter and transformation type helpers. Allows you to set the specific type and subtype of the value that the target_field will have
- skipped: Allows you to ignore the results of a particular test suite (see [Skipped property](#skipped-property)).
- test: This property, in contrast to automatic tests that are generated based on the description of the arguments, allows you to generate a test with specific types and sources as long as it respects the information of each argument.

## Arguments property

accepts a list of objects. Each object has a key to identify the argument and a value, which is another object that describes information about the type, source, and whether there are any restrictions on the values the argument can take.

```yaml
arguments:
  argument_id:
    type: any_type
    generate: any_subset
    source: any_source
    restrictions:
      allowed:
        - any_value
  other_argument_id:
    type: any_type
    generate: any_subset
    source: any_source
```

### Types
- Supported types:
    - number
    - string
    - boolean
    - array
    - object

This can be indicated in the configuration with the *type* property. This property supports one or more types for each argument, in that case the *generate* property is no longer necessary.

### Subsets

In turn, each type admits a particular generator, it can be thought of as if it were the subset for each type described
- Subset type for number type:
    - integer
    - float
    - double
- Subset type for string type:
    - string
    - hexadecimal
    - ip
    - regex
- Subset type for boolean type:
    - boolean
- Subset type for array type:
    - integer
    - float
    - double
    - string
    - hexadecimal
    - ip
    - regex
    - boolean
- Subset type for object type:
    - object

This can be indicated in the configuration with the *generate* property. the generator must be consistent with the declared type.

Correct configuration:
```
type: number
generate: integer
```

Doing this is not possible:

```
type: number
generate: regex
```


### Source
This property allows you to set whether the argument accepts values, references or both.
- value
- reference
- both

### Restrictions
Define allowed or forbidden values for each argument. It is only possible to set one of the two. each supports a list of values.

```
restrictions:
    allowed:
    - testing
```

Doing this is not possible:

```
restrictions:
    allowed:
    - testing
    forbidden:
    - testing2
```

## General restrictions property

This property sets restrictions between the arguments.
This is the way to set this property.

```yaml
general_restrictions:
  - arguments:
      argument_id: some_value
      other_argument_id: some_value
    details: some restriction detail
```
Each key under `arguments` is the name of an argument defined in the `arguments` property (`validate` rejects
any other name). The value must correspond to the one indicated in the argument. The generator will do the
rest based on the information in the arguments property. A restriction may have only `details`.

## Target field property

This property is used for the filter and transformation type helpers. defines the type and corresponding subtype for the target_field.
```
target_field:
  type: array
  generate: string
```
It is also possible to establish a list of types, in that case the generate property is no longer necessary:
```
target_field:
  type:
    - number
    - string
    - object
    - boolean
    - array
```

## Output property

Describes the type of the value a `map` helper returns, with `type` (mandatory: one type or a list) and,
for a single type, its `subset`, which must be consistent with the type. `expected` values in `test`
entries must match it.

```yaml
output:
  type: number
  subset: integer
```

## Skipped property
With this property it is possible to ignore the results of the tests generated from the arguments. It supports a
list with the specific tags listed below; each one refers to a particular suite:

```yaml
skipped:
  - success_cases
  - different_type
  - different_source
  - different_target_field_type
  - allowed
  - fewer_arguments
```

## Test property

Allows custom tests to be carried out, respecting the information defined in each argument. As for its operation, it is dual. Since you can simply put a value to each argument and the generator will create different versions of the argument according to the information already established or you can manually choose which specific source you want. The latter is useful for arguments that admit both sources (both) and it is required to test a source and a particular value, for example for helpers that admit absences of references (any suffix).
On the other hand, if the helper in its is_variadic property is defined as variadic, you can add more arguments than the defined ones, named `<last argument id>_<number>` (for example `operand_right_1`); the generator will respect the source and type of the last argument. For `filter` and `transformation` helpers every test must set `target_field`.
Configuration that only indicates values and leaves the source assignment in the hands of the generator:
```
test:
  - arguments:
      id_argument: any_value
      id_argument: any_value
      target_field: any_value
    should_pass: whether or not it should happen
    expected: [1,2,3,4]
    description: any description
```

Configuration indicating values and source
```
test:
  - arguments:
      id_argument:
        source: any_source
        value: any_value
      id_argument:
        source: any_source
        value: any_value
      target_field: any_value
    should_pass: whether or not it should happen
    expected: any_value
    description: any description
```

# How generate helper functions documentation
`-o/--output-path` is mandatory. The default exporter is `mark_down`, which writes every processed helper
into a single `ref-helper-functions.md` in the output directory (the `html` and `pdf` exporters write
nothing). The commands below run from `src/engine/`.

## Generate documentation for a particular helper function
```bash
engine-helper-test -e /tmp/environment generate-doc --input-file test/helper_tests/helpers_description/map/int_calculate.yml -o test/helper_tests/documentation
```
## Generate documentation for a particular type of helper function
```bash
engine-helper-test -e /tmp/environment generate-doc --input-dir test/helper_tests/helpers_description/map -o test/helper_tests/documentation
```

## Generate documentation for all helper functions

This regenerates the published reference, `docs/ref/modules/engine/ref-helper-functions.md`, which is never
edited by hand:

```bash
engine-helper-test -e /tmp/environment generate-doc --input-dir test/helper_tests/helpers_description/ -o ../../docs/ref/modules/engine/
```
