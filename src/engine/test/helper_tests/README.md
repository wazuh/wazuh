# Engine helper test

1. [End to end tests for helper functions](#end-to-end-tests-for-helper-functions)
1. [Directory structure](#directory-structure)
1. [Install](#install)
    1. [engine-helper-test-initial-state](#engine-helper-test-initial-state)
    1. [engine-helper-test-validator](#engine-helper-test-validator)
    1. [engine-helper-test-generator](#engine-helper-test-generator)
    1. [engine-helper-test-generate-runner](#engine-helper-test-generate-runner)
    1. [engine-helper-test-documentation](#engine-helper-test-documentation)
1. [How to run all the tests](#how-to-run-all-the-tests)
1. [How to create an output in particular and in general](#how-to-create-an-output-in-particular-and-in-general)
    1. [Create an output for a given helper function](#create-an-output-for-a-given-helper-function)
    2. [Create an output for a set of helper functions belonging to a certain type](#create-an-output-for-a-set-of-helper-functions-belonging-to-a-certain-type)
1. [How to run a test in particular and in general](#how-to-run-a-test-in-particular-and-in-general)
    1. [Run a test for a given helper function](#run-a-test-for-a-given-helper-function)
    2. [Run a test suite of a certain type](#run-a-test-suite-of-a-certain-type)
1. [How to write a test](#how-to-write-a-test)
    1. [Schema](#schema)
    2. [Arguments property](#arguments-property)
        1. [Types](#types)
        2. [Subsets](#subsets)
        2. [Sources](#source)
    3. [General restrictions property](#general-restrictions-property)
    4. [Target field property](#target-field-property)
    5. [Skipped property](#skipped-property)
    6. [Test property](#test-property)
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

# Directory structure

```bash
helper/
├── configuration_files
├   └── general.conf
├── engine_helper_test
|   └── src
|     └── definition_types
|       └── __init__.py
|       └── types.py
|       └── utils.py
|     └── generator_runner
|       └── __init__.py
|       └── __main__.py
|     └── initial_state
|       └── __init__.py
|       └── __main__.py
|     └── runner
|       └── __init__.py
|       └── __main__.py
|     └── test_cases_generator
|       └── __init__.py
|       └── __main__.py
|       └── argument.py
|       └── buildtime_cases.py
|       └── generator.py
|       └── parser.py
|       └── template.py
|       └── test_data.py
|       └── validator.py
|     └── documentation_generator
|       └── __init__.py
|       └── __main__.py
|       └── documentation.py
|       └── exporter.py
|       └── html_generator.py
|       └── mark_down_generator.py
|       └── pdf_generator.py
|       └── types.py
|    └── .gitignore
|    └── pyproject.toml
|    └── setup.cfg
|    └── setup.py
├── helpers_description
|    └── filter
|     └── ...
|    └── map
|     └── ...
|    └── transformation
|     └── ...
├── mmdb
│   └── testdb-asn.mmdb
│   └── testdeb-city.mmdb
├── README.md
```

# Install

The `engine_helper_test` python package contains various scripts to help to create and run helper function tests.


Requires python 3.8, to install navigate where the Wazuh repository folder is located and run:

`pip install wazuh/src/engine/test/helper_tests/engine_helper_test`

If we want to install for developing and modifying the scripts, install in editable mode and the additional dev packages:

`pip install -e wazuh/src/engine/test/helper_tests/engine_helper_test[dev]`

## engine-helper-test-initial-state

```bash
usage: engine-helper-test-initial-state [-h] -e ENVIRONMENT -b BINARY --mmdb MMDB --conf CONF

Update configuration, create kvdbs and mmdbs

optional arguments:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Environment directory
  -b BINARY, --binary BINARY
                        Path to the binary file
  --mmdb MMDB           Directory path where the as and geo databases are located
  --conf CONF           File path where the engine configuration file is
```

## engine-helper-test-validator

```bash
usage: engine-helper-test-validator [-h] [--input_file_path INPUT_FILE_PATH] [--folder_path FOLDER_PATH]

Validates that the helper descriptions comply with the schema

optional arguments:
  -h, --help            show this help message and exit
  --input_file_path INPUT_FILE_PATH
                        Absolute or relative path where the description of the helper function is located
  --folder_path FOLDER_PATH
                        Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located
```

## engine-helper-test-generator

```bash
usage: engine-helper-test-generator [-h] [--input_file_path INPUT_FILE_PATH] [--folder_path FOLDER_PATH] -o OUTPUT_PATH

Generates files containing test cases for a given helper

optional arguments:
  -h, --help            show this help message and exit
  --input_file_path INPUT_FILE_PATH
                        Absolute or relative path where the description of the helper function is located
  --folder_path FOLDER_PATH
                        Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located
  -o OUTPUT_PATH, --output_path OUTPUT_PATH
                        Absolute or relative path of the directory where the generated test files will be located
```

## engine-helper-test-runner

```bash
usage: engine-helper-test-runner [-h] -e ENVIRONMENT -b BINARY [--input_file_path INPUT_FILE_PATH] [--folder_path FOLDER_PATH] [--failure_cases] [--success_cases]

Runs the generated test cases and validates their results

optional arguments:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Environment directory
  -b BINARY, --binary BINARY
                        Path to the binary file
  --input_file_path INPUT_FILE_PATH
                        Absolute or relative path where the test cases were generated
  --folder_path FOLDER_PATH
                        Absolute or relative path where the test cases were generated
  --failure_cases       Shows only the failure test cases that occurred
  --success_cases       Shows only the success test cases that occurred
```

## engine-helper-test-generate-runner

```bash
usage: engine-helper-test-generate-runner [-h] -e ENVIRONMENT -b BINARY -i INPUT -o OUTPUT

Generate and run all helper test cases

optional arguments:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Environment directory
  -b BINARY, --binary BINARY
                        Path to the binary file
  -i INPUT, --input INPUT
                        Absolute or relative path where of the directory where the helper configurations are located
  -o OUTPUT, --output OUTPUT
                        Absolute or relative path where the test cases were generated
```

## engine-helper-test-documentation
```bash
usage: engine-helper-test-documentation [-h] [--input_file_path INPUT_FILE_PATH] [--folder_path FOLDER_PATH] [--exporter EXPORTER] [-o OUTPUT_PATH]

Generates files containing documentation for a given helper

options:
  -h, --help            show this help message and exit
  --input_file_path INPUT_FILE_PATH
                        Absolute or relative path where the description of the helper function is located
  --folder_path FOLDER_PATH
                        Absolute or relative path where the directory that contains the descriptions of the auxiliary functions is located
  --exporter EXPORTER   Absolute or relative path of the directory where the generated test files will be located
  -o OUTPUT_PATH, --output_path OUTPUT_PATH
                        Absolute or relative path of the directory where the generated documentation files will be located
```

# How to run all the tests

After completing the installation, you must run the setupEnvironment.py that builds the environment in a certain location.

```bash
usage: setupEnvironment.py [-h] [-e ENVIRONMENT]

Setup engine directories.

optional arguments:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Environment directory
```

- `test/setupEnvironment.py -e /tmp/env`

Once the environment is built, the initial state must be initialized

- `engine-helper-test-initial-state -e /tmp/env/ -b build/main --mmdb test/helper_tests/mmdb/ --conf test/helper_tests/configuration_files/general.conf`

At this point you can execute the generation and evaluation of the tests using a single command.
It is important to clarify that the storage of the generated test cases can only be in temporary directories.

- `engine-helper-test-generate-runner -e /tmp/env/ -b build/main -i test/helper_tests/helpers_description/ -o /tmp/output`

# How to create an output in particular and in general

If you only need to generate test cases for a particular helper or for a helper set of a certain type, it is not necessary to create any environment or establish an initial state.

## Create an output for a given helper function

`engine-helper-test-generator --input_file_path test/helper_tests/helpers_description/map/int_calculate.yml -o /tmp/output`

## Create an output for a set of helper functions belonging to a certain type

`engine-helper-test-generator --folder_path test/helper_tests/helpers_description/map/ -o /tmp/output`

# How to run a test in particular and in general
To run the generated tests, the environment must be created and the initial state established as explained [here](#how-to-run-all-the-tests)

## Run a test for a given helper function
After having generated the test cases, whether [particular](#create-an-output-for-a-given-helper-function) or [general](#create-an-output-for-a-set-of-helper-functions-belonging-to-a-certain-type) is possible to execute the tests for a single output

`engine-helper-test-runner -e /tmp/env -b build/main --input_file_path /tmp/output/int_calculate.yml --failure_cases`

## Run a test suite of a certain type
After having generated the test cases, whether [particular](#create-an-output-for-a-given-helper-function) or [general](#create-an-output-for-a-set-of-helper-functions-belonging-to-a-certain-type) is possible to execute the tests for a single output

`engine-helper-test-runner -e /tmp/env -b build/main --folder_path /tmp/output --failure_cases`


# How to write a test

## Schema

Each helper descriptor file is verified before the construction of the test cases to ensure that it contains exactly the format and information expected by the generator.
Below are the mandatory properties that the file should have:

- name: Details the name of the helper function that will be evaluated for the construction of the test cases.
- helper_type: It is only possible to set one of the types supported by the engine [map, filter, transformation]
- is_variadic: Indicates whether or not the helper function admits a number of variable arguments.

Once the minimum necessary for the helper descriptor has been defined, optional properties can be added:

- arguments: Includes information about the helper arguments such as accepted types and allowed fonts, among other things.
- general_restrictions: This property is useful when there is some type of restriction between the values ​​that the helper arguments can take.
- target_field: This property is useful for the filter and transformation type helpers. Allows you to set the specific type and subtype of the value that the target_field will have
- skipped: Allows you to ignore the results of a particular test suite. At the moment only the output of the following suites ["success_cases", "different_type", "different_source", "different_target_field_type", "allowed"] can be ignored. I will develop this topic further later.
- test: This property, in contrast to automatic tests that are generated based on the description of the arguments, allows you to generate a test with specific types and sources as long as it respects the information of each argument.

## Arguments property

accepts a list of objects. Each object has a key to identify the argument and a value, which is another object that describes information about the type, source, and whether there are any restrictions on the values ​​the argument can take.

```
arguments:
  argument_id:
    type: any_type
    generate: any_subtset
    source: any_source
    restrictions:
      allowed:
        - tany_value
  argument_id:
    type: any_type
    generate: any_subtset
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
Define allowed or forbidden values ​​for each argument. It is only possible to set one of the two. each supports a list of values.

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

```
general_restrictions:
  - brief: some restriction brief
    arguments:
      argument_id: some_value
      argument_id: some_value
    details: some restriction detail
```
The argument_id is a numerical identifier that indicates its position within the parameters. The value must correspond to the one indicated in the argument. The generator will do the rest based on the information in the arguments property.

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

## Skipped property
With this property it is possible to ignore the results of the tests generated from the arguments. Supports a list with specific tags listed below. Supports a list with specific tags listed below. each one refers to a particular suite:

```
skipped:
  - success_cases
  - different_type
  - different_source
  - different_target_field_type
  - allowed
```

## Test property

Allows custom tests to be carried out, respecting the information defined in each argument. As for its operation, it is dual. Since you can simply put a value to each argument and the generator will create different versions of the argument according to the information already established or you can manually choose which specific source you want. The latter is useful for arguments that admit both sources (both) and it is required to test a source and a particular value, for example for helpers that admit absences of references (any suffix).
On the other hand, if the helper in its is_variadic property is defined as variadic, you can put as many arguments as you want (maximum 40), the generator will respect the source and type of the last argument.
Configuration that only indicates values ​​and leaves the source assignment in the hands of the generator:
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

Configuration indicating values ​​and source
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
By default, if a directory is not specified to store the created documentation, it will be saved in `/tmp/documentation`.
Likewise, the default exporter type if one is not specified will be `markdown`.
The commands below use absolute paths to the engine directory.

## Generate documentation for a particular helper function
```bash
engine-helper-test-documentation --input_file_path test/helper_tests/helpers_description/map/int_calculate.yml -o test/helper_tests/documentation
```
## Generate documentation for a particular type of helper function
```bash
engine-helper-test-documentation --folder_path test/helper_tests/helpers_description/map -o test/helper_tests/documentation
```
```bash
engine-helper-test-documentation --folder_path test/helper_tests/helpers_description/filter -o test/helper_tests/documentation
```
```bash
engine-helper-test-documentation --folder_path test/helper_tests/helpers_description/transformation -o test/helper_tests/documentation
```
## Generate documentation for all helper functions
```bash
engine-helper-test-documentation --folder_path test/helper_tests/helpers_description/ -o docs/helpers/
```
