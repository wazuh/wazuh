# Test Generator for Helper Functions in assets

This tool automates the generation of test cases to verify the correct operation of the auxiliary functions used in the assets. It uses YAML files to describe the parameters of helper functions and generates corresponding test cases.
The tool automatically generates test cases from these YAML files. Each test case includes:
- Asset that contains the helper to test
- Test inputs (if there are references)
- Description detailing what is being tested
- Expected output
- Result


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

## Install

The `components` python package contains various scripts to help to create and run helper function tests.


Requires python 3.8, to install navigate where the Wazuh repository folder is located and run:

`pip install wazuh/src/engine/test/helper_tests/components`

If we want to install for developing and modifying the scripts, install in editable mode and the additional dev packages:

`pip install -e wazuh/src/engine/test/helper_tests/components[dev]`

## engine-helper-test-initial-state
```
usage: engine-helper-test-initial-state [-h] -e ENVIRONMENT -b BINARY --mmdb MMDB --conf CONF

Update configuration, create kvdbs and mmdbs

optional arguments:
  -h, --help            show this help message and exit
  -e ENVIRONMENT, --environment ENVIRONMENT
                        Environment directory
  -b BINARY, --binary BINARY
                        Path to the binary file
  --mmdb MMDB           Directory path where the as and geo databases are located
  --conf CONF           Directory path where the engine configuration file is
```

## engine-helper-test-validator
It is responsible for performing validations on a directory or file that contains the description of a helper function.

```
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

```
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
```
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
```
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

## Use
Below, the execution that should be followed to test the tool is listed in order.

- `python3 src/engine/test/setupEnvironment.py -e env`
- `engine-helper-test-initial-state -h`
- `engine-helper-test-generator -h`
- `engine-helper-test-runner -h`


The YAML files are organized into three folders that represent the types of builders available. The folder structure is as follows:

- Map: Contains YAML files related to Map Builder.
- Filter: Contains YAML files related to Filter Builder.
- Transform: Contains YAML files related to Transform Builder.

Each folder contains the YAML files corresponding to the auxiliary functions used in the respective builder. This structure helps organize and maintain files in an orderly manner.
