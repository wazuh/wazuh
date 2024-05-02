### Test Generator for Helper Functions in assets
This tool automates the generation of test cases to verify the correct operation of the auxiliary functions used in the assets. It uses YAML files to describe the parameters of helper functions and generates corresponding test cases.

### Functioning
The tool takes YAML files that describe the parameters of the helper functions used in the assets. These YAML files must contain the following information:

- Helper Function Name: The name of the function to test.
- Variacity: Indicates whether the auxiliary function supports a variable number of arguments.
- Expected Arguments: A list of arguments expected by the helper function, including the expected type and, if necessary, allowed values.
- Special cases: Special cases that must be considered when generating tests.

The tool automatically generates test cases from these YAML files. Each test case includes:
- Asset that contains the helper to test
- Test inputs (if there are references)
- Description detailing what is being tested
- Expected result.

This guarantees exhaustive coverage of the different parameter combinations and special cases, making it easier to verify the correct operation of the auxiliary functions in the assets.

To generate these tests, it is necessary to run the run.py script, which will loop through each corresponding builder type, running the test generator specific to that builder. This process ensures that appropriate test cases are generated for each type of builder used in the project.

### Folder Structure
The YAML files are organized into three folders that represent the types of builders available. The folder structure is as follows:

- Map: Contains YAML files related to Map Builder.
- Filter: Contains YAML files related to Filter Builder.
- Transform: Contains YAML files related to Transform Builder.
Each folder contains the YAML files corresponding to the auxiliary functions used in the respective builder. This structure helps organize and maintain files in an orderly manner.

### Fault Generation
Failures can occur both at compile time (when building the asset or updating it) and at run time (when the event is ingested into the asset).
