import json
import pytest
import warnings


def test_default_field_type():
    # Load the JSON file
    with open("wazuh-template.json") as f:
        data = json.load(f)

    # Get the "index.query.default_field" object from "mappings"
    default_field = data["settings"]["index.query.default_field"]

    # Validate that all fields in "default_field" are of type "text" or "keyword"
    errors = []
    for field in default_field:
        # Split the field name into its nested parts
        field_names = field.split(".")
        # Access the nested JSON recursively
        properties = data["mappings"]["properties"]
        # Iterate over each element of the list using index
        for index, field_name in enumerate(field_names):
            # Check if the field exists
            if field_name not in properties:
                # Warning since the most important thing is not to have fields that are not text or keyword, which
                # causes more serious problems and is easier to reproduce -> issue #16543
                warnings.warn(
                    f"The field '{field}' does not exist in mappings, this may be a error.")
                break
            else:
                properties = properties[field_name]
            # Check if it is the last index.
            if index == len(field_names) - 1 or len(field_names) == 1:
                # Check that the field exists and is of type text or keyword
                if "type" in properties:
                    if properties["type"] not in ["text", "keyword"]:
                        errors.append(
                            f"ERROR - The field '{field}' is not of type 'text' or 'keyword'")
                break
            else:
                properties = properties["properties"]
    # Check if there were any errors, and fail the test if there were
    if errors:
        pytest.fail("\n".join(errors))
