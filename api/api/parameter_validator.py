# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Optional

from connexion.utils import is_null, is_nullable
from connexion.validators import ParameterValidator
from jsonschema import Draft4Validator, ValidationError

# Wording for every keyword the specification applies to a parameter. Each message names the
# violated constraint and nothing else: jsonschema's own text opens with the submitted value and is
# followed by the failing subschema as a Python dict literal, neither of which belongs in a response.
CONSTRAINT_MESSAGES = {
    'enum': lambda value: f"must be one of: {', '.join(str(item) for item in value)}",
    'format': lambda value: f"must match the '{value}' format",
    'maxLength': lambda value: f'must be at most {value} characters long',
    'maximum': lambda value: f'must be less than or equal to {value}',
    'minItems': lambda value: f"must contain at least {value} item{'s' if value != 1 else ''}",
    'minLength': lambda value: f'must be at least {value} characters long',
    'minimum': lambda value: f'must be greater than or equal to {value}',
    'type': lambda value: f"must be of type {' or '.join(value) if isinstance(value, list) else value}",
}


class WazuhParameterValidator(ParameterValidator):
    """Parameter validator reporting a rejection in the API's own vocabulary."""

    @staticmethod
    def validate_parameter(parameter_type: str, value, param: dict, param_name: str = None) -> Optional[str]:
        """Validate a parameter against its schema.

        Parameters
        ----------
        parameter_type : str
            Where the parameter comes from: query, path, header or cookie.
        value : any
            Submitted value.
        param : dict
            Parameter definition, as the specification declares it.
        param_name : str
            Parameter name, used when the definition does not carry one.

        Returns
        -------
        str or None
            Reason why the parameter was rejected, or None if it was accepted.
        """
        if is_nullable(param) and is_null(value):
            return None

        if value is None:
            name = param.get('name', param_name)
            return f"Missing {parameter_type} parameter '{name}'" if param.get('required') else None

        schema = param.get('schema', param)
        try:
            Draft4Validator(schema, format_checker=Draft4Validator.FORMAT_CHECKER).validate(value)
        except ValidationError as exc:
            constraint = CONSTRAINT_MESSAGES.get(exc.validator, lambda _: f"does not satisfy '{exc.validator}'")
            return (f"Invalid value for {parameter_type} parameter '{param.get('name', param_name)}': "
                    f"{constraint(exc.validator_value)}")

        return None
