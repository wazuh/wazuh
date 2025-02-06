# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from connexion.uri_parsing import OpenAPIURIParser

LOWER_FIELDS = (
    'component',
    'configuration',
    'hash',
    'requirement',
    'status',
    'type',
    'section',
    'tag',
    'level',
    'resource',
)


class APIUriParser(OpenAPIURIParser):
    """Sanitize parameters class."""

    def resolve_params(self, params, _in):
        """Sanitizes the lower_fields parameters converting keys and values to lowercase."""
        # Transform to lowercase the values for query parameter's spec.yaml enums
        params.update(
            {
                k.lower(): [list_item.lower() for list_item in v] if isinstance(v, list) else v.lower()
                for k, v in params.items()
                if k in LOWER_FIELDS
            }
        )

        return super().resolve_params(params, _in)
