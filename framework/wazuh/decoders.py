# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from os.path import exists
from dataclasses import asdict

from wazuh.core.exception import WazuhError
from wazuh.core.engine import get_engine_client
from wazuh.core.engine.utils import validate_response_or_raise
from wazuh.core.engine.models.resources import ResourceFormat, Resource
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.assets import save_asset_file, generate_asset_file_path
from wazuh.core.results import AffectedItemsWazuhResult


DEFAULT_DECODER_FORMAT = ResourceFormat.JSON
ENGINE_USER_NAMESPACE = 'user'

def create_decoder(filename: str, contents: Resource, policy_type: PolicyType):
    """Create a new decoder resource.

    Parameters
    ----------
    filename : str
        The name of the decoder file.
    contents : Resource
        The decoder resource object.
    policy_type : PolicyType
        The policy type for the decoder.

    Returns
    -------
    AffectedItemsWazuhResult
        Result object indicating success or failure.

    Raises
    ------
    WazuhError
        If the decoder file already exists (code 8001),
        if validation fails (code 8002),
        or if creation fails (code 8003).
    """
    result = AffectedItemsWazuhResult(all_msg='Decoder was successfully uploaded',
                                      none_msg='Could not upload decoder'
                                      )

    try:
        asset_file_path = generate_asset_file_path(filename, policy_type)
        if exists(asset_file_path):
            raise WazuhError(8001)

        async with get_engine_client() as client:
            file_contents_json = json.dumps(asdict(contents))

            # Validate contents
            validation_results = client.catalog.validate_resource(
                name=contents.name,
                format=DEFAULT_DECODER_FORMAT,
                content=file_contents_json,
                namespace_id=ENGINE_USER_NAMESPACE
            )

            validate_response_or_raise(validation_results, 8002)

            # Create the new resource
            creation_results = client.content.create_resource(
                type=policy_type,
                format=DEFAULT_DECODER_FORMAT,
                content=file_contents_json,
                policy_type=policy_type
            )

            validate_response_or_raise(creation_results, 8003)

        # Create file
        save_asset_file(asset_file_path, file_contents_json)

        result.affected_items.append(filename)
        result.total_affected_items = len(result.affected_items)
    except WazuhError as exc:
        result.add_failed_item(id_=filename, error=exc)

    return result

def get_decoders():
    pass

def update_decoder():
    pass


def delete_decoders():
    pass