# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Pin the `resource` query parameter of `GET /security/resources` to the RBAC catalog it filters."""

import os

import yaml

SPEC_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'spec', 'spec.yaml')


def test_resource_list_enum_matches_the_rbac_catalog():
    """Every catalog resource can be asked for, and nothing else: a resource missing from the enum answers 400."""
    with open(SPEC_PATH) as spec_file:
        spec = yaml.safe_load(spec_file)

    enum = spec['components']['parameters']['resource_list']['schema']['enum']

    assert sorted(enum) == sorted(spec['x-rbac-catalog']['resources'])
