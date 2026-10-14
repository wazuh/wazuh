# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The resolver and the framework agree on passwords. The resolver seeds rbac.db before the framework is importable, so
it carries its own rule and generator; every value it accepts or generates must pass the Server API's rule
(framework/wazuh/security.py), and its generator must match the framework's (framework/wazuh/rbac/orm.py). Both files
are read as source, never imported: the framework's dependencies are not installed here."""

import ast
import os
import re

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def constants(relative):
    """The module-level assignments of literals (and re.compile(<literal>) patterns) in a framework file."""
    with open(os.path.join(REPO, relative)) as handle:
        tree = ast.parse(handle.read())
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = node.value
            if (isinstance(value, ast.Call) and getattr(value.func, "attr", "") == "compile" and value.args
                    and isinstance(value.args[0], ast.Constant)):
                found[node.targets[0].id] = re.compile(value.args[0].value)
            elif isinstance(value, ast.Constant):
                found[node.targets[0].id] = value.value
    return found


API = constants("framework/wazuh/security.py")
SEEDING = constants("framework/wazuh/rbac/orm.py")


def test_generator_matches_framework(resolver):
    assert resolver.CHARS_SYMBOLS == SEEDING["_PASSWORD_SYMBOLS"]
    assert resolver.PASSWORD_LENGTH == SEEDING["_PASSWORD_LENGTH"]


def test_resolver_values_pass_api_rule(resolver):
    """Whatever the resolver generates or accepts, the Server API accepts too."""
    values = [resolver.generate_password() for _ in range(200)] + ["Aa1." * 3, "Aa1." * 16, "Api.Passw0rd-123"]
    for value in values:
        assert resolver.password_problem(value) is None
        assert API["_user_password"].match(value), value
        assert API["PASSWORD_MIN_LENGTH"] <= len(value) <= API["PASSWORD_MAX_LENGTH"]
    assert (resolver.PASSWORD_MIN_LENGTH, resolver.PASSWORD_MAX_LENGTH) == (API["PASSWORD_MIN_LENGTH"],
                                                                          API["PASSWORD_MAX_LENGTH"])
