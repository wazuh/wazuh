# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""One writing run at a time: the lock on <CONF>/ca."""

import io
import os

import pytest


def run(resolver, sandbox, *argv):
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ={}, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_second_run_times_out(resolver, sandbox, monkeypatch):
    sandbox.stage_ca()
    with resolver.open_top(sandbox.conf, resolver.conf_spec(sandbox.paths)) as conf:
        held = resolver.acquire_lock(conf)
        try:
            with pytest.raises(resolver.LockTimeout):
                resolver.acquire_lock(conf, timeout=0.5)
            monkeypatch.setattr(resolver, "LOCK_TIMEOUT", 0.5)
            code, _, err = run(resolver, sandbox, "--prestart")
            assert code == 2 and f"another resolve-credentials run holds {sandbox.conf}/ca" in err
        finally:
            held.close()
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "WAZUH_INDEXER_MANAGER_PASSWORD=Idx.Passw0rd-123\n")
    assert run(resolver, sandbox, "--prestart")[0] == 0          # released with its descriptor
