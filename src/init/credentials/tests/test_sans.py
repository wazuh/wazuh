# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Subject alternative names of the server pairs: explicit lists (one per pair; apid never inherits remoted's) and
discovery (the node's names and the global addresses of the default-route interfaces only)."""

import io
import os

import pytest
from cryptography import x509


def run(resolver, sandbox, *argv, environ=None):
    environ = dict({"WAZUH_INDEXER_MANAGER_PASSWORD": "Idx.Passw0rd-789"}, **(environ or {}))
    out, err = io.StringIO(), io.StringIO()
    code = resolver.main(list(argv), paths=sandbox.paths, environ=environ, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def sans_of(sandbox, name):
    leaf = x509.load_pem_x509_certificates(open(os.path.join(sandbox.certs, f"{name}.pem"), "rb").read())[0]
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return [f"DNS:{n.value}" if isinstance(n, x509.DNSName) else f"IP:{n.value}" for n in names]


LOOPBACK = ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]


# ---------------------------------------------------------------- explicit lists

@pytest.mark.parametrize("value", ["", "IP:999.1.1.1", "IP:2001:::1", "IP:fe80::1%eth0", "IP:010.1.1.1",
                                   "DNS:*.test", "DNS:foo,", "DNS:foo,,DNS:bar"])
def test_invalid_sans(resolver, sandbox, value):
    """Eight malformed lists, each refused before any leaf is issued."""
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_REMOTED_CERT_SANS": value})
    assert code == 0 and "INVALID WAZUH_MANAGER_REMOTED_CERT_SANS: " in err
    assert not os.path.exists(os.path.join(sandbox.certs, "remoted.pem"))
    assert not os.path.exists(os.path.join(sandbox.certs, "apid.pem"))           # neither pair: lists come first


@pytest.mark.parametrize("value", ["10.0.0.1/24", "DNS:under_score", "DNS:-lead.example", "a..b"])
def test_more_invalid_entries(resolver, value):
    assert resolver.parse_san_list(value)[1] is not None


def test_explicit_list(resolver, sandbox):
    run(resolver, sandbox, "--install",
        environ={"WAZUH_MANAGER_REMOTED_CERT_SANS": "DNS:a.example, 10.0.0.1, IP:2001:db8::1, A.example, ::1, 10.0.0.1"})
    # Duplicates go (DNS case-insensitively, addresses by value) keeping the first occurrence: the list's own ::1
    # stays where the operator put it, before the appended loopback names.
    assert sans_of(sandbox, "remoted") == ["DNS:a.example", "IP:10.0.0.1", "IP:2001:db8::1", "IP:::1",
                                           "DNS:localhost", "IP:127.0.0.1"]


def test_explicit_list_from_local_env(resolver, sandbox):
    sandbox.write(os.path.join(sandbox.conf, "local.env"), "WAZUH_MANAGER_APID_CERT_SANS=api.example\n")
    run(resolver, sandbox, "--install")
    assert sans_of(sandbox, "apid") == ["DNS:api.example"] + LOOPBACK


def test_apid_never_inherits(resolver, sandbox):
    run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_REMOTED_CERT_SANS": "DNS:agents.example"})
    assert sans_of(sandbox, "remoted") == ["DNS:agents.example"] + LOOPBACK
    assert "DNS:agents.example" not in sans_of(sandbox, "apid")
    assert sans_of(sandbox, "apid")[0] == "DNS:node1"


def test_empty_list_is_invalid(resolver, sandbox):
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_APID_CERT_SANS": ""})
    assert "INVALID WAZUH_MANAGER_APID_CERT_SANS: empty (set in the environment)" in err


# ---------------------------------------------------------------- discovery

def test_discovery(resolver, sandbox):
    """eth0 carries the default routes: its IPv4 and its global, non-deprecated IPv6 address are named; docker0's
    addresses and eth0's link-local one are not."""
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == ""
    assert sans_of(sandbox, "remoted") == ["DNS:node1", "DNS:node1.example.com", "IP:192.0.2.10",
                                           "IP:2001:db8::10"] + LOOPBACK
    assert sans_of(sandbox, "apid") == sans_of(sandbox, "remoted")


def test_discovery_skips_deprecated_and_tentative(resolver, sandbox):
    sandbox.write_proc(if_inet6="20010db8000000000000000000000010 02 40 00 20 eth0\n"
                                "20010db8000000000000000000000011 02 40 00 40 eth0\n"
                                "20010db8000000000000000000000012 02 40 00 08 eth0\n"
                                "20010db8000000000000000000000013 02 40 00 80 eth0\n")
    run(resolver, sandbox, "--install")
    assert [s for s in sans_of(sandbox, "remoted") if s.startswith("IP:2001")] == ["IP:2001:db8::13"]


@pytest.mark.parametrize("address", ["10.0.0.5", "172.16.3.4", "192.168.1.20"])
def test_discovery_keeps_private_ipv4(resolver, sandbox, monkeypatch, address):
    """Private addresses are what most managers have: the kernel's global scope includes them."""
    monkeypatch.setattr(resolver, "interface_ipv4", lambda name: address if name == "eth0" else None)
    run(resolver, sandbox, "--install")
    assert f"IP:{address}" in sans_of(sandbox, "remoted")


@pytest.mark.parametrize("address", ["169.254.10.1", "127.0.0.2"])
def test_discovery_drops_link_local_and_loopback(resolver, sandbox, monkeypatch, address):
    monkeypatch.setattr(resolver, "interface_ipv4", lambda name: address if name == "eth0" else None)
    run(resolver, sandbox, "--install")
    assert f"IP:{address}" not in sans_of(sandbox, "remoted")


def test_discovery_no_global(resolver, sandbox):
    """No default route at all: the pairs are still issued, with names and loopback, and a warning says what to set."""
    sandbox.write_proc(route="Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n", ipv6_route="",
                       if_inet6="")
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0
    assert "no global address on a default-route interface" in err
    assert "WAZUH_MANAGER_REMOTED_CERT_SANS and WAZUH_MANAGER_APID_CERT_SANS" in err
    assert sans_of(sandbox, "remoted") == ["DNS:node1", "DNS:node1.example.com"] + LOOPBACK


@pytest.mark.parametrize("fqdn,expected", [("node1", ["DNS:node1"]), ("node1.corp.example", ["DNS:node1",
                                           "DNS:node1.corp.example"]), ("bad_name.example", ["DNS:node1"]),
                                           (None, ["DNS:node1"])])
def test_fqdn(resolver, sandbox, monkeypatch, fqdn, expected):
    monkeypatch.setattr(resolver, "canonical_name", lambda host: fqdn)
    run(resolver, sandbox, "--install")
    assert [s for s in sans_of(sandbox, "remoted") if s.startswith("DNS:node1")] == expected


def test_old_variable_ignored(resolver, sandbox):
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_CERT_SANS": "DNS:old.example"})
    assert code == 0 and err.count("WAZUH_MANAGER_CERT_SANS is ignored") == 1
    assert "DNS:old.example" not in sans_of(sandbox, "remoted")


def test_bad_list_reported_even_when_kept(resolver, sandbox):
    """--prestart runs every --check test: a bad list is reported although both pairs are kept, and nothing changes."""
    run(resolver, sandbox, "--install")
    before = sandbox.tree_state()
    code, _, err = run(resolver, sandbox, "--prestart", environ={"WAZUH_MANAGER_REMOTED_CERT_SANS": "DNS:bad_name"})
    assert code == 1 and err.count("INVALID WAZUH_MANAGER_REMOTED_CERT_SANS: DNS:bad_name: not a valid DNS name") == 1
    assert sandbox.tree_state() == before
