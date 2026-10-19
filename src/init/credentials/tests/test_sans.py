# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Subject alternative names of the server pairs: explicit lists (one per pair; apid never inherits remoted's) and
discovery (the node's names and every global address of every interface, from the kernel's netlink dump)."""

import errno
import io
import json
import os
import socket
import struct
import subprocess
import sys

import pytest
from cryptography import x509

from conftest import PROGRAM, interface_addresses


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

def use_addresses(resolver, monkeypatch, entries):
    """The kernel's dump for this test: (index, address, scope, flags) tuples, or an OSError the dump raises."""
    if isinstance(entries, OSError):
        def fail():
            raise entries
        monkeypatch.setattr(resolver, "interface_addresses", fail)
    else:
        monkeypatch.setattr(resolver, "interface_addresses", lambda: interface_addresses(resolver, entries))


def test_discovery(resolver, sandbox):
    """Every interface's global addresses, by interface, IPv4 before IPv6: eth0 and the docker0 bridge alike; the
    loopback and link-local addresses are not named (loopback comes from the fixed list)."""
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0 and err == ""
    assert sans_of(sandbox, "remoted") == ["DNS:node1", "DNS:node1.example.com", "IP:192.0.2.10", "IP:2001:db8::10",
                                           "IP:172.18.0.1", "IP:2001:db8::99"] + LOOPBACK
    assert sans_of(sandbox, "apid") == sans_of(sandbox, "remoted")


def test_discovery_names_every_ipv4_address_of_an_interface(resolver, sandbox, monkeypatch):
    """A secondary address, and the primary address of a second subnet on the same interface, are named too."""
    use_addresses(resolver, monkeypatch, [(2, "10.9.0.10", 0, 0x80), (2, "192.168.77.5", 0, 0x80),
                                          (2, "10.9.0.11", 0, 0x81)])
    run(resolver, sandbox, "--install")
    assert [s for s in sans_of(sandbox, "remoted") if s.startswith("IP:") and s not in LOOPBACK] == \
        ["IP:10.9.0.10", "IP:192.168.77.5", "IP:10.9.0.11"]


def test_discovery_names_interfaces_off_the_default_route(resolver, sandbox, monkeypatch):
    """The dump holds the addresses of an interface that is down or carries no route; they are named."""
    use_addresses(resolver, monkeypatch, [(2, "192.0.2.10", 0, 0x80), (7, "172.31.0.1", 0, 0x80)])
    run(resolver, sandbox, "--install")
    assert "IP:172.31.0.1" in sans_of(sandbox, "remoted")


def test_discovery_skips_deprecated_and_tentative(resolver, sandbox, monkeypatch):
    use_addresses(resolver, monkeypatch, [(2, "2001:db8::10", 0, 0x20), (2, "2001:db8::11", 0, 0x40),
                                          (2, "2001:db8::12", 0, 0x08), (2, "2001:db8::13", 0, 0x80)])
    run(resolver, sandbox, "--install")
    assert [s for s in sans_of(sandbox, "remoted") if s.startswith("IP:2001")] == ["IP:2001:db8::13"]


def test_discovery_ignores_ipv6_flags_on_ipv4(resolver, sandbox, monkeypatch):
    """The deprecated and tentative flags are IPv6 states; an IPv4 address carrying the same bits is still named."""
    use_addresses(resolver, monkeypatch, [(2, "192.0.2.10", 0, 0x60)])
    run(resolver, sandbox, "--install")
    assert "IP:192.0.2.10" in sans_of(sandbox, "remoted")


@pytest.mark.parametrize("address", ["10.0.0.5", "172.16.3.4", "192.168.1.20"])
def test_discovery_keeps_private_ipv4(resolver, sandbox, monkeypatch, address):
    """Private addresses are what most managers have: the kernel's global scope includes them."""
    use_addresses(resolver, monkeypatch, [(2, address, 0, 0x80)])
    run(resolver, sandbox, "--install")
    assert f"IP:{address}" in sans_of(sandbox, "remoted")


@pytest.mark.parametrize("address", ["169.254.10.1", "127.0.0.2", "fe80::5"])
def test_discovery_drops_link_local_and_loopback(resolver, sandbox, monkeypatch, address):
    """Left out by value, even when an operator gave them the global scope."""
    use_addresses(resolver, monkeypatch, [(2, "192.0.2.10", 0, 0x80), (2, address, 0, 0x80)])
    run(resolver, sandbox, "--install")
    assert f"IP:{address}" not in sans_of(sandbox, "remoted")


@pytest.mark.parametrize("scope", [200, 253, 254])
def test_discovery_skips_addresses_without_global_scope(resolver, sandbox, monkeypatch, scope):
    use_addresses(resolver, monkeypatch, [(2, "192.0.2.10", 0, 0x80), (2, "198.51.100.7", scope, 0x80)])
    run(resolver, sandbox, "--install")
    assert "IP:198.51.100.7" not in sans_of(sandbox, "remoted")


def test_discovery_names_an_address_once(resolver, sandbox, monkeypatch):
    use_addresses(resolver, monkeypatch, [(2, "192.0.2.10", 0, 0x80), (5, "192.0.2.10", 0, 0x80)])
    run(resolver, sandbox, "--install")
    assert sans_of(sandbox, "remoted").count("IP:192.0.2.10") == 1


def test_discovery_no_global(resolver, sandbox, monkeypatch):
    """No global address at all: the pairs are still issued, with names and loopback, and a warning says what to set."""
    use_addresses(resolver, monkeypatch, [(1, "127.0.0.1", 254, 0x80), (2, "fe80::2", 253, 0x80)])
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0
    assert "WARNING: no global interface address; the certificates name this node only by name and loopback" in err
    assert "WAZUH_MANAGER_REMOTED_CERT_SANS and WAZUH_MANAGER_APID_CERT_SANS" in err
    assert sans_of(sandbox, "remoted") == ["DNS:node1", "DNS:node1.example.com"] + LOOPBACK


def test_discovery_when_the_addresses_cannot_be_listed(resolver, sandbox, monkeypatch):
    """A kernel that refuses the dump costs the addresses, not the pairs: a warning gives the reason."""
    use_addresses(resolver, monkeypatch, PermissionError(errno.EPERM, "Operation not permitted"))
    code, _, err = run(resolver, sandbox, "--install")
    assert code == 0
    assert ("WARNING: cannot list the interface addresses (Operation not permitted); the certificates name this node "
            "only by name and loopback. Set WAZUH_MANAGER_REMOTED_CERT_SANS and WAZUH_MANAGER_APID_CERT_SANS") in err
    assert sans_of(sandbox, "remoted") == ["DNS:node1", "DNS:node1.example.com"] + LOOPBACK


def test_explicit_lists_skip_discovery(resolver, sandbox, monkeypatch):
    """With both lists set the kernel is not asked, so a refused dump says nothing."""
    use_addresses(resolver, monkeypatch, PermissionError(errno.EPERM, "Operation not permitted"))
    code, _, err = run(resolver, sandbox, "--install", environ={"WAZUH_MANAGER_REMOTED_CERT_SANS": "IP:192.0.2.1",
                                                                "WAZUH_MANAGER_APID_CERT_SANS": "IP:192.0.2.2"})
    assert code == 0 and "interface" not in err


# ---------------------------------------------------------------- the netlink reply

SEQ = 1


def attribute(kind, value):
    return struct.pack("=HH", 4 + len(value), kind) + value + b"\0" * (-len(value) % 4)


def message(kind, body, seq=SEQ):
    return struct.pack("=LHHLL", 16 + len(body), kind, 2, seq, 4242) + body + b"\0" * (-len(body) % 4)


def address_message(family, address, index=2, scope=0, flags=0x80, attributes=None, seq=SEQ):
    raw = socket.inet_pton(family, address)
    body = struct.pack("=BBBBI", family, 24, flags & 0xFF, scope, index)
    for kind, value in (attributes if attributes is not None else [(1, raw), (2, raw)]):
        body += attribute(kind, value)
    return message(20, body, seq)


def done(seq=SEQ):
    return message(3, struct.pack("=i", 0), seq)


def test_parse_two_messages_and_the_end(resolver):
    data = address_message(socket.AF_INET, "192.0.2.10") + address_message(socket.AF_INET6, "2001:db8::1", index=3)
    entries, finished = resolver.parse_address_messages(data, SEQ)
    assert not finished
    assert [(e.index, e.family, e.address, e.scope, e.flags) for e in entries] == \
        [(2, socket.AF_INET, "192.0.2.10", 0, 0x80), (3, socket.AF_INET6, "2001:db8::1", 0, 0x80)]
    assert resolver.parse_address_messages(done(), SEQ) == ([], True)


def test_parse_flags_attribute_overrides_the_header(resolver):
    """ifa_flags holds 8 bits; IFA_FLAGS carries all of them."""
    raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    data = address_message(socket.AF_INET6, "2001:db8::1", flags=0,
                           attributes=[(1, raw), (8, struct.pack("=I", 0x220))])
    assert resolver.parse_address_messages(data, SEQ)[0][0].flags == 0x220


def test_parse_prefers_the_local_address(resolver):
    """On a point-to-point link IFA_ADDRESS is the peer; the interface's own address is IFA_LOCAL, as `ip` prints."""
    data = address_message(socket.AF_INET, "10.0.0.1", attributes=[(1, socket.inet_aton("10.0.0.2")),
                                                                    (2, socket.inet_aton("10.0.0.1"))])
    assert resolver.parse_address_messages(data, SEQ)[0][0].address == "10.0.0.1"
    only_address = address_message(socket.AF_INET, "10.0.0.3", attributes=[(1, socket.inet_aton("10.0.0.3"))])
    assert resolver.parse_address_messages(only_address, SEQ)[0][0].address == "10.0.0.3"


def test_parse_skips_other_messages(resolver):
    """Another sequence, another message type, another family, or no address: skipped, not misread."""
    other_family = message(20, struct.pack("=BBBBI", 17, 0, 0, 0, 2) + attribute(1, b"\x01\x02"))
    no_address = message(20, struct.pack("=BBBBI", socket.AF_INET, 24, 0, 0, 2))
    data = (address_message(socket.AF_INET, "192.0.2.1", seq=SEQ + 1) + message(16, b"\0" * 16) + other_family
            + no_address + done(seq=SEQ + 1))
    assert resolver.parse_address_messages(data, SEQ) == ([], False)


def test_parse_error_message(resolver):
    with pytest.raises(OSError) as raised:
        resolver.parse_address_messages(message(2, struct.pack("=i", -errno.EPERM) + b"\0" * 16), SEQ)
    assert raised.value.errno == errno.EPERM
    assert resolver.parse_address_messages(message(2, struct.pack("=i", 0) + b"\0" * 16), SEQ) == ([], False)


@pytest.mark.parametrize("data", [
    b"\x10\x00",                                                            # shorter than a header
    struct.pack("=LHHLL", 8, 20, 2, SEQ, 0),                                 # length below the header's
    struct.pack("=LHHLL", 400, 20, 2, SEQ, 0) + b"\0" * 8,                   # length past the buffer
    message(20, b"\x02\x18"),                                               # body shorter than ifaddrmsg
    message(20, struct.pack("=BBBBI", 2, 24, 0, 0, 2) + struct.pack("=HH", 40, 1) + b"\0" * 4),  # attribute past it
    message(20, struct.pack("=BBBBI", 2, 24, 0, 0, 2) + struct.pack("=HH", 2, 1)),            # attribute too short
    message(2, b"\0\0"),                                                    # error without its code
], ids=["short-header", "short-length", "long-length", "short-body", "long-attribute", "short-attribute",
        "short-error"])
def test_parse_malformed_reply(resolver, data):
    with pytest.raises(OSError, match="malformed netlink reply"):
        resolver.parse_address_messages(data, SEQ)


def test_interface_addresses_real_kernel(resolver):
    """The host's own dump: the loopback address is there, with the host scope."""
    entries = resolver.interface_addresses()
    assert any(e.address == "127.0.0.1" and e.scope == 254 and e.family == socket.AF_INET for e in entries)
    assert [e.index for e in entries] == sorted(e.index for e in entries)


NAMESPACE_SCRIPT = r"""
import importlib.machinery, importlib.util, json, subprocess, sys
for command in ("ip link add d0 type dummy", "ip link set d0 up", "ip addr add 10.9.0.10/24 dev d0",
                "ip addr add 10.9.0.11/24 dev d0", "ip addr add 192.168.77.5/24 dev d0",
                "ip -6 addr add 2001:db8::10/64 dev d0 nodad", "ip link add d1 type dummy",
                "ip addr add 172.31.0.1/16 dev d1"):
    subprocess.run(command.split(), check=True)
loader = importlib.machinery.SourceFileLoader("resolver", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
listed = subprocess.run(["ip", "-o", "addr", "show", "scope", "global"], capture_output=True, text=True, check=True)
print(json.dumps({"resolver": [[e.address, e.flags & 1] for e in module.interface_addresses() if e.scope == 0],
                  "ip": [line.split()[3].split("/")[0] for line in listed.stdout.splitlines()]}))
"""


def test_interface_addresses_in_a_network_namespace():
    """A private network namespace (root, as the suite runs) with three IPv4 addresses on one interface, one of them
    secondary, and a second interface that is down: the dump lists what `ip -o addr show scope global` lists."""
    result = subprocess.run(["unshare", "-n", sys.executable, "-I", "-c", NAMESPACE_SCRIPT, PROGRAM],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    found = json.loads(result.stdout)
    assert [address for address, _ in found["resolver"]] == found["ip"]
    assert ["10.9.0.11", 1] in found["resolver"]
    assert {"10.9.0.10", "192.168.77.5", "172.31.0.1", "2001:db8::10"} <= set(found["ip"])


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
