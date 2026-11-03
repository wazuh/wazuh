# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest tests/test_jwt_vectors_mirror.py -v

"""The simulator's JWT vectors are a mirror of the C++ ones.

src/shared_modules/utils/jwt/testVectors.hpp is asserted by the utils unit tests;
tool_simulator/internal/wire/testdata/jwt_vectors.json is what the Go simulator's tests read. Nothing
else compares the two, so this suite parses both and fails on any difference -- including a constant
added to the header that the JSON (or the mapping below) does not carry.
"""
import json
import os
import re

import pytest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..', '..', '..'))
HPP = os.path.join(ROOT, 'src', 'shared_modules', 'utils', 'jwt', 'testVectors.hpp')
JSON = os.path.join(ROOT, 'tools', 'manager_benchmark', 'tool_simulator', 'internal', 'wire', 'testdata',
                    'jwt_vectors.json')

NS = 'jwt_profile::v1::test_vectors'
ENROLL = NS + '::enroll'
TOKEN = NS + '::enroll_token'

# (namespace, constant) -> its path in jwt_vectors.json. Every constant of the header must be listed.
MIRROR = {
    (NS, 'kKeyHex'): ('key', 'hex'),
    (NS, 'kAgentId'): ('agent_id',),
    (NS, 'kIat'): ('iat',),
    (NS, 'kExp'): ('exp',),
    (NS, 'kJtiBytesHex'): ('jti_bytes_hex',),
    (NS, 'kJti'): ('jti',),
    (NS, 'kHeaderJson'): ('header_json',),
    (NS, 'kPayloadJson'): ('payload_json',),
    (NS, 'kSigningInput'): ('signing_input',),
    (NS, 'kSignatureB64Url'): ('signature_b64url',),
    (NS, 'kToken'): ('token',),
    (NS, 'kAsciiKeyToken'): ('negative', 'ascii_key_token', 'token'),
    (NS, 'kAudPayloadJson'): ('negative', 'aud_present_token', 'payload_json'),
    (NS, 'kAudToken'): ('negative', 'aud_present_token', 'token'),

    (ENROLL, 'kPassword'): ('enroll', 'hkdf', 'password'),
    (ENROLL, 'kKeyHex'): ('enroll', 'hkdf', 'key_hex'),
    (ENROLL, 'kIat'): ('enroll', 'iat'),
    (ENROLL, 'kExp'): ('enroll', 'exp'),
    (ENROLL, 'kJti'): ('enroll', 'jti'),
    (ENROLL, 'kHeaderJson'): ('enroll', 'header_json'),
    (ENROLL, 'kPayloadJson'): ('enroll', 'payload_json'),
    (ENROLL, 'kSigningInput'): ('enroll', 'signing_input'),
    (ENROLL, 'kSignatureB64Url'): ('enroll', 'signature_b64url'),
    (ENROLL, 'kToken'): ('enroll', 'token'),
    (ENROLL, 'kWrongPasswordToken'): ('enroll', 'negative', 'wrong_password_token', 'token'),
    (ENROLL, 'kKidHeaderToken'): ('enroll', 'negative', 'kid_header_token', 'token'),

    (TOKEN, 'kIdHex'): ('enroll_token', 'token_id_hex'),
    (TOKEN, 'kIdB64Url'): ('enroll_token', 'token_id_b64url'),
    (TOKEN, 'kSecretHex'): ('enroll_token', 'token_secret_hex'),
    (TOKEN, 'kSecretB64Url'): ('enroll_token', 'token_secret_b64url'),
    (TOKEN, 'kKeyFieldB64Url'): ('enroll_token', 'token_key_field_b64url'),
    (TOKEN, 'kTokenKeyHex'): ('enroll_token', 'hkdf_token', 'key_hex'),
    (TOKEN, 'kTokenKidHeaderJson'): ('enroll_token', 'token_kid_jwt', 'header_json'),
    (TOKEN, 'kTokenKidJwt'): ('enroll_token', 'token_kid_jwt', 'token'),
    (TOKEN, 'kReenrollSecretHex'): ('enroll_token', 'reenroll_secret_hex'),
    (TOKEN, 'kReenrollKeyHex'): ('enroll_token', 'hkdf_reenroll', 'key_hex'),
    (TOKEN, 'kAgentKid'): ('enroll_token', 'agent_kid_jwt', 'kid'),
    (TOKEN, 'kAgentKidHeaderJson'): ('enroll_token', 'agent_kid_jwt', 'header_json'),
    (TOKEN, 'kAgentKidJwt'): ('enroll_token', 'agent_kid_jwt', 'token'),
    (TOKEN, 'kPinHex'): ('enroll_token', 'enrollment_token', 'pin_hex'),
    (TOKEN, 'kPinB64Url'): ('enroll_token', 'enrollment_token', 'pin_b64url'),
    (TOKEN, 'kTokenNoKey'): ('enroll_token', 'enrollment_token', 'tokens', 0, 'token'),
    (TOKEN, 'kTokenWithKey'): ('enroll_token', 'enrollment_token', 'tokens', 1, 'token'),
    (TOKEN, 'kTokenPortPrefix'): ('enroll_token', 'enrollment_token', 'tokens', 2, 'token'),
}

# Constants the JSON carries only inside another field: (namespace, constant) -> extractor.
EMBEDDED = {
    (TOKEN, 'kAdr'): lambda doc: json.loads(at(doc, ('enroll_token', 'enrollment_token', 'tokens', 0, 'json')))['adr'],
}

DECLARATION = re.compile(r'constexpr\s+[\w:]+\s+(k\w+)\s*=')
NAMESPACE = re.compile(r'^\s*namespace\s+([\w:]+)', re.MULTILINE)


def literal_value(text, pos):
    """The value of the initializer starting at `pos`: adjacent string literals concatenated, or an integer."""
    parts = []
    while True:
        while text[pos].isspace():
            pos += 1
        if text.startswith('R"(', pos):
            end = text.index(')"', pos + 3)
            parts.append(text[pos + 3:end])
            pos = end + 2
        elif text[pos] == '"':
            match = re.compile(r'"((?:[^"\\]|\\.)*)"').match(text, pos)
            parts.append(re.sub(r'\\(.)', r'\1', match.group(1)))
            pos = match.end()
        elif text[pos] == ';':
            break
        else:
            match = re.compile(r'-?\d+').match(text, pos)
            if match is None or parts:
                raise ValueError(f'unexpected initializer at offset {pos}: {text[pos:pos + 40]!r}')
            return int(match.group(0))
    return ''.join(parts)


def parse_header(path):
    """{(namespace, constant): value} for every `constexpr ... kName = ...;` of the header."""
    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    # Full-line comments only: the doc comments quote JSON, and no literal holds a `//`.
    text = '\n'.join('' if line.lstrip().startswith('//') else line for line in text.splitlines())
    namespaces = [(m.start(), m.group(1)) for m in NAMESPACE.finditer(text)]
    constants = {}
    for match in DECLARATION.finditer(text):
        owner = [name for start, name in namespaces if start < match.start()]
        assert owner, f'{match.group(1)} is declared outside any namespace'
        key = (owner[-1], match.group(1))
        assert key not in constants, f'{key} declared twice'
        constants[key] = literal_value(text, match.end())
    return constants


def at(doc, path):
    for step in path:
        doc = doc[step]
    return doc


@pytest.fixture(scope='module')
def header():
    return parse_header(HPP)


@pytest.fixture(scope='module')
def mirror():
    with open(JSON, encoding='utf-8') as handle:
        return json.load(handle)


def test_every_header_constant_is_mirrored(header):
    assert len(header) == len(MIRROR) + len(EMBEDDED), 'parsed constants'
    assert set(header) == set(MIRROR) | set(EMBEDDED)


@pytest.mark.parametrize('key', sorted(MIRROR), ids=lambda key: f'{key[0].rsplit("::", 1)[-1]}.{key[1]}')
def test_header_constant_matches_json(header, mirror, key):
    assert at(mirror, MIRROR[key]) == header[key]


@pytest.mark.parametrize('key', sorted(EMBEDDED), ids=lambda key: f'{key[0].rsplit("::", 1)[-1]}.{key[1]}')
def test_embedded_constant_matches_json(header, mirror, key):
    assert EMBEDDED[key](mirror) == header[key]


def test_json_only_fields_agree_with_the_header(header, mirror):
    """Fields the JSON repeats (nbf, the HKDF inputs, the lengths) restate header values."""
    assert mirror['nbf'] == header[(NS, 'kIat')]
    assert mirror['enroll']['nbf'] == header[(ENROLL, 'kIat')]
    token = mirror['enroll_token']
    assert token['hkdf_token']['ikm_hex'] == header[(TOKEN, 'kSecretHex')]
    assert token['hkdf_reenroll']['ikm_hex'] == header[(TOKEN, 'kReenrollSecretHex')]
    # Both kid forms sign test_vectors::enroll's claims.
    assert token['token_kid_jwt']['payload_json'] == header[(ENROLL, 'kPayloadJson')]
    assert token['agent_kid_jwt']['payload_json'] == header[(ENROLL, 'kPayloadJson')]
    assert token['token_kid_jwt']['bytes'] == len(header[(TOKEN, 'kTokenKidJwt')])
    assert token['agent_kid_jwt']['bytes'] == len(header[(TOKEN, 'kAgentKidJwt')])
    for entry in token['enrollment_token']['tokens']:
        assert entry['chars'] == len(entry['token'])
