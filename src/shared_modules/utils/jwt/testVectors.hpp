/*
 * Wazuh shared modules utils - JWT agent authentication profile
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file testVectors.hpp
/// Frozen `wazuh-agent+jwt` vectors shared by every implementation (C++ manager/agent, Go simulator,
/// Python tools). Generated with Python's stdlib (hmac/hashlib/base64) as an oracle independent of
/// this library; the JSON mirror is tools/manager_benchmark/tool_simulator/internal/wire/testdata/
/// jwt_vectors.json -- keep both in sync. Test code only: nothing in production includes this.

#pragma once

#include <cstdint>
#include <string_view>

namespace jwt_profile::v1::test_vectors
{
    /// 64 lowercase hex chars; first byte 0x00, last 0xff (binary key, not printable).
    constexpr std::string_view kKeyHex = "0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff";
    constexpr std::string_view kAgentId = "001";
    constexpr std::int64_t kIat = 1700000000;
    constexpr std::int64_t kExp = 1700000060;
    /// jti bytes 0x00..0x0f.
    constexpr std::string_view kJtiBytesHex = "000102030405060708090a0b0c0d0e0f";
    constexpr std::string_view kJti = "AAECAwQFBgcICQoLDA0ODw";

    constexpr std::string_view kHeaderJson = R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"})";
    constexpr std::string_view kPayloadJson =
        R"({"exp":1700000060,"iat":1700000000,"iss":"wazuh-agent/001","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000,"sub":"001"})";

    constexpr std::string_view kSigningInput =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWFnZW50K2p3dCJ9."
        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoid2F6dWgtYWdlbnQvMDAxIiwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTE"
        "RBME9EdyIsIm5iZiI6MTcwMDAwMDAwMCwic3ViIjoiMDAxIn0";
    constexpr std::string_view kSignatureB64Url = "VdKOn_yX2AkynNwDOrcjYMiOa8RYguaIhZ7PJCWfdUA";
    /// The complete valid token (272 bytes).
    constexpr std::string_view kToken =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWFnZW50K2p3dCJ9."
        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoid2F6dWgtYWdlbnQvMDAxIiwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTE"
        "RBME9EdyIsIm5iZiI6MTcwMDAwMDAwMCwic3ViIjoiMDAxIn0."
        "VdKOn_yX2AkynNwDOrcjYMiOa8RYguaIhZ7PJCWfdUA";

    /// Negative: same header/payload, signed with the 64 hex chars as an ASCII key. Must be rejected.
    constexpr std::string_view kAsciiKeyToken =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWFnZW50K2p3dCJ9."
        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoid2F6dWgtYWdlbnQvMDAxIiwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTE"
        "RBME9EdyIsIm5iZiI6MTcwMDAwMDAwMCwic3ViIjoiMDAxIn0."
        "3w8hHOsd1aZYBDiDmtA7wrKlLDdQdS8vgf3xYEeOki4";

    /// Negative: correct key and signature, but an extra `aud` claim. Must be rejected (exact claim set).
    constexpr std::string_view kAudPayloadJson =
        R"({"aud":"wazuh-manager","exp":1700000060,"iat":1700000000,"iss":"wazuh-agent/001","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000,"sub":"001"})";
    constexpr std::string_view kAudToken =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWFnZW50K2p3dCJ9."
        "eyJhdWQiOiJ3YXp1aC1tYW5hZ2VyIiwiZXhwIjoxNzAwMDAwMDYwLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IndhenVoLWFnZW50LzAwMSIsIm"
        "p0aSI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJuYmYiOjE3MDAwMDAwMDAsInN1YiI6IjAwMSJ9."
        "ScnCz_6A1XAqPd7vuqmbfMeRLdc8NaM7rDLuHqF9gng";
} // namespace jwt_profile::v1::test_vectors

/// Frozen `wazuh-enroll+jwt` vectors (jwtEnrollProfileV1.hpp), same oracle; JSON mirror under
/// "enroll" in jwt_vectors.json.
namespace jwt_profile::v1::test_vectors::enroll
{
    constexpr std::string_view kPassword = "MyEnrollmentSecret123";
    /// HKDF-SHA256(kPassword, salt = 32 x 0x00, info = "WAZUH-ENROLL-JWT-KEY" || 0x01, L = 32).
    constexpr std::string_view kKeyHex = "eeecc651648436211783381e38d0a661bfecc2888a4e23b28c94f415f98616b6";
    constexpr std::int64_t kIat = 1700000000;
    constexpr std::int64_t kExp = 1700000060;
    constexpr std::string_view kJti = "AAECAwQFBgcICQoLDA0ODw";

    constexpr std::string_view kHeaderJson = R"({"alg":"HS256","typ":"wazuh-enroll+jwt"})";
    constexpr std::string_view kPayloadJson =
        R"({"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000})";
    constexpr std::string_view kSigningInput = "eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ."
                                               "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2N"
                                               "JQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0";
    constexpr std::string_view kSignatureB64Url = "Ll9rqCc4D0emY3xUV99-yD-ep0Xp7CI1qKG8Rzkvm8o";
    /// The complete valid token (210 bytes).
    constexpr std::string_view kToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ."
                                        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTE"
                                        "RBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0."
                                        "Ll9rqCc4D0emY3xUV99-yD-ep0Xp7CI1qKG8Rzkvm8o";

    /// Negative: same claims, signed with the key of password "WrongPassword". Must be rejected.
    constexpr std::string_view kWrongPasswordToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ."
                                                     "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3U"
                                                     "UZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0."
                                                     "a8lxhFZIpYPD74vwYD_h6kPT4ZnedFOHEBMJPbltzZg";

    /// Negative: correct key and signature, header carries an extra `kid` (exact header set).
    constexpr std::string_view kKidHeaderToken =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ."
        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH"
        "0."
        "-PID3RuMlsz0ShaKX5IppGhP3iX2nEq6mfyGPgqDDMY";
} // namespace jwt_profile::v1::test_vectors::enroll

/// Frozen vectors of the `kid` forms of `wazuh-enroll+jwt` and of the enrollment token itself
/// (issue #38993). Same oracle (Python stdlib hmac/hashlib/base64 for HKDF, HS256 and base64url);
/// JSON mirror under "enroll_token" in jwt_vectors.json; authd's C tests (test_enrollment_token.c)
/// pin the same values, so C, C++, Go and Python cannot drift.
namespace jwt_profile::v1::test_vectors::enroll_token
{
    /// Token id bytes 0x00..0x0f, secret bytes 0x10..0x1f.
    constexpr std::string_view kIdHex = "000102030405060708090a0b0c0d0e0f";
    constexpr std::string_view kIdB64Url = "AAECAwQFBgcICQoLDA0ODw"; ///< the `kid` (22 chars)
    constexpr std::string_view kSecretHex = "101112131415161718191a1b1c1d1e1f";
    constexpr std::string_view kSecretB64Url = "EBESExQVFhcYGRobHB0eHw";
    /// base64url(id || secret): the `key` field of the enrollment token (43 chars).
    constexpr std::string_view kKeyFieldB64Url = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    /// HKDF-SHA256(secret, salt = 32 x 0x00, info = "WAZUH-ENROLL-TOKEN-KEY" || 0x01, L = 32).
    constexpr std::string_view kTokenKeyHex = "5da72b786a15757caa8d825a74a3474c3f15b048fd1064b49863ffc715a95860";
    constexpr std::string_view kTokenKidHeaderJson =
        R"({"alg":"HS256","kid":"AAECAwQFBgcICQoLDA0ODw","typ":"wazuh-enroll+jwt"})";
    /// Same claims as test_vectors::enroll (iat 1700000000, jti of bytes 00..0f), signed with
    /// kTokenKeyHex. 251 bytes.
    constexpr std::string_view kTokenKidJwt =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJ0eXAiOiJ3YXp1aC1lbnJvbGwrand0In0."
        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH"
        "0."
        "7sTfFRpPNoSg7QPO1h6FWCvY2Islau-E0gQnP1PWelk";

    /// Re-enrollment: reenroll_secret bytes 0x00..0x1f, `kid` = canonical agent id "001".
    constexpr std::string_view kReenrollSecretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    /// HKDF-SHA256(reenroll_secret, salt = 32 x 0x00, info = "WAZUH-REENROLL-KEY" || 0x01, L = 32).
    constexpr std::string_view kReenrollKeyHex = "68b01ea65fc441951a17e3fd9b7e2dedc846d364f38596630ea3f69f60482ae9";
    constexpr std::string_view kAgentKid = "001";
    constexpr std::string_view kAgentKidHeaderJson = R"({"alg":"HS256","kid":"001","typ":"wazuh-enroll+jwt"})";
    /// Same claims, signed with kReenrollKeyHex. 226 bytes. (Same header as enroll::kKidHeaderToken,
    /// which is signed with the password key and must keep failing on the shared-key verifier.)
    constexpr std::string_view kAgentKidJwt =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ."
        "eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH"
        "0."
        "waWOzsJ3GP5kj1tOAEdpWNBzjqbjGPSqE039h8irCKc";

    /// The enrollment token (the value an operator pastes): base64url of compact JSON
    /// {"ver":1,"adr":…,"pin":…[,"key":…]}. `pin` = base64url(SHA-256(SubjectPublicKeyInfo)) of the
    /// frozen CA (the devcontainer's root-ca.pem; 64 hex below), `key` = kKeyFieldB64Url.
    constexpr std::string_view kPinHex = "6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2";
    constexpr std::string_view kPinB64Url = "YJHcNmXtXoM8jZRfk-u_FLNwIMzudzNORJesLvNZCqI";
    constexpr std::string_view kAdr = "siem.example.local";
    /// No credential (118 chars): {"ver":1,"adr":"siem.example.local","pin":"<kPinB64Url>"}
    constexpr std::string_view kTokenNoKey = "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NO"
                                             "GpaUmZrLXVfRkxOd0lNenVkek5PUkplc0x2TlpDcUkifQ";
    /// With credential (187 chars): …,"key":"<kKeyFieldB64Url>"}
    constexpr std::string_view kTokenWithKey =
        "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NOGpaUmZrLXVfRkxOd0lNenVkek5PUkplc0x2Tl"
        "pDcUki"
        "LCJrZXkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4In0";
    /// Non-default port and prefix, no credential (134 chars): "adr":"siem.example.local:8443/wazuh/"
    constexpr std::string_view kTokenPortPrefix = "eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbDo4NDQzL3dhenVoLyIsInBp"
                                                  "biI6IllKSGNObVh0WG9NOGpaUmZrLXVfRkxOd0lNenVkek5P"
                                                  "Ukplc0x2TlpDcUkifQ";
} // namespace jwt_profile::v1::test_vectors::enroll_token
