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
