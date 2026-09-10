/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authFailureClass.hpp"

#include "external/nlohmann/json.hpp"

#include <array>
#include <utility>

namespace
{
    // The eight classes, spelled exactly as remoted spells them (authMiddleware.cpp's kUnknownAgent
    // and friends). One table drives both directions, so a name can never be read as one class and
    // printed as another. Unclassified is deliberately absent: it is the absence of a class, not a
    // value the manager can send.
    constexpr std::array<std::pair<std::string_view, AuthFailClass>, 8> kClasses {{
        {"unknown_agent", AuthFailClass::UnknownAgent},
        {"stale_token", AuthFailClass::StaleToken},
        {"invalid_signature", AuthFailClass::InvalidSignature},
        {"invalid_request", AuthFailClass::InvalidRequest},
        {"enrollment_key_unavailable", AuthFailClass::EnrollmentKeyUnavailable},
        {"token_unknown", AuthFailClass::TokenUnknown},
        {"token_expired", AuthFailClass::TokenExpired},
        {"token_revoked", AuthFailClass::TokenRevoked},
    }};
} // namespace

const char* authFailClassName(AuthFailClass authClass)
{
    for (const auto& [name, value] : kClasses)
    {
        if (value == authClass)
        {
            return name.data(); // Every entry is a NUL-terminated literal.
        }
    }

    return "unclassified";
}

AuthFailClass parseAuthFailClass(std::string_view body)
{
    if (body.empty())
    {
        return AuthFailClass::Unclassified;
    }

    // Non-throwing parse (same call shape as reporterStream.cpp/controlStream.cpp): a 401 body is
    // whatever arrived on the wire, including whatever an intermediary replaced it with, so a parse
    // failure is an expected input here rather than an error to report.
    const auto document = nlohmann::json::parse(body, nullptr, false);

    if (document.is_discarded() || !document.is_object())
    {
        return AuthFailClass::Unclassified;
    }

    // Top level only. A `code` found under some other key belongs to a body this profile did not
    // send, and reading it would let an unrelated document steer the re-enrollment decision.
    const auto code = document.find("code");

    if (code == document.end() || !code->is_string())
    {
        return AuthFailClass::Unclassified;
    }

    const auto name = code->get<std::string>();

    for (const auto& [candidate, value] : kClasses)
    {
        if (candidate == name)
        {
            return value;
        }
    }

    return AuthFailClass::Unclassified;
}
