/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_ERRORS_HPP
#define _REGISTRY_ERRORS_HPP

#include <cstddef>
#include <string>

namespace containerimages
{
    /// @brief Longest server-provided text that reaches a log line.
    ///
    /// Long enough for an IAM denial that names the principal and the resource by ARN, which
    /// runs to a couple of hundred characters, and still one line a person can read.
    constexpr std::size_t MAX_REASON_LENGTH {480};

    /// @brief Make text that arrived from a server safe for one log line.
    ///
    /// Only printable ASCII survives, the length is capped, and text that looks like an
    /// echoed request (an authorization header, a credential scope, a signature, an access
    /// key id, a long token) is withheld entirely rather than trimmed, because a partial echo is still one.
    ///
    /// @return The cleaned text, or an empty string when it was withheld.
    std::string sanitizeServerText(const std::string& text, std::size_t maxLength = MAX_REASON_LENGTH);

    /// @brief The reason in an OCI registry error body, `{"errors":[{"code","message"}]}`.
    /// @return `CODE: message` cleaned for logging, or an empty string when the body names none.
    std::string registryErrorReason(const std::string& body);

    /// @brief True when a registry error body carries the code `DENIED`.
    ///
    /// What a private ECR registry answers when the credential is valid and not permitted,
    /// as well as when the token is bad: the two are told apart by registryRefusesTheToken.
    bool registryDenies(const std::string& body);

    /// @brief True when a registry error body says the token itself was refused.
    ///
    /// An invalid or expired token, as opposed to a credential that is valid and not allowed
    /// to do what was asked. Only the first can be put right by asking for a new token, and
    /// the second would cost a signed AWS call for nothing.
    bool registryRefusesTheToken(const std::string& body);

    /// @brief A failed AWS API call, reduced to what is safe to log.
    struct AwsApiFailure
    {
        std::string reason;     ///< A fixed sentence chosen by this module, plus the sanitised error type.
        long retryStatus {0};   ///< HTTP status to evaluate the retry policy with.
        bool clockSkew {false}; ///< True when the failure says the agent clock is off.
    };

    /// @brief Map an AWS JSON error response, `{"__type","message"}`, to a failure.
    ///
    /// The server's own message is never copied into the result. AWS messages for signed
    /// calls may echo the canonical request or the caller's ARN, so only the error type
    /// is taken from the body, whitelisted, and the sentence is this module's.
    AwsApiFailure describeAwsApiFailure(long status, const std::string& body);
} // namespace containerimages

#endif // _REGISTRY_ERRORS_HPP
