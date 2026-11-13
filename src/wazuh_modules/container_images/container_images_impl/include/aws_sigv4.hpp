/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AWS_SIGV4_HPP
#define _AWS_SIGV4_HPP

#include "credential_provider.hpp"

#include <chrono>
#include <string>
#include <utility>
#include <vector>

namespace containerimages::aws
{
    /// @brief One request, as the signature sees it.
    ///
    /// General on purpose: method, path, query, headers and payload are all inputs, so
    /// the signer runs unmodified against the reference cases AWS publishes for the
    /// algorithm. The one request this module signs is a single caller of it.
    struct SigningRequest
    {
        std::string method;
        std::string path;  ///< Request path as sent, not percent-encoded. Empty means "/".
        std::string query; ///< Query string without the '?', parameters not percent-encoded.

        /// Every header that is sent and signed, in the order they are sent. Must include
        /// "host". The names may be in any case, and a name may repeat.
        std::vector<std::pair<std::string, std::string>> headers;

        std::string payload;
        std::string region;
        std::string service;
        std::string amzDate; ///< `yyyymmddThhmmssZ`, the value of the `x-amz-date` header.
    };

    /// @brief The signature's step 1: the canonical request.
    std::string canonicalRequest(const SigningRequest& request);

    /// @brief Names of the signed headers, lower-cased and sorted, joined with ';'.
    std::string signedHeaderNames(const SigningRequest& request);

    /// @brief The credential scope: `yyyymmdd/region/service/aws4_request`.
    std::string credentialScope(const SigningRequest& request);

    /// @brief The signature's step 2: the string to sign.
    std::string stringToSign(const SigningRequest& request, const std::string& canonicalRequestText);

    /// @brief The signing key derived from the secret access key for one scope.
    Secret signingKey(const Secret& secretAccessKey, const SigningRequest& request);

    /// @brief The value of the `Authorization` header.
    ///
    /// The result carries the access key id in clear and a signature derived from the
    /// secret, so it is never logged. Empty when a cryptographic primitive fails.
    std::string authorizationHeader(const SigningRequest& request,
                                    const std::string& accessKeyId,
                                    const Secret& secretAccessKey);

    /// @brief Lower-case hexadecimal SHA-256 of @p data. Empty on failure.
    std::string sha256Hex(const std::string& data);

    /// @brief Format a time as `yyyymmddThhmmssZ`, in UTC.
    ///
    /// Computed from the epoch rather than through gmtime_r or gmtime_s, which differ
    /// between POSIX and Windows and this module is built for both.
    std::string formatAmzDate(std::chrono::system_clock::time_point time);
} // namespace containerimages::aws

#endif // _AWS_SIGV4_HPP
