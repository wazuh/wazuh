/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ECR_TOKEN_CLIENT_HPP
#define _ECR_TOKEN_CLIENT_HPP

#include "credential_provider.hpp"
#include "registry_transport.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief What a request for a private ECR registry token produced.
    struct EcrTokenResult
    {
        bool ok {false};
        Secret token;                                   ///< The value sent as `Authorization: Basic <token>`.
        std::chrono::system_clock::time_point expiresAt; ///< When the token stops working.
        long status {0};     ///< HTTP status, or @ref TRANSPORT_FAILURE, for the retry policy.
        std::string retryAfter; ///< The `Retry-After` header AWS sent, empty when it sent none.

        /// False when no call was made or none was answered, and another attempt would fail the
        /// same way: a certificate that does not verify, a URL that is not usable.
        bool retryable {true};
        std::string reason;  ///< Why it failed, safe to log. Never carries a credential.
    };

    /// @brief Source of the token a private ECR registry accepts.
    ///
    /// The reader depends on this rather than on AWS, so the reader's tests stub it and
    /// the signed call is covered where it lives.
    class IEcrTokenSource
    {
        public:
            virtual ~IEcrTokenSource() = default;

            /// @param region          Region the request is signed for and sent to.
            /// @param dnsSuffix       "amazonaws.com" or "amazonaws.com.cn".
            /// @param accessKeyId     The AWS access key id.
            /// @param secretAccessKey The AWS secret access key.
            virtual EcrTokenResult fetch(const std::string& region,
                                         const std::string& dnsSuffix,
                                         const Secret& accessKeyId,
                                         const Secret& secretAccessKey) = 0;
    };

    /// @brief A signed POST, as built for the transport.
    struct EcrPostRequest
    {
        std::string url;
        std::vector<std::string> headers; ///< Includes the `Authorization` header.
        std::string body;
    };

    /// @brief Build the signed `GetAuthorizationToken` request.
    ///
    /// Pure, so a fixed time gives a fixed request. The endpoint is built only from a
    /// region and a suffix that passed validation, never from text of any other origin.
    ///
    /// @return False, with @p error, when the region or the suffix is not valid or the
    ///         signature cannot be computed.
    bool buildGetAuthorizationTokenRequest(const std::string& region,
                                           const std::string& dnsSuffix,
                                           const Secret& accessKeyId,
                                           const Secret& secretAccessKey,
                                           std::chrono::system_clock::time_point now,
                                           EcrPostRequest& request,
                                           std::string& error);

    /// @brief Read the answer to `GetAuthorizationToken`.
    ///
    /// @param response The HTTP response.
    /// @param now      The current time, used when the answer carries no expiry.
    EcrTokenResult parseGetAuthorizationTokenResponse(const HttpResponse& response,
                                                      std::chrono::system_clock::time_point now);

    /// @brief Obtains a private ECR registry token by calling AWS with a signed request.
    class EcrTokenClient final : public IEcrTokenSource
    {
        public:
            using PostFunction = std::function<bool(const EcrPostRequest&, HttpResponse&, std::string&)>;
            using Clock = std::function<std::chrono::system_clock::time_point()>;

            /// @param post  Sends one request. Replaceable, so the client is testable
            ///              without a network.
            /// @param clock Source of the signing time. Replaceable for a fixed-time test.
            explicit EcrTokenClient(PostFunction post, Clock clock = [] { return std::chrono::system_clock::now(); });

            /// @brief A client that posts over libcurl with the given transport settings.
            static std::unique_ptr<EcrTokenClient> overCurl(const TransportConfig& config);

            EcrTokenResult fetch(const std::string& region,
                                 const std::string& dnsSuffix,
                                 const Secret& accessKeyId,
                                 const Secret& secretAccessKey) override;

        private:
            PostFunction m_post;
            Clock m_clock;
    };
} // namespace containerimages

#endif // _ECR_TOKEN_CLIENT_HPP
