/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ecr_token_client.hpp"

#include "aws_sigv4.hpp"
#include "oci_metadata.hpp"
#include "registry_errors.hpp"
#include "registry_profile.hpp"
#include "retry_policy.hpp"

#include <algorithm>
#include <utility>

namespace
{
    constexpr auto SERVICE {"ecr"};
    constexpr auto TARGET {"AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"};
    constexpr auto CONTENT_TYPE {"application/x-amz-json-1.1"};
    constexpr std::size_t MAX_TOKEN_LENGTH {8192};

    /// @brief True when @p token is base64, the only thing a Basic header can carry here.
    ///
    /// The value goes into a request header, so anything else, a line break above all,
    /// is refused rather than passed on.
    bool isBase64(const std::string& token)
    {
        return !token.empty() && token.size() <= MAX_TOKEN_LENGTH &&
               std::all_of(token.begin(),
                           token.end(),
                           [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '+' || character == '/' ||
                   character == '=';
        });
    }

    /// @brief True when @p keyId has the shape of an access key id: letters and digits only.
    ///
    /// It goes into the `Credential=` field of a header, so a stored value with a trailing
    /// blank, a comma or a quote must not reach it. Not echoed anywhere when it is refused.
    bool isWellFormedAccessKeyId(const std::string& keyId)
    {
        return !keyId.empty() && keyId.size() <= 128 &&
               std::all_of(keyId.begin(),
                           keyId.end(),
                           [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9');
        });
    }

    /// @brief Latest expiry accepted from AWS, 9999-12-31T23:59:59Z, so the conversion below cannot overflow.
    constexpr double MAX_EXPIRY_SECONDS {253402300799.0};

    bool contains(const std::string& text, const std::string& fragment)
    {
        return !fragment.empty() && text.find(fragment) != std::string::npos;
    }

    void scrubRequest(containerimages::EcrPostRequest& request)
    {
        for (auto& header : request.headers)
        {
            containerimages::scrubString(header);
        }

        request.headers.clear();
    }
} // namespace

namespace containerimages
{
    bool buildGetAuthorizationTokenRequest(const std::string& region,
                                           const std::string& dnsSuffix,
                                           const Secret& accessKeyId,
                                           const Secret& secretAccessKey,
                                           const std::chrono::system_clock::time_point now,
                                           EcrPostRequest& request,
                                           std::string& error)
    {
        request = {};
        error.clear();

        if (!isValidAwsRegion(region))
        {
            // The region is configuration, not a secret, and the message has to say which one.
            const auto shown {sanitizeServerText(region, 40)};
            error = "the AWS region" + (shown.empty() ? std::string {} : " '" + shown + "'") +
                    " is not valid, so nothing was sent";
            return false;
        }

        if (!isSupportedAwsDnsSuffix(dnsSuffix))
        {
            error = "the AWS domain is not valid, so nothing was sent";
            return false;
        }

        if (!isWellFormedAccessKeyId(accessKeyId.value()))
        {
            error = "the stored access key id is not well-formed, so nothing was sent";
            return false;
        }

        const auto host {"api.ecr." + region + "." + dnsSuffix};

        aws::SigningRequest signing;
        signing.method = "POST";
        signing.path = "/";
        signing.region = region;
        signing.service = SERVICE;
        signing.amzDate = aws::formatAmzDate(now);
        signing.payload = "{}";
        signing.headers = {{"content-type", CONTENT_TYPE},
                           {"host", host},
                           {"x-amz-date", signing.amzDate},
                           {"x-amz-target", TARGET}};

        auto authorization {aws::authorizationHeader(signing, accessKeyId.value(), secretAccessKey)};

        if (authorization.empty())
        {
            error = "the request signature could not be computed";
            return false;
        }

        request.url = "https://" + host + "/";
        request.body = signing.payload;
        request.headers = {std::string {"Content-Type: "} + CONTENT_TYPE,
                           "X-Amz-Date: " + signing.amzDate,
                           std::string {"X-Amz-Target: "} + TARGET,
                           "Authorization: " + authorization};

        scrubString(authorization);

        return true;
    }

    EcrTokenResult parseGetAuthorizationTokenResponse(const HttpResponse& response,
                                                      const std::chrono::system_clock::time_point now)
    {
        EcrTokenResult result;
        result.status = response.status;

        if (response.status < 200 || response.status > 299)
        {
            const auto failure {describeAwsApiFailure(response.status, response.body)};

            result.status = failure.retryStatus;
            result.retryAfter = response.header("retry-after");
            result.reason = failure.reason;

            return result;
        }

        // Initialized with '=', never braces: a braced nlohmann::json wraps its single
        // element in an array.
        nlohmann::json document = oci::parseJson(response.body);
        const auto data {document.find("authorizationData")};

        if (data == document.end() || !data->is_array() || data->empty() || !data->front().is_object())
        {
            result.reason = "AWS answered without an authorization token";
            return result;
        }

        auto& entry {data->front()};
        const auto token {entry.find("authorizationToken")};
        auto* tokenText {token != entry.end() ? token->get_ptr<std::string*>() : nullptr};

        if (tokenText == nullptr || !isBase64(*tokenText))
        {
            if (tokenText != nullptr)
            {
                scrubString(*tokenText);
            }

            result.reason = "AWS answered with an authorization token that is not valid";
            return result;
        }

        result.token = Secret {*tokenText};
        scrubString(*tokenText);

        // A token with no readable expiry is usable now and never cached: an expiry of
        // "now" is already inside the cache's renewal margin.
        result.expiresAt = now;

        const auto expiresAt {entry.find("expiresAt")};

        if (expiresAt != entry.end() && expiresAt->is_number())
        {
            const auto seconds {expiresAt->get<double>()};

            // Out of range, or not a number at all, is read as "no expiry": usable once and
            // never cached, rather than converted into an undefined time.
            if (seconds >= 0.0 && seconds <= MAX_EXPIRY_SECONDS)
            {
                result.expiresAt = std::chrono::system_clock::time_point {} +
                                   std::chrono::duration_cast<std::chrono::system_clock::duration>(
                                       std::chrono::duration<double> {seconds});
            }
        }

        result.ok = true;

        return result;
    }

    EcrTokenClient::EcrTokenClient(PostFunction post, Clock clock)
        : m_post {std::move(post)}
        , m_clock {std::move(clock)}
    {
    }

    std::unique_ptr<EcrTokenClient> EcrTokenClient::overCurl(const TransportConfig& config)
    {
        auto transport {std::make_shared<CurlRegistryTransport>(config)};

        return std::make_unique<EcrTokenClient>(
            [transport](const EcrPostRequest& request, HttpResponse& response, std::string& error)
        {
            return transport->post(request.url, request.headers, request.body, response, error);
        });
    }

    EcrTokenResult EcrTokenClient::fetch(const std::string& region,
                                         const std::string& dnsSuffix,
                                         const Secret& accessKeyId,
                                         const Secret& secretAccessKey)
    {
        // Nothing here may throw into the caller. The reader's catch-all logs what() at
        // warning level, and a message produced anywhere near the signing code is not
        // something to let reach a log.
        EcrTokenResult result;

        try
        {
            EcrPostRequest request;
            std::string error;

            if (!buildGetAuthorizationTokenRequest(region,
                                                   dnsSuffix,
                                                   accessKeyId,
                                                   secretAccessKey,
                                                   m_clock(),
                                                   request,
                                                   error))
            {
                scrubRequest(request);

                // Nothing was sent, so there is nothing to retry: the same input fails again.
                result.status = 400;
                result.retryable = false;
                result.reason = error;
                return result;
            }

            HttpResponse response;

            const auto posted {m_post(request, response, error)};

            scrubRequest(request);

            if (!posted)
            {
                result.status = TRANSPORT_FAILURE;
                result.retryable = response.retryable;
                result.reason = "the request to AWS could not be completed: " + sanitizeServerText(error);
                return result;
            }

            result = parseGetAuthorizationTokenResponse(response, m_clock());
            scrubString(response.body);

            // A final guard: whatever the reason says, it does not contain a credential.
            if (contains(result.reason, accessKeyId.value()) || contains(result.reason, secretAccessKey.value()))
            {
                result.reason = "AWS refused the request";
            }

            return result;
        }
        catch (...)
        {
            // The same input fails the same way, so it is not tried again.
            result = {};
            result.retryable = false;
            result.reason = "the request to AWS failed unexpectedly";

            return result;
        }
    }
} // namespace containerimages
