/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_errors.hpp"

#include "oci_metadata.hpp"

#include <algorithm>
#include <array>

namespace
{
    constexpr std::size_t MAX_ERROR_TYPE_LENGTH {64};
    constexpr std::size_t MAX_ERROR_CODE_LENGTH {40};
    constexpr std::size_t MAX_TOKEN_RUN {64};

    std::string lowerCase(std::string text)
    {
        std::transform(text.begin(),
                       text.end(),
                       text.begin(),
                       [](const unsigned char character)
        {
            return static_cast<char>(character >= 'A' && character <= 'Z' ? character + ('a' - 'A') : character);
        });

        return text;
    }

    /// @brief True when @p character could belong to an unbroken token, key or signature.
    ///
    /// Separators that ordinary text and identifiers use ('/', '-', '_', '.', ':') end a run,
    /// so a long repository path or an ARN is not mistaken for a credential.
    bool isTokenCharacter(const char character)
    {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '+' || character == '=';
    }

    /// @brief True when a text is quoting a request or a credential rather than describing a failure.
    ///
    /// Fragments of an echoed header or canonical request, an access key id, or a long
    /// unbroken run of token characters, which is what a bearer token, a signature or a
    /// base64 secret looks like. An ARN is an identifier and not a credential, so it passes:
    /// an IAM denial names the principal and the resource, and that is the reason.
    bool looksLikeAnEchoedRequest(const std::string& text)
    {
        static const std::array<const char*, 7> MARKERS {"authorization:",
                                                         "authorization=",
                                                         "credential=",
                                                         "signature=",
                                                         "aws4-hmac",
                                                         "x-amz-",
                                                         "canonical request"};

        const auto lowered {lowerCase(text)};

        if (std::any_of(MARKERS.begin(),
                        MARKERS.end(),
                        [&lowered](const char* marker) { return lowered.find(marker) != std::string::npos; }))
        {
            return true;
        }

        if (text.find("AKIA") != std::string::npos || text.find("ASIA") != std::string::npos)
        {
            return true;
        }

        std::size_t run {0};

        for (const auto character : text)
        {
            run = isTokenCharacter(character) ? run + 1 : 0;

            if (run >= MAX_TOKEN_RUN)
            {
                return true;
            }
        }

        return false;
    }

    /// @brief An identifier taken from a server: letters, digits, '_' and '-', capped.
    std::string identifier(const std::string& text, const std::size_t maxLength)
    {
        const auto allowed = [](const char character)
        {
            return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '_' || character == '-';
        };

        if (text.empty() || text.size() > maxLength || !std::all_of(text.begin(), text.end(), allowed))
        {
            return {};
        }

        return text;
    }

    bool contains(const std::string& text, const char* fragment)
    {
        return lowerCase(text).find(fragment) != std::string::npos;
    }
} // namespace

namespace containerimages
{
    std::string sanitizeServerText(const std::string& text, const std::size_t maxLength)
    {
        if (looksLikeAnEchoedRequest(text))
        {
            return {};
        }

        std::string cleaned;

        for (const auto character : text)
        {
            const auto byte {static_cast<unsigned char>(character)};

            if (byte < 0x20 || byte > 0x7E || byte == ' ')
            {
                // Control characters and anything outside ASCII, so a body cannot start a
                // second log line or smuggle terminal escapes. A run of them is one space.
                if (!cleaned.empty() && cleaned.back() != ' ')
                {
                    cleaned.push_back(' ');
                }

                continue;
            }

            cleaned.push_back(character);
        }

        while (!cleaned.empty() && cleaned.back() == ' ')
        {
            cleaned.pop_back();
        }

        if (cleaned.size() > maxLength)
        {
            cleaned.resize(maxLength);
            cleaned += "...";
        }

        return cleaned;
    }

    bool registryDenies(const std::string& body)
    {
        const nlohmann::json errors = oci::arrayField(oci::parseJson(body), "errors");

        return !errors.empty() && errors.front().is_object() && oci::stringField(errors.front(), "code") == "DENIED";
    }

    bool registryRefusesTheToken(const std::string& body)
    {
        const nlohmann::json errors = oci::arrayField(oci::parseJson(body), "errors");

        if (errors.empty() || !errors.front().is_object())
        {
            return false;
        }

        auto message {lowerCase(oci::stringField(errors.front(), "message"))};

        // An IAM denial names the principal and the resource, and a repository or a user may
        // be called anything, "token-service" or "expiry-job" included. What is matched is
        // what the registry says about the token, so the ARNs are taken out first and nothing
        // from " on resource" on is read.
        for (auto arn = message.find("arn:"); arn != std::string::npos; arn = message.find("arn:"))
        {
            const auto end {message.find_first_of(" \t", arn)};
            message.erase(arn, end == std::string::npos ? std::string::npos : end - arn);
        }

        const auto resource {message.find(" on resource")};

        if (resource != std::string::npos)
        {
            message.erase(resource);
        }

        // Phrases, not words: the measured answer to a token the registry did not issue is
        // "Your Authorization Token is invalid.", and an expired one is worded the same way.
        static const std::array<const char*, 9> PHRASES {"authorization token",
                                                         "token is invalid",
                                                         "token is not valid",
                                                         "token has expired",
                                                         "token is expired",
                                                         "token expired",
                                                         "invalid token",
                                                         "expired token",
                                                         "token invalid"};

        return std::any_of(PHRASES.begin(),
                           PHRASES.end(),
                           [&message](const char* phrase) { return message.find(phrase) != std::string::npos; });
    }

    std::string registryErrorReason(const std::string& body)
    {
        // Initialized with '=', never braces: a braced nlohmann::json wraps its single
        // element in an array.
        const nlohmann::json errors = oci::arrayField(oci::parseJson(body), "errors");

        if (errors.empty() || !errors.front().is_object())
        {
            return {};
        }

        const auto code {identifier(oci::stringField(errors.front(), "code"), MAX_ERROR_CODE_LENGTH)};
        const auto message {sanitizeServerText(oci::stringField(errors.front(), "message"))};

        if (code.empty())
        {
            return message;
        }

        return message.empty() ? code : code + ": " + message;
    }

    AwsApiFailure describeAwsApiFailure(const long status, const std::string& body)
    {
        const nlohmann::json document = oci::parseJson(body);
        auto type {oci::stringField(document, "__type")};

        // The type may be namespaced, "com.amazon.coral.service#ThrottlingException".
        const auto hash {type.rfind('#')};

        if (hash != std::string::npos)
        {
            type = type.substr(hash + 1);
        }

        type = identifier(type, MAX_ERROR_TYPE_LENGTH);

        // Read for classification only. It is never copied into the result.
        auto message {oci::stringField(document, "message")};

        if (message.empty())
        {
            message = oci::stringField(document, "Message");
        }

        const auto suffix {type.empty() ? std::string {} : " (" + type + ")"};

        AwsApiFailure failure;
        failure.retryStatus = status;

        if (contains(type, "throttl") || status == 429)
        {
            failure.retryStatus = 429;
            failure.reason = "AWS throttled the request" + suffix;
        }
        else if (contains(type, "requestexpired") || contains(type, "timetooskewed") ||
                 contains(message, "signature expired") || contains(message, "not yet current") ||
                 contains(message, "is now earlier than") || contains(message, "request is not yet valid"))
        {
            failure.clockSkew = true;
            failure.reason = "AWS refused the signature because the agent clock differs too much from AWS time, "
                             "so the system time has to be corrected" + suffix;
        }
        else if (contains(type, "unrecognizedclient") || contains(type, "invalidclienttokenid") ||
                 contains(type, "invalidaccesskeyid"))
        {
            failure.reason = "AWS does not accept the access key id" + suffix;
        }
        else if (contains(type, "invalidsignature") || contains(type, "signaturedoesnotmatch"))
        {
            failure.reason = "AWS rejected the signature, so the secret access key does not match the access key id" +
                             suffix;
        }
        else if (contains(type, "accessdenied"))
        {
            failure.reason = "the credential is not allowed to request a registry authorization token" + suffix;
        }
        else if (contains(type, "missingauthenticationtoken") || contains(type, "incompletesignature"))
        {
            failure.reason = "AWS did not accept the request signature" + suffix;
        }
        else
        {
            failure.reason = "AWS answered " + std::to_string(status) + suffix;
        }

        return failure;
    }
} // namespace containerimages
