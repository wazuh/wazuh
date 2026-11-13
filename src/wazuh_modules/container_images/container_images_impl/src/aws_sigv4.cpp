/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "aws_sigv4.hpp"

#include <algorithm>
#include <cstdint>
#include <map>

#include <openssl/evp.h>

namespace
{
    constexpr auto ALGORITHM {"AWS4-HMAC-SHA256"};
    constexpr auto TERMINATOR {"aws4_request"};
    constexpr std::size_t DATE_LENGTH {8}; // yyyymmdd
    constexpr std::size_t SHA256_BYTES {32};

    std::string toHex(const unsigned char* data, const std::size_t size)
    {
        constexpr auto DIGITS {"0123456789abcdef"};
        std::string hex;
        hex.reserve(size * 2);

        for (std::size_t index = 0; index < size; ++index)
        {
            hex.push_back(DIGITS[data[index] >> 4]);
            hex.push_back(DIGITS[data[index] & 0x0F]);
        }

        return hex;
    }

    /// @brief RFC 3986 percent-encoding, leaving only the unreserved characters as they are.
    std::string uriEncode(const std::string& text)
    {
        constexpr auto DIGITS {"0123456789ABCDEF"};
        std::string encoded;

        for (const auto character : text)
        {
            const auto byte {static_cast<unsigned char>(character)};
            const auto unreserved {(byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                                   (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
                                   byte == '~'};

            if (unreserved)
            {
                encoded.push_back(character);
            }
            else
            {
                encoded.push_back('%');
                encoded.push_back(DIGITS[byte >> 4]);
                encoded.push_back(DIGITS[byte & 0x0F]);
            }
        }

        return encoded;
    }

    std::vector<std::string> splitOn(const std::string& text, const char separator)
    {
        std::vector<std::string> parts;
        std::string::size_type start {0};

        while (true)
        {
            const auto position {text.find(separator, start)};

            if (position == std::string::npos)
            {
                parts.push_back(text.substr(start));
                break;
            }

            parts.push_back(text.substr(start, position - start));
            start = position + 1;
        }

        return parts;
    }

    /// @brief The path with empty and dot segments resolved, then each segment encoded once.
    std::string canonicalPath(const std::string& path)
    {
        std::vector<std::string> segments;

        for (const auto& segment : splitOn(path, '/'))
        {
            if (segment.empty() || segment == ".")
            {
                continue;
            }

            if (segment == "..")
            {
                if (!segments.empty())
                {
                    segments.pop_back();
                }

                continue;
            }

            segments.push_back(segment);
        }

        std::string result;

        for (const auto& segment : segments)
        {
            result += "/" + uriEncode(segment);
        }

        if (result.empty() || (path.back() == '/' && !segments.empty()))
        {
            result += "/";
        }

        return result;
    }

    std::string canonicalQuery(const std::string& query)
    {
        std::vector<std::pair<std::string, std::string>> parameters;

        for (const auto& parameter : splitOn(query, '&'))
        {
            if (parameter.empty())
            {
                continue;
            }

            const auto separator {parameter.find('=')};

            parameters.emplace_back(uriEncode(parameter.substr(0, separator)),
                                    separator == std::string::npos ? std::string {}
                                                                   : uriEncode(parameter.substr(separator + 1)));
        }

        std::sort(parameters.begin(), parameters.end());

        std::string result;

        for (const auto& parameter : parameters)
        {
            if (!result.empty())
            {
                result += "&";
            }

            result += parameter.first + "=" + parameter.second;
        }

        return result;
    }

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

    /// @brief Trim a header value and collapse every run of blanks inside it to one space.
    std::string normalizeHeaderValue(const std::string& value)
    {
        std::string result;
        auto pendingBlank {false};

        for (const auto character : value)
        {
            if (character == ' ' || character == '\t')
            {
                pendingBlank = !result.empty();
                continue;
            }

            if (pendingBlank)
            {
                result.push_back(' ');
                pendingBlank = false;
            }

            result.push_back(character);
        }

        return result;
    }

    /// @brief Header values by lower-cased name, repeated names joined in the order sent.
    std::map<std::string, std::string> canonicalHeaders(const containerimages::aws::SigningRequest& request)
    {
        std::map<std::string, std::string> headers;

        for (const auto& header : request.headers)
        {
            auto& value {headers[lowerCase(header.first)]};

            if (!value.empty())
            {
                value += ",";
            }

            value += normalizeHeaderValue(header.second);
        }

        return headers;
    }

    /// @brief HMAC-SHA256 of @p data under @p key. Empty on failure.
    containerimages::Secret hmac(const containerimages::Secret& key, const std::string& data)
    {
        if (key.empty())
        {
            return {};
        }

        unsigned char digest[SHA256_BYTES] {};
        std::size_t length {0};

        const auto* result {EVP_Q_mac(nullptr,
                                      "HMAC",
                                      nullptr,
                                      "SHA256",
                                      nullptr,
                                      key.value().data(),
                                      key.value().size(),
                                      reinterpret_cast<const unsigned char*>(data.data()),
                                      data.size(),
                                      digest,
                                      sizeof(digest),
                                      &length)};

        if (result == nullptr || length != SHA256_BYTES)
        {
            return {};
        }

        containerimages::Secret derived {std::string {reinterpret_cast<const char*>(digest), length}};

        // The stack copy of the derived key is cleared with the same volatile writes the
        // secret type uses.
        volatile unsigned char* raw {digest};

        for (std::size_t index = 0; index < sizeof(digest); ++index)
        {
            raw[index] = 0;
        }

        return derived;
    }
} // namespace

namespace containerimages::aws
{
    std::string sha256Hex(const std::string& data)
    {
        unsigned char digest[SHA256_BYTES] {};
        std::size_t length {0};

        if (EVP_Q_digest(nullptr,
                         "SHA256",
                         nullptr,
                         data.data(),
                         data.size(),
                         digest,
                         &length) != 1 ||
            length != SHA256_BYTES)
        {
            return {};
        }

        return toHex(digest, length);
    }

    std::string signedHeaderNames(const SigningRequest& request)
    {
        std::string names;

        for (const auto& header : canonicalHeaders(request))
        {
            if (!names.empty())
            {
                names += ";";
            }

            names += header.first;
        }

        return names;
    }

    std::string canonicalRequest(const SigningRequest& request)
    {
        std::string text {request.method + "\n" + canonicalPath(request.path.empty() ? "/" : request.path) + "\n" +
                          canonicalQuery(request.query) + "\n"};

        for (const auto& header : canonicalHeaders(request))
        {
            text += header.first + ":" + header.second + "\n";
        }

        text += "\n" + signedHeaderNames(request) + "\n" + sha256Hex(request.payload);

        return text;
    }

    std::string credentialScope(const SigningRequest& request)
    {
        return request.amzDate.substr(0, DATE_LENGTH) + "/" + request.region + "/" + request.service + "/" +
               TERMINATOR;
    }

    std::string stringToSign(const SigningRequest& request, const std::string& canonicalRequestText)
    {
        return std::string {ALGORITHM} + "\n" + request.amzDate + "\n" + credentialScope(request) + "\n" +
               sha256Hex(canonicalRequestText);
    }

    Secret signingKey(const Secret& secretAccessKey, const SigningRequest& request)
    {
        if (secretAccessKey.empty() || request.amzDate.size() < DATE_LENGTH)
        {
            return {};
        }

        const Secret seed {"AWS4" + secretAccessKey.value()};
        const auto dateKey {hmac(seed, request.amzDate.substr(0, DATE_LENGTH))};
        const auto regionKey {hmac(dateKey, request.region)};
        const auto serviceKey {hmac(regionKey, request.service)};

        return hmac(serviceKey, TERMINATOR);
    }

    std::string authorizationHeader(const SigningRequest& request,
                                    const std::string& accessKeyId,
                                    const Secret& secretAccessKey)
    {
        const auto key {signingKey(secretAccessKey, request)};

        if (key.empty())
        {
            return {};
        }

        // A failed hash would otherwise be signed over as an empty string.
        const auto canonical {canonicalRequest(request)};

        if (sha256Hex(request.payload).empty() || sha256Hex(canonical).empty())
        {
            return {};
        }

        const auto toSign {stringToSign(request, canonical)};
        const auto signature {hmac(key, toSign)};

        if (signature.empty())
        {
            return {};
        }

        return std::string {ALGORITHM} + " Credential=" + accessKeyId + "/" + credentialScope(request) +
               ", SignedHeaders=" + signedHeaderNames(request) + ", Signature=" +
               toHex(reinterpret_cast<const unsigned char*>(signature.value().data()), signature.value().size());
    }

    std::string formatAmzDate(const std::chrono::system_clock::time_point time)
    {
        const auto seconds {std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count()};

        // Days since 1970-01-01 to a civil date: the proleptic Gregorian calendar
        // arithmetic from Howard Hinnant's date algorithms, which needs no time zone
        // database and no library call that differs between POSIX and Windows.
        auto days {seconds / 86400};
        auto secondsOfDay {seconds % 86400};

        if (secondsOfDay < 0)
        {
            secondsOfDay += 86400;
            --days;
        }

        days += 719468;
        const auto era {(days >= 0 ? days : days - 146096) / 146097};
        const auto dayOfEra {static_cast<std::int64_t>(days - era * 146097)};
        const auto yearOfEra {(dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365};
        const auto dayOfYear {dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)};
        const auto monthPart {(5 * dayOfYear + 2) / 153};
        const auto day {dayOfYear - (153 * monthPart + 2) / 5 + 1};
        const auto month {monthPart < 10 ? monthPart + 3 : monthPart - 9};
        const auto year {yearOfEra + era * 400 + (month <= 2 ? 1 : 0)};

        const auto pad = [](const std::int64_t value, const int width)
        {
            auto text {std::to_string(value)};

            return std::string(width > static_cast<int>(text.size()) ? width - text.size() : 0, '0') + text;
        };

        return pad(year, 4) + pad(month, 2) + pad(day, 2) + "T" + pad(secondsOfDay / 3600, 2) +
               pad((secondsOfDay % 3600) / 60, 2) + pad(secondsOfDay % 60, 2) + "Z";
    }
} // namespace containerimages::aws
