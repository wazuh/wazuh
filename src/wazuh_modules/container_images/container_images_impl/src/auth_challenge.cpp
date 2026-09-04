/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "auth_challenge.hpp"

#include <algorithm>
#include <cctype>

namespace
{
    const std::string HTTPS_PREFIX {"https://"};

    std::string lowered(std::string value)
    {
        std::transform(value.begin(),
                       value.end(),
                       value.begin(),
                       [](const unsigned char character) { return static_cast<char>(std::tolower(character)); });

        return value;
    }

    bool isSpace(const char character)
    {
        return character == ' ' || character == '\t' || character == '\r' || character == '\n';
    }

    std::string trimmed(const std::string& value)
    {
        auto first {value.begin()};
        auto last {value.end()};

        while (first != last && isSpace(*first))
        {
            ++first;
        }

        while (last != first && isSpace(*(last - 1)))
        {
            --last;
        }

        return std::string {first, last};
    }
} // namespace

namespace containerimages
{
    std::string percentEncode(const std::string& value)
    {
        static constexpr char DIGITS[] = "0123456789ABCDEF";

        std::string encoded;
        encoded.reserve(value.size());

        for (const auto character : value)
        {
            const auto byte {static_cast<unsigned char>(character)};

            // The unreserved set of RFC 3986. Everything else is escaped, which includes
            // '&', '=', '?' and '#', so a value can never add a parameter to the URL it
            // is placed in. ':' and '/' appear in a scope and are escaped too, which
            // registries accept.
            const auto unreserved {(byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
                                   (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.' ||
                                   byte == '~'};

            if (unreserved)
            {
                encoded.push_back(static_cast<char>(byte));
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

    bool parseAuthChallenge(const std::string& header, AuthChallenge& challenge)
    {
        challenge = {};

        const auto value {trimmed(header)};

        if (value.empty())
        {
            return false;
        }

        // The scheme is the first token, separated from the parameters by whitespace.
        const auto schemeEnd {value.find_first_of(" \t")};
        challenge.scheme = lowered(value.substr(0, schemeEnd));

        if (challenge.scheme.empty())
        {
            return false;
        }

        if (schemeEnd == std::string::npos)
        {
            // A scheme with no parameters, such as a bare "Basic".
            return true;
        }

        // Walk the parameter list one character at a time, tracking whether a quoted
        // string is open. Splitting on ',' first would cut a value that contains one,
        // and a scope legitimately can.
        const auto parameters {value.substr(schemeEnd + 1)};

        std::string name;
        std::string current;
        bool inQuotes {false};
        bool escaped {false};
        bool readingName {true};

        const auto commit = [&challenge, &name, &current, &readingName]()
        {
            const auto trimmedName {lowered(trimmed(name))};

            if (!trimmedName.empty())
            {
                challenge.parameters[trimmedName] = trimmed(current);
            }

            name.clear();
            current.clear();
            readingName = true;
        };

        for (const auto character : parameters)
        {
            if (escaped)
            {
                current.push_back(character);
                escaped = false;
                continue;
            }

            if (inQuotes)
            {
                if (character == '\\')
                {
                    escaped = true;
                }
                else if (character == '"')
                {
                    inQuotes = false;
                }
                else
                {
                    current.push_back(character);
                }

                continue;
            }

            if (character == '"')
            {
                inQuotes = true;
            }
            else if (character == '=' && readingName)
            {
                readingName = false;
            }
            else if (character == ',')
            {
                commit();
            }
            else if (readingName)
            {
                name.push_back(character);
            }
            else
            {
                current.push_back(character);
            }
        }

        commit();

        return true;
    }

    std::string tokenRequestUrl(const AuthChallenge& challenge, const std::string& scope)
    {
        const auto realm {challenge.realm()};

        // The realm comes from a response header, so it decides which host the module
        // sends a credential to. Anything but an https URL is refused: a plain http realm
        // would send the credential in clear, and any other scheme is not a realm at all.
        if (realm.size() <= HTTPS_PREFIX.size() || realm.compare(0, HTTPS_PREFIX.size(), HTTPS_PREFIX) != 0)
        {
            return {};
        }

        if (realm.find_first_of("\r\n") != std::string::npos)
        {
            return {};
        }

        auto url {realm};
        auto separator {url.find('?') == std::string::npos ? '?' : '&'};

        const auto service {challenge.service()};

        if (!service.empty())
        {
            url += separator;
            url += "service=" + percentEncode(service);
            separator = '&';
        }

        const auto requested {scope.empty() ? challenge.scope() : scope};

        if (!requested.empty())
        {
            url += separator;
            url += "scope=" + percentEncode(requested);
        }

        return url;
    }
} // namespace containerimages
