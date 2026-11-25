/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "os_release_parser.hpp"

#include <cstdint>
#include <map>
#include <sstream>
#include <string>

namespace
{
    constexpr auto WHITESPACE {" \t\r"};

    std::string trim(const std::string& text)
    {
        const auto first {text.find_first_not_of(WHITESPACE)};

        if (first == std::string::npos)
        {
            return {};
        }

        return text.substr(first, text.find_last_not_of(WHITESPACE) - first + 1);
    }

    /// @brief Remove the quotes of a value, and a comment that follows the closing quote.
    /// Inside double quotes a backslash escapes the next character, inside single quotes
    /// nothing is escaped. A value that is not closed as written is returned as it is.
    std::string unquote(const std::string& value)
    {
        if (value.empty() || (value.front() != '"' && value.front() != '\''))
        {
            return value;
        }

        const auto quote {value.front()};
        std::string inner;
        std::size_t closing {std::string::npos};

        for (std::size_t i = 1; i < value.size(); ++i)
        {
            if (value[i] == quote)
            {
                closing = i;
                break;
            }

            if (quote == '"' && value[i] == '\\' && i + 1 < value.size())
            {
                ++i;
            }

            inner.push_back(value[i]);
        }

        if (closing == std::string::npos)
        {
            return value;
        }

        const auto rest {trim(value.substr(closing + 1))};

        return rest.empty() || rest.front() == '#' ? inner : value;
    }

    /// @brief Replace every byte sequence that is not valid UTF-8 with U+FFFD.
    ///
    /// The values come from a file the image controls, and they end up in JSON, which
    /// refuses text that is not UTF-8.
    std::string validUtf8(const std::string& text)
    {
        static const std::string REPLACEMENT {"\xEF\xBF\xBD"};
        std::string result;

        for (std::size_t i = 0; i < text.size();)
        {
            const auto lead {static_cast<unsigned char>(text[i])};
            std::size_t length {0};
            std::uint32_t lowest {0};
            std::uint32_t codePoint {lead};

            if (lead < 0x80)
            {
                length = 1;
            }
            else if (lead >= 0xC2 && lead <= 0xDF)
            {
                length = 2;
                lowest = 0x80;
                codePoint = lead & 0x1FU;
            }
            else if (lead >= 0xE0 && lead <= 0xEF)
            {
                length = 3;
                lowest = 0x800;
                codePoint = lead & 0x0FU;
            }
            else if (lead >= 0xF0 && lead <= 0xF4)
            {
                length = 4;
                lowest = 0x10000;
                codePoint = lead & 0x07U;
            }

            bool valid {length > 0 && i + length <= text.size()};

            for (std::size_t offset = 1; valid && offset < length; ++offset)
            {
                const auto next {static_cast<unsigned char>(text[i + offset])};
                valid = (next & 0xC0) == 0x80;
                codePoint = (codePoint << 6) | (next & 0x3FU);
            }

            // Overlong forms, surrogates and values past U+10FFFF are not UTF-8 either.
            valid = valid && codePoint >= lowest && codePoint <= 0x10FFFF &&
                    (codePoint < 0xD800 || codePoint > 0xDFFF);

            if (valid)
            {
                result.append(text, i, length);
                i += length;
            }
            else
            {
                result += REPLACEMENT;
                ++i;
            }
        }

        return result;
    }

    std::string firstWord(const std::string& words)
    {
        const auto start {words.find_first_not_of(WHITESPACE)};

        if (start == std::string::npos)
        {
            return {};
        }

        return words.substr(start, words.find_first_of(WHITESPACE, start) - start);
    }
} // namespace

namespace containerimages
{
    const std::vector<std::string>& osReleasePaths()
    {
        static const std::vector<std::string> PATHS {"etc/os-release", "usr/lib/os-release"};

        return PATHS;
    }

    ImageOperatingSystem parseOsRelease(const std::string& content)
    {
        std::map<std::string, std::string> values;
        // A byte order mark would hide the first key.
        static const std::string BOM {"\xEF\xBB\xBF"};
        std::istringstream stream {content.compare(0, BOM.size(), BOM) == 0 ? content.substr(BOM.size()) : content};
        std::string line;

        while (std::getline(stream, line))
        {
            const auto text {trim(line)};
            const auto separator {text.find('=')};

            if (text.empty() || text.front() == '#' || separator == std::string::npos || separator == 0)
            {
                continue;
            }

            values[text.substr(0, separator)] = unquote(trim(text.substr(separator + 1)));
        }

        const auto valueOf = [&values](const char* key)
        {
            const auto value {values.find(key)};

            if (value == values.end())
            {
                return std::string {};
            }

            return validUtf8(value->second);
        };

        ImageOperatingSystem os;
        os.name = valueOf("NAME");
        os.version = valueOf("VERSION_ID");
        os.id = valueOf("ID");
        os.family = firstWord(valueOf("ID_LIKE"));
        os.codename = valueOf("VERSION_CODENAME");
        os.prettyName = valueOf("PRETTY_NAME");

        return os;
    }
} // namespace containerimages
