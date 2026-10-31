/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentCodingGuard.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace
{
    constexpr std::string_view SPACE {" \t\r\n"};

    std::string_view trimmed(std::string_view text)
    {
        const auto begin = text.find_first_not_of(SPACE);
        return begin == std::string_view::npos ? std::string_view {} :
               text.substr(begin, text.find_last_not_of(SPACE) - begin + 1);
    }

    /// Codings are case-insensitive tokens (RFC 9110 8.4.1).
    bool sameCoding(std::string_view left, std::string_view right)
    {
        return std::equal(left.begin(), left.end(), right.begin(), right.end(), [](char a, char b)
        {
            return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        });
    }

    /// Calls `visit` with every non-empty coding of a comma-separated list, until it returns false.
    /// @return false if `visit` did.
    template<typename Visit>
    bool everyCoding(std::string_view list, Visit visit)
    {
        for (;;)
        {
            const auto comma = list.find(',');
            const auto coding = trimmed(list.substr(0, comma));

            if (!coding.empty() && !visit(coding))
            {
                return false;
            }

            if (comma == std::string_view::npos)
            {
                return true;
            }

            list.remove_prefix(comma + 1);
        }
    }
} // namespace

ContentCodingGuard::ContentCodingGuard(std::string offered)
    : m_offered(std::move(offered))
{
}

bool ContentCodingGuard::admit(std::string_view value)
{
    const bool admitted = everyCoding(value, [this](std::string_view coding)
    {
        return admitCoding(coding);
    });

    if (!admitted)
    {
        m_refused = std::string {trimmed(value)};
    }

    return admitted;
}

const std::string& ContentCodingGuard::refused() const
{
    return m_refused;
}

bool ContentCodingGuard::admitCoding(std::string_view coding)
{
    return sameCoding(coding, "identity") || (offers(coding) && ++m_codings == 1);
}

bool ContentCodingGuard::offers(std::string_view coding) const
{
    return !everyCoding(m_offered, [coding](std::string_view offered)
    {
        return !sameCoding(offered, coding);
    });
}
