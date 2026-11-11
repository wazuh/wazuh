/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "headerField.hpp"

#include <algorithm>
#include <cctype>

bool sameToken(std::string_view left, std::string_view right) noexcept
{
    return std::equal(left.begin(), left.end(), right.begin(), right.end(), [](char a, char b)
    {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    });
}

std::optional<std::string_view> headerValue(std::string_view line, std::string_view name) noexcept
{
    const size_t colon = name.size();

    if (line.size() <= colon + 1 || line[colon] != ':' || !sameToken(line.substr(0, colon), name))
    {
        return std::nullopt;
    }

    return line.substr(colon + 1);
}
