// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_JSON_NAME_COMPARE_HPP
#define _BASE_JSON_NAME_COMPARE_HPP

#include <algorithm>
#include <cstring>
#include <string_view>

namespace json::internal
{

// Byte order first, then length: names may contain NUL bytes.
inline int compareNames(std::string_view lhs, std::string_view rhs)
{
    const auto common = std::min(lhs.size(), rhs.size());
    if (common != 0)
    {
        const int result = std::memcmp(lhs.data(), rhs.data(), common);
        if (result != 0)
        {
            return result;
        }
    }
    if (lhs.size() == rhs.size())
    {
        return 0;
    }
    return lhs.size() < rhs.size() ? -1 : 1;
}

} // namespace json::internal

#endif // _BASE_JSON_NAME_COMPARE_HPP
