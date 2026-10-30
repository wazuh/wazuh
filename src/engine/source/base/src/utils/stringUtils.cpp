// SPDX-License-Identifier: AGPL-3.0-or-later
#include "utils/stringUtils.hpp"

namespace base::utils::string
{

std::vector<std::string> split(std::string_view str, const char delimiter)
{
    std::vector<std::string> ret;
    if (!str.empty() && str[0] == delimiter)
    {
        str = str.substr(1);
    }

    while (true)
    {
        auto pos = str.find(delimiter);
        if (pos == str.npos)
        {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if (!str.empty())
    {
        ret.emplace_back(str);
    }

    return ret;
}

std::string join(const std::vector<std::string>& strVector, std::string_view separator, const bool startsWithSeparator)
{
    std::string strResult {};
    for (std::size_t i = 0; i < strVector.size(); ++i)
    {
        strResult.append((!startsWithSeparator && 0 == i) ? "" : separator);
        strResult.append(strVector.at(i));
    }

    return strResult;
}

std::vector<std::string> splitEscaped(std::string_view input, const char& splitChar, const char& escape)
{
    std::vector<std::string> splitted;
    // Add first segment
    splitted.emplace_back("");

    for (std::size_t i = 0; i < input.size(); ++i)
    {
        const auto& thisChar = input[i];
        if (thisChar == escape && i + 1 < input.size())
        {
            const auto& nextChar = input[i + 1];
            // Escape char
            if (nextChar == escape || nextChar == splitChar)
            {
                splitted.back() += nextChar;
                ++i;
            }
            else
            {
                splitted.back() += thisChar;
            }
        }
        else if (thisChar == splitChar)
        {
            // Add another segment
            splitted.push_back("");
        }
        else
        {
            splitted.back() += thisChar;
        }
    }

    return splitted;
}

std::string
unescapeString(std::string_view str, char escapeChar, const std::string& escapedChars, const bool strictMode)
{
    std::string result;
    result.reserve(str.size()); // Reserve memory upfront to avoid reallocations

    auto it = str.begin();
    while (it != str.end())
    {
        if (*it == escapeChar && std::next(it) != str.end())
        {
            char nextChar = *(std::next(it));
            if (nextChar == escapeChar || escapedChars.find(nextChar) != std::string::npos)
            {
                result += nextChar;
                ++it; // Skip the next character since it's already handled
            }
            else
            {
                result += *it;
            }
        }
        else
        {
            result += *it;
        }
        ++it;
    }

    return result;
}

std::string toUpperCase(std::string_view str)
{
    std::string temp {str};
    std::transform(std::begin(temp),
                   std::end(temp),
                   std::begin(temp),
                   [](std::string::value_type character) { return std::toupper(character); });
    return temp;
}

std::string toLowerCase(std::string_view str)
{
    std::string temp {str};
    std::transform(std::begin(temp),
                   std::end(temp),
                   std::begin(temp),
                   [](std::string::value_type character) { return std::tolower(character); });
    return temp;
}

bool replaceFirst(std::string& data, const std::string& toSearch, const std::string& toReplace)
{
    auto pos {data.find(toSearch)};
    auto ret {false};

    if (std::string::npos != pos)
    {
        data.replace(pos, toSearch.size(), toReplace);
        ret = true;
    }

    return ret;
}

std::string leftTrim(const std::string& str, const std::string& args)
{
    const auto pos {str.find_first_not_of(args)};

    if (pos != std::string::npos)
    {
        return str.substr(pos);
    }
    else
    {
        return "";
    }

    return str;
}

std::string rightTrim(const std::string& str, const std::string& args)
{
    const auto pos {str.find_last_not_of(args)};

    if (pos != std::string::npos)
    {
        return str.substr(0, pos + 1);
    }
    else
    {
        return "";
    }

    return str;
}

std::string trim(const std::string& str, const std::string& args)
{
    return leftTrim(rightTrim(str, args), args);
}

std::string toSentenceCase(const std::string& str)
{
    std::string temp;
    if (!str.empty())
    {
        temp = toLowerCase(str);
        *temp.begin() = static_cast<char>(std::toupper(*str.begin()));
    }
    return temp;
}

bool isNumber(const std::string& str)
{
    std::string::const_iterator it = str.begin();

    while (it != str.end() && std::isdigit(*it)) ++it;

    return !str.empty() && it == str.end();
}

bool replaceAll(std::string& data, const std::string_view toSearch, const std::string_view toReplace)
{
    if (toSearch.empty() || toSearch == toReplace || toReplace.find(toSearch) != std::string_view::npos)
    {
        return false; // Nothing to search for if toSearch is empty
    }

    bool found = false;

    if (size_t pos = data.find(toSearch); pos != std::string::npos)
    {
        found = true;
        data.replace(pos, toSearch.length(), toReplace);
        // Recursively call replaceAll from the new position (pos + toReplace.length())
        replaceAll(data, toSearch, toReplace);
    }

    return found;
}

bool haveUpperCaseCharacters(const std::string& str)
{
    return std::any_of(
        std::begin(str), std::end(str), [](std::string::value_type character) { return std::isupper(character); });
}

namespace
{
/**
 * @brief Decode a string of hexadecimal digit pairs into raw bytes.
 *
 * @param hex Hexadecimal digits.
 * @param upperCaseOnly When true, the letters 'a'-'f' are rejected.
 * @return std::optional<std::string> The decoded bytes, or std::nullopt on an odd length or a non hexadecimal digit.
 */
std::optional<std::string> hexToBytes(std::string_view hex, bool upperCaseOnly)
{
    if (hex.size() % 2 != 0)
    {
        return std::nullopt;
    }

    const auto hexValue = [upperCaseOnly](char c) -> int
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F')
        {
            return c - 'A' + 10;
        }
        if (!upperCaseOnly && c >= 'a' && c <= 'f')
        {
            return c - 'a' + 10;
        }
        return -1;
    };

    std::string decoded;
    decoded.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2)
    {
        const auto high = hexValue(hex[i]);
        const auto low = hexValue(hex[i + 1]);
        if (high < 0 || low < 0)
        {
            return std::nullopt;
        }
        decoded.push_back(static_cast<char>((high << 4) | low));
    }

    return decoded;
}
} // namespace

std::optional<std::string> hexToAscii(std::string_view hex)
{
    auto decoded = hexToBytes(hex, false);
    if (decoded
        && std::any_of(decoded->cbegin(), decoded->cend(), [](char c) { return static_cast<unsigned char>(c) > 0x7F; }))
    {
        return std::nullopt;
    }
    return decoded;
}

std::optional<std::string> hexToUtf8(std::string_view hex, bool upperCaseOnly)
{
    auto decoded = hexToBytes(hex, upperCaseOnly);
    if (decoded && !isValidUtf8(*decoded))
    {
        return std::nullopt;
    }
    return decoded;
}

bool isValidUtf8(std::string_view str)
{
    const auto size = str.size();
    std::size_t i = 0;
    while (i < size)
    {
        const auto lead = static_cast<unsigned char>(str[i]);
        if (lead <= 0x7F)
        {
            ++i;
            continue;
        }

        // Number of continuation bytes and the allowed range of the first one (RFC 3629: no overlong forms, no
        // surrogates, nothing above U+10FFFF)
        std::size_t continuation = 0;
        unsigned char low = 0x80;
        unsigned char high = 0xBF;
        if (lead >= 0xC2 && lead <= 0xDF)
        {
            continuation = 1;
        }
        else if (lead >= 0xE0 && lead <= 0xEF)
        {
            continuation = 2;
            low = (lead == 0xE0) ? 0xA0 : 0x80;
            high = (lead == 0xED) ? 0x9F : 0xBF;
        }
        else if (lead >= 0xF0 && lead <= 0xF4)
        {
            continuation = 3;
            low = (lead == 0xF0) ? 0x90 : 0x80;
            high = (lead == 0xF4) ? 0x8F : 0xBF;
        }
        else
        {
            return false;
        }

        if (size - i <= continuation)
        {
            return false;
        }
        for (std::size_t j = 1; j <= continuation; ++j)
        {
            const auto byte = static_cast<unsigned char>(str[i + j]);
            if (byte < low || byte > high)
            {
                return false;
            }
            low = 0x80;
            high = 0xBF;
        }
        i += continuation + 1;
    }

    return true;
}

} // namespace base::utils::string
