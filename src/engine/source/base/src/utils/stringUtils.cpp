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

} // namespace base::utils::string
