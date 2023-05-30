#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <utils/stringUtils.hpp>

namespace hlp
{

parsec::Parser<json::Json> getBetweenParser(std::string name, Stop, Options lst)
{
    if (lst.size() != 2)
    {
        throw std::runtime_error("between parser requires exactly two parameters,"
                                 " start and end substrings");
    }
    // check empty strings
    if (lst[0].empty() && lst[1].empty())
    {
        throw std::runtime_error("between parser requires non-empty start and end substrings");
    }

    auto start = lst[0];
    auto end = lst[1];

    return [name, start, end](std::string_view text, int index)
    {
        // No check Stop, because the parser will only accept the input
        // if the end substring is found. (Stop can cut the input before the end)
        auto res = internal::eofError<json::Json>(text, index);
        if (res.has_value())
        {
            return res.value();
        }

        // Check start substring
        if (text.substr(index, start.size()) != start)
        {
            return parsec::makeError<json::Json>(fmt::format("Expected '{}'", start),
                                                 index);
        }
        index += start.size();
        auto remaining = text.substr(index);

        // Find end substring in remaining text
        auto endIndex = remaining.find(end);
        if (endIndex == std::string_view::npos)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Expected '{}' at the end", end), index);
        }

        auto value = remaining.substr(0, endIndex);
        json::Json doc;

        doc.setString(std::string {value});
        index += endIndex + end.size();

        return parsec::makeSuccess<json::Json>(std::move(doc), index);
    };
}
} // namespace hlp
