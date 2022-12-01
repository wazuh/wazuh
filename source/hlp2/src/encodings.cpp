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

inline bool is_valid_base64_char(char c)
{
    if ((c >= 'A') && (c <= 'Z'))
    {
        return true;
    }

    if ((c >= 'a') && ('z'))
    {
        return true;
    }

    if ((c >= '0') && (c <= '9'))
    {
        return true;
    }

    if ((c == '+') || (c == '/'))
    {
        return true;
    }

    return false;
}

namespace hlp
{

parsec::Parser<json::Json> getBinaryParser(Stop, Options lst)
{
    if (!lst.empty())
    {
        throw std::runtime_error("binary parser doesn't accept parameters");
    }

    return [](std::string_view text, int index)
    {
        auto error = internal::eofError<json::Json>(text, index);
        if (error.has_value())
        {
            return error.value();
        }

        auto end = std::find_if(std::begin(text) + index,
                                std::end(text),
                                [](char c) { return !is_valid_base64_char(c); });

        auto endPos = end - std::begin(text);
        if (endPos == index)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Invalid base64 char '{}' found at '{}'", *end, endPos),
                text,
                endPos);
        }
        // consume up to two '=' padding chars
        if (*end == '=')
        {
            ++endPos;
            auto nx = std::next(end);
            if (*nx == '=')
                ++endPos;
        }

        if ((endPos % 4) != 0)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Wrong string size '{}' for base64 from offset {} to {}",
                            endPos,
                            index,
                            endPos),
                text,
                endPos);
        }
        json::Json doc;
        // copy can be slow
        doc.setString(std::string {text.substr(index, endPos)});
        return parsec::makeSuccess<json::Json>(doc, text, endPos);
    };
}
} // namespace hlp
