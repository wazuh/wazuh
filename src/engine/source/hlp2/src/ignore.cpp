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

namespace hlp
{

parsec::Parser<json::Json> getIgnoreParser(std::string name, Stop endTokens, Options lst)
{
    if (lst.size() != 1 || lst[0].empty())
    {
        throw std::runtime_error("Ignore parser requires exactly one parameter,"
                                 " with the string to match");
    }

    return [repeatStr = lst.at(0), name](std::string_view text, int index)
    {
        auto res = internal::eofError<json::Json>(text, index);
        if (res.has_value())
        {
            return res.value();
        }

        std::size_t repPos {0ul};
        while (index < text.size() && text[index] == repeatStr[repPos])
        {
            ++index;
            ++repPos;
            if (repPos == repeatStr.size())
            {
                repPos = 0;
            }
        }

        return parsec::makeSuccess<json::Json>({}, index);
    };
}
} // namespace hlp
