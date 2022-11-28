#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/parsec.hpp>
#include <json/json.hpp>

#include "base.hpp"

namespace hlp
{
parsec::Parser<json::Json> getLiteralParser(Stop str, Options lst)
{
    if (str.has_value())
    {
        throw(std::runtime_error("Literal parser does not support stop string"));
    }

    if (lst.size() != 1)
    {
        throw(std::runtime_error("Literal parser requires exactly one option"));
    }

    return [literal = lst[0]](std::string_view txt, size_t idx)
    {
        auto eof = eofError<json::Json>(txt, idx);
        if (eof.has_value())
        {
            return eof.value();
        }

        if (txt.substr(idx, literal.size()) == literal)
        {
            return parsec::makeSuccess<json::Json>({}, txt, idx + literal.size());
        }
        else
        {
            return parsec::makeError<json::Json>(
                fmt::format("Expected '{}'", literal), txt, idx);
        }
    };
}
} // namespace hlp
