#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{
parsec::Parser<json::Json> getLiteralParser(Stop, Options lst)
{
    if (lst.size() != 1)
    {
        throw(std::runtime_error("Literal parser requires exactly one option"));
    }

    return [literal = lst[0]](std::string_view txt, size_t idx)
    {
        auto eof = internal::eofError<json::Json>(txt, idx);
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
