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
parsec::Parser<json::Json> getLiteralParser(std::string name, Stop, Options lst)
{
    if (lst.size() != 1)
    {
        throw(std::runtime_error("Literal parser requires exactly one option"));
    }

    return [literal = lst[0], name](std::string_view txt, size_t idx)
    {
        auto eof = internal::eofError<json::Json>(txt, idx);
        if (eof.has_value())
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Expected literal '{}' but found 'EOF'", name, literal),
                idx);
        }

        if (txt.substr(idx, literal.size()) == literal)
        {
            return parsec::makeSuccess<json::Json>({}, idx + literal.size());
        }
        else
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Expected literal '{}'", name, literal), idx);
        }
    };
}
} // namespace hlp
