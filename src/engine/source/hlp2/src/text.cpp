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
parsec::Parser<json::Json> getTextParser(const std::string& name, const Stop& endTokens, const Options& lst)
{
    if (endTokens.empty())
    {
        throw std::runtime_error(fmt::format("Text parser needs a stop string"));
    }

    if (!lst.empty())
    {
        throw std::runtime_error("text parser doesn't accept parameters");
    }

    return [endTokens, name](std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);
        auto pos = fp.size() + index;
        if (pos == index)
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Nothing to parse", name), pos);
        }

        json::Json doc;
        // copy can be slow
        doc.setString(std::string {fp});
        return parsec::makeSuccess<json::Json>(std::move(doc), pos);
    };
}
} // namespace hlp
