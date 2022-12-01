#include <optional>
#include <stdexcept>

#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{

parsec::Parser<json::Json> getJSONParser(Stop endTokens, Options lst)
{
    if (lst.size() > 0)
    {
        throw std::runtime_error(fmt::format("JSON parser do not accept arguments!"));
    }

    return [endTokens](std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);
        auto pos = fp.size() + index;

        rapidjson::Reader reader;
        rapidjson::StringStream ss {fp.data()};
        rapidjson::Document doc;

        doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);
        if (doc.HasParseError())
        {
            auto msg = fmt::format("{}", doc.GetParseError());
            return parsec::makeError<json::Json>(msg, text, index);
        }

        return parsec::makeSuccess<json::Json>(
            json::Json(std::move(doc)), text, ss.Tell());
    };
}
} // namespace hlp
