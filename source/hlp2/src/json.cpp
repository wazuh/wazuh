#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <optional>
#include <json/json.hpp>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getJSONParser(Stop str, Options lst)
{
    if (lst.size() > 0)
    {
        throw std::runtime_error(fmt::format("JSON parser do not accept arguments!"));
    }

    return [str](std::string_view text, int index)
    {
        size_t pos = text.size();
        std::string_view fp = text;
        if (str.has_value() && ! str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }

        rapidjson::Reader reader;
        rapidjson::StringStream ss {fp.data()};
        rapidjson::Document doc;

        doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);
        if (doc.HasParseError())
        {
            auto msg = fmt::format("{}", doc.GetParseError());
            return parsec::makeError<json::Json>(msg, text, index);
        }

        return parsec::makeSuccess<json::Json>(json::Json(std::move(doc)), text, ss.Tell());

    };
}
}