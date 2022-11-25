#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <optional>
#include <list>
#include <json/json.hpp>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getJSONParser(Stop str, Options lst)
{
    return [str](std::string_view text, int index)
    {
        std::string_view fp;

        unsigned long pos;
        if (!str.has_value()) {
            fp = text;
        }
        else
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

        // Parse the json and stop at the end of the json object, if error return false
        // TODO: see if there is a way to specify the root JSON type
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