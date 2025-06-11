#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(const json::Json& parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.set(targetField, parsed);
    };
}

SemParser getSemParser(std::string_view targetField, json::Json&& parsed)
{
    return [targetField, parsed = std::move(parsed)](std::string_view)
    {
        return getMapper(parsed, targetField);
    };
}

} // namespace
namespace hlp::parsers
{

Parser getJSONParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw std::runtime_error(fmt::format("JSON parser do not accept arguments!"));
    }

    const auto target = params.targetField.empty() ? "" : params.targetField;

    return [name = params.name, target](std::string_view txt)
    {
        if (txt.empty())
        {
            return abs::makeFailure<ResultT>(txt, name);
        }

        rapidjson::Reader reader;
        const auto ssInput = std::string(txt);
        rapidjson::StringStream ss(ssInput.c_str());
        rapidjson::Document doc;

        doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);
        if (doc.HasParseError())
        {
            return abs::makeFailure<ResultT>(txt, name);
        }
        const auto parsed = txt.substr(0, ss.Tell());
        const auto remaining = txt.substr(ss.Tell());
        const auto semP = target.empty() ? noSemParser() : getSemParser(target, json::Json(std::move(doc)));
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, remaining);
    };
}
} // namespace hlp::parsers
