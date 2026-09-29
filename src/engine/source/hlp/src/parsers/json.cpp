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
    return [targetField, parsed = std::move(parsed)](std::string_view, bool)
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
    // A Result keeps its trace as a string_view: the depth-cap text must live in the closure, like the name.
    auto depthTrace = fmt::format("{}: {} ({})", params.name, json::Json::DEPTH_ERROR_MSG, json::Json::MAX_DEPTH);

    return [name = params.name, target, depthTrace = std::move(depthTrace)](std::string_view txt)
    {
        if (txt.empty())
        {
            return abs::makeFailure<ResultT>(txt, name);
        }

        const auto ssInput = std::string(txt);
        rapidjson::StringStream ss(ssInput.c_str());
        rapidjson::Document doc;

        // Nesting deeper than Json::MAX_DEPTH never becomes a DOM; the stream still reports what was consumed.
        const auto result = json::Json::parseBounded<rapidjson::kParseStopWhenDoneFlag>(doc, ss);
        if (!result)
        {
            if (json::Json::isDepthError(result))
            {
                return abs::makeFailure<ResultT>(txt, depthTrace);
            }
            return abs::makeFailure<ResultT>(txt, name);
        }
        const auto parsed = txt.substr(0, ss.Tell());
        const auto remaining = txt.substr(ss.Tell());
        const auto semP = target.empty() ? noSemParser() : getSemParser(target, json::Json(std::move(doc)));
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, remaining);
    };
}
} // namespace hlp::parsers
