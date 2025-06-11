#include <map>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(std::map<std::string, std::string>&& fileAttrs, std::string_view targetField)
{
    return [fileAttrs, targetField](json::Json& event)
    {
        for (const auto& [attr, value] : fileAttrs)
        {
            const auto attrPath = std::string(targetField) + attr;
            event.setString(value, attrPath);
        }
    };
}

std::map<std::string, std::string> parseFp(char slash, std::string_view in)
{
    std::map<std::string, std::string> out {};

    if (slash == '\\' && in[0] > 'A' && in[0] < 'Z')
    {
        out["/drive_letter"] = std::string {in[0]};
    }

    // Get path
    auto indexPathEnd = in.find_last_of(slash);
    auto path = in.substr(0, indexPathEnd == 0 ? 1 : indexPathEnd);

    out["/path"] = std::string {path};

    // Get file name
    auto indexNameStart = (indexPathEnd == std::string::npos) ? 0 : (indexPathEnd + 1);

    auto fileName = in.substr(indexNameStart);
    out["/name"] = std::string {fileName};

    // Get extension
    auto indexExtStart = fileName.find_last_of('.');
    auto ext = indexExtStart == std::string::npos ? "" : fileName.substr(indexExtStart + 1);

    std::string lext {ext};
    std::transform(lext.begin(), lext.end(), lext.begin(), ::tolower);
    out["/ext"] = std::string {lext};

    return out;
}

SemParser getSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        auto res = parsed.find('\\') != std::string::npos ? parseFp('\\', parsed) : parseFp('/', parsed);

        return getMapper(std::move(res), targetField);
    };
}

} // namespace

namespace hlp::parsers
{

Parser getFilePathParser(const Params& params)
{
    if (params.stop.empty())
    {
        throw std::runtime_error("File parser needs a stop string");
    }

    if (!params.options.empty())
    {
        throw std::runtime_error("File parser does not support any options");
    }

    const auto synP = syntax::parsers::toEnd(params.stop);
    const auto semP = params.targetField.empty() ? noSemParser() : getSemParser(params.targetField);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(txt, name);
        }

        const auto parsed = syntax::parsed(synR, txt);
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}

} // namespace hlp::parsers
