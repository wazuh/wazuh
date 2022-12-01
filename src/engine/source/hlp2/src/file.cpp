#include "fmt/format.h"
#include <algorithm>
#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <iostream>
#include <json/json.hpp>
#include <optional>
#include <sstream>

void parseFp(std::string slash, json::Json* out, std::string_view in)
{
    if (slash == "\\")
    {
        if (in[0] > 'A' && in[0] < 'Z')
            out->setString(std::string {in[0]}, "/drive_letter");
    }
    auto pathEnd = in.find_last_of(slash);
    auto pathName = pathEnd == std::string::npos ? in : in.substr(0, pathEnd);
    out->setString(std::string {pathName}, "/path");

    auto fileNameStart = pathEnd;
    auto fileName =
        fileNameStart == std::string::npos ? in : in.substr(fileNameStart + 1);
    out->setString(std::string {fileName}, "/name");

    auto extStart = fileName.find_last_of('.');
    auto ext = extStart == std::string::npos ? "" : fileName.substr(extStart + 1);

    std::string lext {ext};
    std::transform(lext.begin(), lext.end(), lext.begin(), ::tolower);
    out->setString(std::string {lext}, "/ext");
}

namespace hlp
{

parsec::Parser<json::Json> getFilePathParser(Stop endTokens, Options lst)
{
    if (endTokens.empty())
    {
        throw std::invalid_argument(fmt::format("File parser needs a stop string"));
    }

    if (lst.size() > 1)
    {
        throw std::invalid_argument(fmt::format("File parser accepts only one option"));
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

        json::Json doc;

        if (fp.find("\\") != std::string::npos)
        {
            parseFp("\\", &doc, fp);
        }
        else
            parseFp("/", &doc, fp);

        return parsec::makeSuccess<json::Json>(doc, text, pos);
    };
}

} // namespace hlp
