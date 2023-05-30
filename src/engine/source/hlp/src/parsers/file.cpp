#include <hlp/hlp.hpp>

#include <algorithm>
#include <iostream>
#include <optional>
#include <sstream>

#include <fmt/format.h>
#include <json/json.hpp>

#include <hlp/base.hpp>
#include <hlp/parsec.hpp>

json::Json parseFp(char slash, std::string_view in)
{
    json::Json out {};

    if (slash == '\\' && in[0] > 'A' && in[0] < 'Z')
    {
        out.setString(std::string {in[0]}, "/drive_letter");
    }
    // Get path
    auto indexPathEnd = in.find_last_of(slash);
    auto path = in.substr(0, indexPathEnd == 0 ? 1 : indexPathEnd);

    out.setString(std::string {path}, "/path");

    // Get file name
    auto indexNameStart = (indexPathEnd == std::string::npos)
                             ? 0
                             : (indexPathEnd + 1);

    auto fileName = in.substr(indexNameStart);
    out.setString(std::string {fileName}, "/name");

    // Get extension
    auto indexExtStart = fileName.find_last_of('.');
    auto ext = indexExtStart == std::string::npos ? "" : fileName.substr(indexExtStart + 1);

    std::string lext {ext};
    std::transform(lext.begin(), lext.end(), lext.begin(), ::tolower);
    out.setString(std::string {lext}, "/ext");

    return out;
}

namespace hlp
{

parsec::Parser<json::Json>
getFilePathParser(std::string name, Stop endTokens, Options lst)
{
    if (endTokens.empty())
    {
        throw std::runtime_error("File parser needs a stop string");
    }

    if (!lst.empty())
    {
        throw std::runtime_error("File parser does not support any options");
    }
    return [endTokens, name](std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }
        auto fp = std::get<std::string_view>(res);

        if (fp.size() == 0)
        {
            return parsec::makeError<json::Json>("File path is empty", index);
        }


        json::Json doc;
        if (fp.find("\\") != std::string::npos)
        {
            doc = parseFp('\\', fp);
        }
        else
        {
           doc = parseFp('/', fp);
        }

        return parsec::makeSuccess<json::Json>(std::move(doc), fp.size() + index);
    };
}

} // namespace hlp
