#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <optional>
#include <json/json.hpp>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;


void parseFp(std::string slash, json::Json *out, std::string_view in)
{
    if (slash == "\\") {
        if (in[0] > 'A' && in[0] < 'Z')
            out->setString(std::string {in[0]}, "/drive_letter");
    }
    auto pathEnd = in.find_last_of(slash);
    auto pathName = pathEnd == std::string::npos ? in : in.substr(0, pathEnd);
    out->setString(std::string {pathName},"/path");

    auto fileNameStart = pathEnd;
    auto fileName = fileNameStart == std::string::npos ? in : in.substr(fileNameStart + 1);
    out->setString(std::string {fileName},"/name" );

    auto extStart = fileName.find_last_of('.');
    auto ext = extStart == std::string::npos ? "" : fileName.substr(extStart + 1);

    std::string lext{ext};
    std::transform(lext.begin(), lext.end(), lext.begin(), ::tolower);
    out->setString(std::string{lext}, "/ext");
}

namespace hlp
{

parsec::Parser<json::Json> getFilePathParser(Stop str, Options lst)
{
    if ( ! str.has_value()) {
        throw std::invalid_argument(fmt::format("File parser needs a stop string"));
    }
    auto stop = str.value();

    return [stop](std::string_view text, int index)
    {
        std::string_view fp;

        unsigned long pos;
        if (stop.empty()) {
            fp = text;
            pos = text.size();
        } else
        {
            pos = text.find(stop, index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", stop), text, index);
            }
            fp = text.substr(index, pos);
        }
        json::Json doc;

        if ( fp.find("\\") != std::string::npos) {
            parseFp("\\",&doc, fp);
        } else
            parseFp("/", &doc, fp);

        return parsec::makeSuccess<json::Json>(doc, text, pos);
    };
}

} // hlp namespace