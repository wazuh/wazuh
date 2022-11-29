#include <optional>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/parsec.hpp>
#include <json/json.hpp>

#include "base.hpp"

namespace hlp
{

parsec::Parser<json::Json> getBoolParser(Stop str, Options lst)
{
    return [str](std::string_view text, int index)
    {
        auto res = preProcess<json::Json>(text, index, str);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);

        // TODO Check True/ TRUE/ true/ False/ FALSE/ false / 0 / 1?
        if (fp == "true")
        {
            return parsec::makeSuccess<json::Json>(
                json::Json("true"), text, index + 4);
        }
        else if (fp == "false")
        {
            return parsec::makeSuccess<json::Json>(
                json::Json("false"), text, index + 5);
        }
        else
        {
            return parsec::makeError<json::Json>(
                "Expected 'true' or 'false'", text, index);
        }
    };
}
} // namespace hlp
