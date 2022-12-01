#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <utils/stringUtils.hpp>

namespace hlp
{

parsec::Parser<json::Json> getBoolParser(Stop, Options lst)
{
    if (!lst.empty())
    {
        throw std::runtime_error("bool parser doesn't accept parameters");
    }

    return [](std::string_view text, int index)
    {
        auto res = internal::eofError<json::Json>(text, index);
        if (res.has_value())
        {
            return res.value();
        }
        json::Json ret;
        // TODO Check True/ TRUE/ true/ False/ FALSE/ false / 0 / 1?
        if (utils::string::startsWith(text, "true"))
        {
            ret.setBool(true);
            return parsec::makeSuccess<json::Json>(ret, text, index + 4);
        }
        else if (utils::string::startsWith(text, "false"))
        {
            ret.setBool(false);
            return parsec::makeSuccess<json::Json>(ret, text, index + 5);
        }
        else
        {
            return parsec::makeError<json::Json>(
                "Expected 'true' or 'false'", text, index);
        }
    };
}
} // namespace hlp
