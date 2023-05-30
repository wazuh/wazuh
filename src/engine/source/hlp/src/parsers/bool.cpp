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

parsec::Parser<json::Json> getBoolParser(std::string name, Stop, Options lst)
{
    if (!lst.empty())
    {
        throw std::runtime_error("bool parser doesn't accept parameters");
    }

    return [name](std::string_view text, int index)
    {
        auto res = internal::eofError<json::Json>(text, index);
        if (res.has_value())
        {
            return res.value();
        }
        auto fp = text.substr(index);
        json::Json ret;
        // TODO Check True/ TRUE/ true/ False/ FALSE/ false / 0 / 1?
        if (base::utils::string::startsWith(fp, "true"))
        {
            ret.setBool(true);
            return parsec::makeSuccess<json::Json>(std::move(ret), index + 4);
        }
        else if (base::utils::string::startsWith(fp, "false"))
        {
            ret.setBool(false);
            return parsec::makeSuccess<json::Json>(std::move(ret), index + 5);
        }
        else
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Expected 'true' or 'false'", name), index);
        }
    };
}
} // namespace hlp
