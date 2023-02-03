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

namespace hlp
{
parsec::Parser<json::Json> getAlphanumericParser(const std::string& name, Stop, Options lst)
{
    if (!lst.empty())
    {
        throw std::runtime_error("alphanumeric parser doesn't accept parameters");
    }

    return [name](std::string_view text, int index)
    {
        auto res = internal::eofError<json::Json>(text, index);
        if (res.has_value())
        {
            return res.value();
        }

        auto begin {text.begin()};
        std::advance(begin, index);

        auto it = std::find_if(begin, text.end(), [](char const &c) {
            return !std::isalnum(c);
        });

        if (it == text.end())
        {
            json::Json alphaNumeric;

            alphaNumeric.setString(std::string {text});
            index += text.size();

            return parsec::makeSuccess<json::Json>(std::move(alphaNumeric), index);
        }
        else
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Expected alphanumeric input", name), index);
        }
    };
}
} // namespace hlp
