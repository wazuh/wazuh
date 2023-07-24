#ifndef _BUILDER_HELPER_PARSER_HPP
#define _BUILDER_HELPER_PARSER_HPP

#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include <fmt/format.h>
#include <re2/re2.h>

#include <error.hpp>
#include <json/json.hpp>

#include "syntax.hpp"
#include "utils/stringUtils.hpp"

namespace builder::internals
{
struct HelperToken
{
    std::string name = "";
    std::vector<std::string> args = {};

    friend std::ostream& operator<<(std::ostream& os, const HelperToken& helperToken)
    {
        std::string separator {};
        separator += syntax::FUNCTION_HELPER_ARG_ANCHOR;

        os << helperToken.name << "(" << base::utils::string::join(helperToken.args, separator, false) << ")";

        return os;
    }
};

inline std::tuple<std::string, json::Json> toBuilderInput(const HelperToken& helperToken,
                                                          const std::string& targetField)
{
    json::Json value {};
    auto valueStr = fmt::format("{}({})", helperToken.name, base::utils::string::join(helperToken.args, ","));
    value.setString(valueStr);

    return std::make_tuple(targetField, std::move(value));
}

inline std::tuple<std::string, json::Json> toBuilderInput(const HelperToken& helperToken)
{
    if (helperToken.args.empty())
    {
        std::stringstream ss {};
        ss << helperToken;
        throw std::runtime_error(
            fmt::format("Helper {} has no arguments, expected to have target field as first argument", ss.str()));
    }

    return toBuilderInput({helperToken.name, {helperToken.args.begin() + 1, helperToken.args.end()}},
                          helperToken.args[0]);
}

inline std::variant<HelperToken, base::Error> parseHelper(const std::string& text)
{
    static const auto regexPattern = R"(^([\w_]+)\((.*)\)$)";
    static const re2::RE2 pattern(regexPattern);

    std::string helperName;
    std::string strArgs;

    HelperToken result;

    if (re2::RE2::FullMatch(text, pattern, &result.name, &strArgs))
    {
        if (!strArgs.empty())
        {
            size_t pos = 0;
            while ((pos = strArgs.find(',', pos)) != std::string::npos)
            {
                // if the comma is escaped skip it 
                if (pos != 0 && strArgs[pos - 1] == '\\')
                {
                    ++pos;
                    continue;
                }

                // if a space is found after the comma, erase it
                if ((pos + 1) < strArgs.size() && strArgs[pos + 1] == ' ')
                {
                    strArgs.erase(pos + 1, 1);
                }
                // if the space is scaped, delete the backslash
                else if ((pos + 2) < strArgs.size() && strArgs[pos + 1] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE
                         && strArgs[pos + 2] == ' ')
                {
                    strArgs.erase(pos + 1, 1);
                }

                ++pos;
            }

            result.args = base::utils::string::splitEscaped(
                strArgs, syntax::FUNCTION_HELPER_ARG_ANCHOR, syntax::FUNCTION_HELPER_DEFAULT_ESCAPE);
        }

        return result;
    }

    return base::Error {"No match found!"};
}
} // namespace builder::internals

#endif // _BUILDER_HELPER_PARSER_HPP
