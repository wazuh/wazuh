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

parsec::Parser<json::Json> getQuotedParser(const std::string& name, const Stop& endTokens, Options lst)
{
    if (lst.size() > 2)
    {
        throw std::runtime_error("Quoted parser requires 0, 1 or 2 parameters."
                                 " The first parameter is the quote character, the "
                                 "second is the escape character");
    }
    else if (lst.size() > 0 && lst[0].size() != 1)
    {
        throw std::runtime_error("Quoted parser requires a single character "
                                 "as delimiter. Got: "
                                 + lst[0]);
    }
    else if (lst.size() > 1 && lst[1].size() != 1)
    {
        throw std::runtime_error("Quoted parser requires a single character "
                                 "as escape character. Got: "
                                 + lst[1]);
    }

    // Default values for quote and escape characters
    char quoteChar = lst.size() > 0 ? lst[0][0] : '"';
    char escapeChar = lst.size() > 1 ? lst[1][0] : '\\';

    if (quoteChar == escapeChar)
    {
        throw std::runtime_error("Quoted parser requires different characters "
                                 "for quote and escape. Got: "
                                 + lst[0]);
    }

    // The parser
    return [quoteChar, escapeChar, name](std::string_view text, int index)
    {
        auto res = internal::eofError<json::Json>(text, index);
        if (res.has_value())
        {
            return res.value();
        }

        json::Json ret;
        if (text[index] != quoteChar)
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Expected quote character '{}'", name, quoteChar), index);
        }

        std::string str {};
        int i = index + 1;
        while (i < text.size())
        {
            if (text[i] == quoteChar)
            {
                ret.setString(str);
                return parsec::makeSuccess<json::Json>(std::move(ret), i + 1);
            }
            else if (text[i] == escapeChar)
            {
                if (i + 1 >= text.size())
                {
                    return parsec::makeError<json::Json>(
                        fmt::format("{}: Unexpected end of input after escape character",
                                    name),
                        i + 1);
                }
                else if (text[i + 1] == quoteChar)
                {
                    str += quoteChar;
                    i += 2;
                }
                else if (text[i + 1] == escapeChar)
                {
                    str += escapeChar;
                    i += 2;
                }
                else
                {
                    return parsec::makeError<json::Json>(
                        fmt::format(
                            "{}: Unexpected escape sequence: \\{}", name, text[i + 1]),
                        i + 1);
                }
            }
            else
            {
                str += text[i];
                i++;
            }
        }

        return parsec::makeError<json::Json>(
            fmt::format("{}: Expected quote character '{}'", name, quoteChar), i);
    };
}
} // namespace hlp
