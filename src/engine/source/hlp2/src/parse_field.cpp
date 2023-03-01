#include "parse_field.hpp"
#include "fmt/format.h"
#include "number.hpp"
#include <iostream>
#include <json/json.hpp>
#include <string_view>
namespace hlp
{

std::optional<Field> getField(std::string_view input,
                              const char delimiter,
                              const char quote,
                              const char escape,
                              bool s)
{
    size_t last_escape_location = 0;

    if (input.empty())
    {
        return Field {0,0,false,false};
    }

    bool quote_opened {false};
    bool isEscaped = false;
    bool isQuoted = false;

    for (auto i = 0ul; i < input.size(); i++)
    {
        if (input[i] == delimiter && !quote_opened)
        {
            return Field {0, i, isEscaped, isQuoted};
        }
        else
        {
            if (quote_opened && quote != escape && input[i] == escape)
            {
                last_escape_location = i;
            }
            // TODO: If it does not begin with quotation marks, why does it advance until
            // it is found?
            if (input[i] == quote)
            {
                if (!quote_opened)
                {
                    quote_opened = true;
                    // If fields are not enclosed with double quotes, then
                    // double quotes may not appear inside the fields.
                    if (s && (i > 1) && input[i - 1] != delimiter)
                    {
                        return {};
                    }
                    if (quote == escape)
                    {
                        last_escape_location = i;
                    }
                }
                else
                {
                    bool escaped = (last_escape_location + 1 == i);
                    isEscaped = isEscaped || escaped;
                    last_escape_location += (i - last_escape_location) * size_t(!escaped);
                    quote_opened = escaped || (input[i + 1] != delimiter);
                    isQuoted = true;
                }
            }
        }
    }
    // unclosed quote
    if (quote_opened && input.back() != quote)
    {
        return {};
    }

    return Field {0, input.size(), isEscaped, isQuoted};
};

void unescape(bool isEscaped, std::string& vs, std::string_view escape)
{
    if (isEscaped)
    {
        for (auto j = vs.find(escape, 0); j != std::string::npos; j = vs.find(escape, j))
        {
            vs.erase(j, 1);
            j++;
        }
    }
}

void updateDoc(json::Json& doc,
               std::string_view hdr,
               std::string_view val,
               bool isEscaped,
               std::string_view escape)
{
    if (val.empty())
    {
        doc.setNull(hdr);
        return;
    }

    int64_t i;
    auto [ptr, ec] {utils::from_chars(val.data(), val.data() + val.size(), i)};
    if (std::errc() == ec && (val.data() + val.size()) == ptr)
    {
        doc.setInt64(i, hdr);
        return;
    }
    else
    {
        double_t d;
        auto [ptr, ec] {utils::from_chars(val.data(), val.data() + val.size(), d)};
        if (std::errc() == ec && (val.data() + val.size()) == ptr)
        {
            doc.setDouble(d, hdr);
            return;
        }
    }

    auto vs = std::string {val.data(), val.size()};
    unescape(isEscaped, vs, escape);
    doc.setString(vs, hdr);
}

} // namespace hlp
