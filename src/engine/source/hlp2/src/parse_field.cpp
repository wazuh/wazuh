#include "parse_field.hpp"
#include "fmt/format.h"
#include <iostream>
#include <json/json.hpp>
#include <string_view>
#include "number.hpp"
namespace hlp
{

std::optional<Field>
getField(const char* in, size_t pos, size_t size, const char delimiter, const char quote, const char escape, bool s)
{
    size_t last_escape_location = 0;


    bool escaped {false};
    bool quote_opened = false;

    Field f{pos, size, false, false};

    for (auto i = pos; i < size; i++)
    {
        pos = i;
        if (in[i] == delimiter && !quote_opened)
        {
            f.end_ = pos;
            return f;
        }
        else
        {
            if (quote_opened && quote != escape && in[i] == escape)
                last_escape_location = i;

            if (in[i] == quote)
            {
                if (!quote_opened)
                {
                    quote_opened = true;
                    // If fields are not enclosed with double quotes, then
                    // double quotes may not appear inside the fields.
                    if ( s && i> 1 & in[i-1] != delimiter )
                        return {};
                    if (quote == escape)
                        last_escape_location = i;
                }
                else
                {
                    escaped = (last_escape_location == i - 1);
                    f.is_escaped = f.is_escaped || escaped;
                    last_escape_location += (i - last_escape_location) * size_t(!escaped);
                    quote_opened = escaped || (in[i + 1] != delimiter);
                    f.is_quoted = true;
                }
            }
        }
    }
    // unclosed quote
    if (quote_opened && in[pos] != quote )
        return {};

    if ( f.start_ > f.end_)
        return {};


    f.end_ = pos + 1;

    return f;
};


void unescape(bool is_escaped, std::string & vs, std::string_view escape)
{
    if ( is_escaped) {
        for (auto j = vs.find(escape, 0); j != std::string::npos;
             j = vs.find(escape, j)) {
            vs.erase(j,1);
            j++;
        }
    }
}

void updateDoc(json::Json & doc, std::string_view hdr, std::string_view val, bool is_escaped, std::string_view escape)
{
    if (val.empty())
    {
        doc.setNull(hdr);
        return;
    }

    int64_t i;
    auto [ptr, ec] {utils::from_chars(val.data(), val.data() + val.size(), i)};
    if (ec == std::errc())
    {
        doc.setInt64(i, hdr);
        return;
    }
    else
    {
        double_t d;
        auto [ptr, ec] {utils::from_chars(val.data(), val.data()+val.size(), d)};
        if (ec == std::errc())
        {
            doc.setDouble(d,hdr);
            return;
        }
    }

    auto vs = std::string { val.data(), val.size() };
    unescape(is_escaped,vs,escape);
    doc.setString(vs, hdr);

}



} // hlp namespace
