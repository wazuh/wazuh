#include "parse_field.hpp"
#include "fmt/format.h"
#include "number.hpp"
#include <iostream>
#include <base/json.hpp>
#include <string_view>
namespace hlp
{

std::optional<Field> getField(std::string_view input,
                              const char delimiter,
                              const char quote,
                              const char escape,
                              bool strict)
{
    size_t last_escape_location = 0;

    if (input.empty())
    {
        // Empty field
        return Field {0, 0, false, false};
    }

    bool quote_opened {false};
    bool isEscaped = false;
    bool isQuoted = false;

    for (auto i = 0ul; i < input.size(); i++)
    {
        if (input[i] == delimiter && !quote_opened)
        {
            // Found delimiter outside quotes, return field
            return Field {0, i, isEscaped, isQuoted};
        }
        else
        {
            if (quote_opened && quote != escape && input[i] == escape)
            {
                // Handle escape character
                last_escape_location = i;
            }
            if (input[i] == quote)
            {
                if (!quote_opened)
                {
                    // Handle opening quote
                    quote_opened = true;
                    if (strict && (1 < i) && input[i - 1] != delimiter)
                    {
                        // Invalid field if strict parsing is enabled and there is no delimiter before opening quote
                        return {};
                    }
                    if (quote == escape)
                    {
                        last_escape_location = i;
                    }
                }
                else
                {
                    // Handle closing quote
                    bool escaped = (last_escape_location + 1 == i) && (1 < i);
                    isEscaped = isEscaped || escaped;
                    last_escape_location += (i - last_escape_location) * size_t(!escaped);
                    quote_opened = escaped || (input[i + 1] != delimiter);
                    isQuoted = true;
                }
            }
        }
    }
    // Unclosed quote
    if (quote_opened && input.back() != quote)
    {
        return {};
    }

    // Return field
    return Field {0, input.size(), isEscaped, isQuoted};
};

void unescape(bool is_escaped, std::string& vs, std::string_view escape)
{
    if (is_escaped)
    {
        for (auto j = vs.find(escape, 0); j != std::string::npos; j = vs.find(escape, j))
        {
            vs.erase(j, 1);
            j++;
        }
    }
}

void updateDoc(json::Json& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted)
{
    if (value.empty())
    {
        doc.setNull(key);
        return;
    }

    // If the value is a string, unescape it if necessary and add it to the JSON document
    auto vs = std::string {value.data(), value.size()};
    unescape(is_escaped, vs, escape);
    doc.setString(vs, key);
}

} // namespace hlp
