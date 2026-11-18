// SPDX-License-Identifier: AGPL-3.0-or-later
#include "parse_field.hpp"
#include "fmt/format.h"
#include "number.hpp"
#include <algorithm>
#include <base/json.hpp>
#include <base/jsonPathWriter.hpp>
#include <cstring>
#include <iostream>
#include <string_view>
namespace hlp
{

std::optional<Field>
getField(std::string_view input, const char delimiter, const char quote, const char escape, bool strict)
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
                    quote_opened = escaped || (i + 1 >= input.size() || input[i + 1] != delimiter);
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
    // An empty escape matches at every position: it is not a separator, and no caller passes one.
    if (!is_escaped || escape.empty())
    {
        return;
    }

    // One pass: every surviving byte is moved at most once. The clean run between two escapes is moved in a
    // single memmove, and the search keeps using find, so a value with few escapes costs what the scan costs.
    // The write index never overtakes the read index, so the regions overlap and memmove is required: memcpy
    // would be undefined behaviour here even though it happens to produce the same bytes with forward copies.
    std::size_t write = 0;
    std::size_t read = 0;
    for (auto found = vs.find(escape, read); found != std::string::npos; found = vs.find(escape, read))
    {
        if (found > read)
        {
            if (write != read)
            {
                std::memmove(&vs[write], &vs[read], found - read);
            }
            write += found - read;
            read = found;
        }

        // The escape drops its first byte and the byte after it is kept verbatim; a trailing escape leaves
        // read at the end of the value, so it is dropped and nothing is kept after it.
        ++read;
        if (read < vs.size())
        {
            vs[write++] = vs[read++];
        }
    }

    if (read < vs.size())
    {
        if (write != read)
        {
            std::memmove(&vs[write], &vs[read], vs.size() - read);
        }
        write += vs.size() - read;
    }

    vs.resize(write);
}

// TODO: evaluate which is the most suitable site for this functionality
std::string convertDotToSlash(std::string_view key)
{
    auto pos = key.find('.');
    if (pos == std::string_view::npos)
    {
        return std::string {key};
    }
    std::string s {key};
    std::replace(s.begin() + pos, s.end(), '.', '/');
    return s;
}

namespace
{
// A JSON Pointer path has one token per '/'; the escapes ~0 and ~1 add none.
bool exceedsMaxDepth(std::string_view path)
{
    return static_cast<std::size_t>(std::count(path.cbegin(), path.cend(), '/')) > json::Json::MAX_DEPTH;
}

// Body shared by the two overloads of updateDoc: Doc is json::Json or json::PathWriter.
template<typename Doc>
bool updateDocImpl(
    Doc& doc, std::string_view key, std::string_view value, bool is_escaped, std::string_view escape, bool is_quoted)
{
    // Keys come from event data: every token is written as an object member, never as an array index.
    // The dots of the key nest the value whether it is empty or not, so both count towards the depth cap
    const auto path = convertDotToSlash(key);
    if (exceedsMaxDepth(path))
    {
        return false;
    }

    if (value.empty())
    {
        doc.setNullAsMembers(path);
        return true;
    }

    // If the value is a string, unescape it if necessary and add it to the JSON document
    auto vs = std::string {value.data(), value.size()};
    unescape(is_escaped, vs, escape);
    doc.setStringAsMembers(vs, path);
    return true;
}
} // namespace

bool updateDoc(json::Json& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted)
{
    return updateDocImpl(doc, key, value, is_escaped, escape, is_quoted);
}

bool updateDoc(json::PathWriter& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted)
{
    return updateDocImpl(doc, key, value, is_escaped, escape, is_quoted);
}

} // namespace hlp
