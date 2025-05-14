#ifndef WAZUH_ENGINE_PARSE_FIELD_HPP
#define WAZUH_ENGINE_PARSE_FIELD_HPP

#include <base/json.hpp>
#include <optional>
#include <string_view>
#include <tuple>

namespace hlp
{

/**
 * @brief
 */
class Field
{
private:
    size_t m_start;
    size_t m_end;
    bool m_isEscaped;
    bool m_isQuoted;

public:
    Field(size_t start, size_t end, bool isEscaped, bool isQuoted)
        : m_start(start)
        , m_end(end)
        , m_isEscaped(isEscaped)
        , m_isQuoted(isQuoted)
    {
    }
    inline int end() const { return m_end; }

    inline int len() const { return m_isQuoted ? m_end - m_start - 2 : m_end - m_start; }

    inline int start() const { return m_isQuoted ? m_start + 1 : m_start; }

    inline bool isEscaped() const { return m_isEscaped; }

    inline bool isQuoted() const { return m_isQuoted; }

    inline void addOffset(size_t offset)
    {
        m_start += offset;
        m_end += offset;
    }
};

/**
 * @brief Parses a field from a string using the given delimiter, quote, and escape characters.
 *
 * @param input The string to parse the field from.
 * @param delimiter The delimiter character used to separate fields.
 * @param quote The quote character used to enclose fields that contain delimiter characters.
 * @param escape The escape character used to escape quote or escape characters inside a field.
 * @param strict Whether strict parsing should be used. If true, fields not enclosed in quotes cannot contain quotes.
 * @return An optional Field object containing the parsed field, or std::nullopt if the input is invalid.
 */
std::optional<Field>
getField(std::string_view input, const char delimiter, const char quote, const char escape, bool strict);

/**
 * @brief Unescapes a string
 *
 * @param is_escaped Whether the string is escaped.
 * @param vs The string to be unescaped.
 * @param escape The escape character
 */
void unescape(bool is_escaped, std::string& vs, std::string_view escape);

/**
 * @brief Adds a key:value pair to a JSON document. Unescapes the value if necessary.
 *
 * @param doc The JSON document to update.
 * @param key The key to be added to the document.
 * @param value The value to be added to the document.
 * @param is_escaped Whether the value should be unescaped.
 * @param escape The character used to unescape quote or escape characters inside the string value.
 * @param is_quoted Whether the value is quoted. If false, it tries to parse the value as int or double.
 */
void updateDoc(json::Json& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted);

} // namespace hlp
#endif // WAZUH_ENGINE_PARSE_FIELD_HPP
