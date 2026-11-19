// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef WAZUH_ENGINE_PARSE_FIELD_HPP
#define WAZUH_ENGINE_PARSE_FIELD_HPP

#include <base/json.hpp>
#include <optional>
#include <string_view>
#include <tuple>

namespace json
{
class PathWriter;
} // namespace json

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
 * @brief Removes the escape characters of a value, in place and in one pass.
 *
 * Scanning left to right, every occurrence of @p escape drops its first byte and the byte after that one is
 * kept verbatim: `a\\b` becomes `a\b` and an escape at the end of the value disappears. Every occurrence is
 * removed, not only the ones that escape a meaningful character, which is what the key-value parser detects
 * to set @p is_escaped. Only the first byte of @p escape is dropped, so a sequence of more than one byte
 * leaves the rest in the value. An empty @p escape is a no-op.
 *
 * @param is_escaped Whether the value holds escapes to remove; false leaves @p vs untouched.
 * @param vs The value, modified in place and shortened to the unescaped length.
 * @param escape The escape sequence; every caller in the tree passes a single character.
 */
void unescape(bool is_escaped, std::string& vs, std::string_view escape);

/**
 * @brief Adds a key:value pair to a JSON document. Unescapes the value if necessary.
 *
 * The value is written under @p key with every '.' converted into '/': as null if it is empty, as a string otherwise.
 * Every token of that path is written as an object member name, never as an array index (json::Json::setNullAsMembers,
 * json::Json::setStringAsMembers). The tokens of the path are counted, one per '/' (std::count; the escapes ~0 and ~1
 * add none), and nothing is written if there are more than json::Json::MAX_DEPTH.
 *
 * @param doc The JSON document to update.
 * @param key The key to be added to the document.
 * @param value The value to be added to the document.
 * @param is_escaped Whether the value should be unescaped.
 * @param escape The character used to unescape quote or escape characters inside the string value.
 * @param is_quoted Whether the value was quoted in the source. Currently not consulted: a non-empty value is
 * always stored as a string (unescaped when @p is_escaped) and an empty one as null; no numeric conversion is done.
 * @return true if the pair was written; false, without touching @p doc, if the path it would be written to has more
 * than json::Json::MAX_DEPTH tokens.
 */
bool updateDoc(json::Json& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted);

/**
 * @brief Same as updateDoc(json::Json&, ...), writing through @p doc.
 *
 * Same contract, result and document as the json::Json overload. Meant for callers that write many keys into one
 * document: they keep one json::PathWriter for the whole document and pass it to every call.
 *
 * @param doc The writer over the JSON document to update.
 */
bool updateDoc(json::PathWriter& doc,
               std::string_view key,
               std::string_view value,
               bool is_escaped,
               std::string_view escape,
               bool is_quoted);

} // namespace hlp
#endif // WAZUH_ENGINE_PARSE_FIELD_HPP
