#ifndef WAZUH_ENGINE_PARSE_FIELD_HPP
#define WAZUH_ENGINE_PARSE_FIELD_HPP

#include <json/json.hpp>
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
    inline const int end() const { return m_end; }

    inline const int len() const
    {
        return m_isQuoted ? m_end - m_start - 2 : m_end - m_start;
    }

    inline const int start() const { return m_isQuoted ? m_start + 1 : m_start; }

    inline const bool isEscaped() const { return m_isEscaped; }

    inline void addOffset(const int offset)
    {
        m_start += offset;
        m_end += offset;
    }
};

/**
 * @brief Get the Field object
 *
 * @param in
 * @param pos
 * @param size
 * @param delimiter
 * @param quote
 * @param escape
 * @param s
 * @return std::optional<Field>
 */
std::optional<Field> getField(std::string_view input,
                              const char delimiter,
                              const char quote,
                              const char escape,
                              bool s);

// TODO:DOC THIS
void unescape(bool isEscaped, std::string& vs, std::string_view escape);

// TODO:DOC THIS
void updateDoc(json::Json& doc,
               std::string_view hdr,
               std::string_view val,
               bool isEscaped,
               std::string_view escape);

} // namespace hlp
#endif // WAZUH_ENGINE_PARSE_FIELD_HPP
