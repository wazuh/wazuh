#ifndef WAZUH_ENGINE_PARSE_FIELD_HPP
#define WAZUH_ENGINE_PARSE_FIELD_HPP

#include <json/json.hpp>
#include <optional>
#include <string_view>
#include <tuple>

namespace hlp
{
// TODO:DOC THIS
/**
 * @brief
 */
struct Field
{
    size_t start_;
    size_t end_;
    bool is_escaped;
    bool is_quoted;

    inline const int end() const { return end_; }

    inline const int len() const { return is_quoted ? end_ - start_ - 2 : end_ - start_; }

    inline const int start() const { return is_quoted ? start_ + 1 : start_; }
};

// TODO:DOC THIS
std::optional<Field> getField(const char* in,
                              size_t pos,
                              size_t size,
                              const char delimiter,
                              const char quote,
                              const char ecsape,
                              bool s);

// TODO:DOC THIS
void unescape(bool is_escaped, std::string& vs, std::string_view escape);

// TODO:DOC THIS
void updateDoc(json::Json& doc,
               std::string_view hdr,
               std::string_view val,
               bool is_escaped,
               std::string_view escape);

} // namespace hlp
#endif // WAZUH_ENGINE_PARSE_FIELD_HPP
