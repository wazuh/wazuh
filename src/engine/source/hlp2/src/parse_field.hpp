#ifndef WAZUH_ENGINE_PARSE_FIELD_HPP
#define WAZUH_ENGINE_PARSE_FIELD_HPP

#include <tuple>
#include <optional>
#include <string_view>
#include <json/json.hpp>


namespace hlp {

struct Field
{
    size_t start_;
    size_t end_;
    bool is_escaped;
    bool is_quoted;

    inline const int end() const {
        return end_;
    }

    inline const int len() const {
        return is_quoted ? end_-start_-2 : end_-start_;
    }

    inline const int start() const {
        return is_quoted ? start_+1 : start_;
    }
};

std::optional<Field>  getField(const char *in, size_t pos, size_t size, const char delimiter, const char quote, const char ecsape,  bool s);
void unescape(bool is_escaped, std::string & vs, std::string_view escape);
void updateDoc(json::Json & doc, std::string_view hdr, std::string_view val, bool is_escaped, std::string_view escape);

} // hlp namespace
#endif // WAZUH_ENGINE_PARSE_FIELD_HPP
