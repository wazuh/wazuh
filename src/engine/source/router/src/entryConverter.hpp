#ifndef ROUTER_ENTRY_CONVERTER_HPP
#define ROUTER_ENTRY_CONVERTER_HPP

#include <exception>
#include <list>
#include <optional>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <router/types.hpp>

namespace router
{

class EntryConverter
{
public:
    EntryConverter() = delete;

    explicit EntryConverter(const test::Entry& entry); ///< Converts from test::Entry to EntryConverter
    explicit EntryConverter(const prod::Entry& entry); ///< Converts from prod::Entry to EntryConverter
    explicit EntryConverter(const json::Json& jEntry); ///< Converts from json::Json to EntryConverter

    const std::string& name() const;                       ///< Returns the name of the entry
    const std::string& policy() const;                     ///< Returns the policy of the entry
    const std::optional<std::string>& description() const; ///< Returns the description of the entry
    const std::optional<int64_t>& lifetime() const;        ///< Returns the lifetime of the entry
    const std::optional<int64_t>& lastUse() const;         ///< Returns the lastUse of the entry

    explicit operator json::Json() const;      ///< Converts from EntryConverter to json::Json
    explicit operator test::EntryPost() const; ///< Converts from EntryConverter to test::EntryPost
    explicit operator prod::EntryPost() const; ///< Converts from EntryConverter to prod::EntryPost

    static std::vector<EntryConverter>
    fromJsonArray(const json::Json& json); ///< Converts from json::Json to std::vector<EntryConverter>

    template<typename EntryType>
    static json::Json
    toJsonArray(const std::list<EntryType>& entries); ///< Converts from std::list<EntryType> to json::Json

private:
    std::string m_name;
    std::string m_policy;
    std::optional<std::string> m_description;
    std::optional<int64_t> m_lifetime;
    std::optional<int64_t> m_lastUse;
    std::optional<std::string> m_filter;
    std::optional<size_t> m_priority;

    static constexpr auto NAME_PATH = "/name";
    static constexpr auto POLICY_PATH = "/policy";
    static constexpr auto DESCRIPTION_PATH = "/description";
    static constexpr auto LIFETIME_PATH = "/lifetime";
    static constexpr auto LAST_USE_PATH = "/lastUse";
    static constexpr auto FILTER_PATH = "/filter";
    static constexpr auto PRIORITY_PATH = "/priority";
};

} // namespace router

#endif // ROUTER_ENTRY_CONVERTER_HPP
