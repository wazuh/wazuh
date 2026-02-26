// EntryConverter.cpp
#include "entryConverter.hpp"
#include <stdexcept>

namespace router
{

EntryConverter::EntryConverter(const test::Entry& entry)
    : m_name {entry.name()}
    , m_namespace {entry.namespaceId()}
    , m_description {entry.description()}
    , m_lifetime {entry.lifetime()}
    , m_lastUse {entry.lastUse()}
{
}

EntryConverter::EntryConverter(const prod::Entry& entry)
    : m_name {entry.name()}
    , m_namespace {entry.namespaceId()}
    , m_description {entry.description()}
    , m_priority {entry.priority()}
{
}

EntryConverter::EntryConverter(const json::Json& jEntry)
{
    auto name = jEntry.getString(NAME_PATH);
    auto namespaceId = jEntry.getString(NAMESPACE_PATH);
    if (!name || !namespaceId)
    {
        throw std::runtime_error {"Cannot load the entry: name or namespace is missing"};
    }

    m_name = name.value();
    m_namespace = namespaceId.value();
    m_description = jEntry.getString(DESCRIPTION_PATH);
    m_lifetime = jEntry.getInt64(LIFETIME_PATH);
    m_lastUse = jEntry.getInt64(LAST_USE_PATH);
    m_priority = jEntry.getInt64(PRIORITY_PATH);
}

const std::string& EntryConverter::name() const
{
    return m_name;
}
const std::string& EntryConverter::namespaceId() const
{
    return m_namespace;
}
const std::optional<std::string>& EntryConverter::description() const
{
    return m_description;
}
const std::optional<int64_t>& EntryConverter::lifetime() const
{
    return m_lifetime;
}
const std::optional<int64_t>& EntryConverter::lastUse() const
{
    return m_lastUse;
}

EntryConverter::operator json::Json() const
{
    json::Json jEntry {};

    jEntry.setString(m_name, NAME_PATH);
    jEntry.setString(m_namespace, NAMESPACE_PATH);

    if (m_description)
    {
        jEntry.setString(m_description.value(), DESCRIPTION_PATH);
    }

    if (m_lifetime)
    {
        jEntry.setInt64(m_lifetime.value(), LIFETIME_PATH);
    }

    if (m_lastUse)
    {
        jEntry.setInt64(m_lastUse.value(), LAST_USE_PATH);
    }

    if (m_priority)
    {
        jEntry.setInt64(static_cast<int64_t>(m_priority.value()), PRIORITY_PATH);
    }

    return jEntry;
}

EntryConverter::operator test::EntryPost() const
{
    if (!m_lifetime)
    {
        throw std::runtime_error {"Cannot load the entry: lifetime is missing"};
    }

    const auto& namespaceId = cm::store::NamespaceId(m_namespace);
    auto entryPost = test::EntryPost(m_name, namespaceId, m_lifetime.value());
    if (m_description)
    {
        entryPost.description(m_description.value());
    }

    return entryPost;
}

EntryConverter::operator prod::EntryPost() const
{
    if (!m_priority)
    {
        throw std::runtime_error {"Cannot load the entry: priority is missing"};
    }

    const auto& namespaceId = cm::store::NamespaceId(m_namespace);
    auto entryPost = prod::EntryPost(m_name, namespaceId, m_priority.value());
    if (m_description)
    {
        entryPost.description(m_description.value());
    }

    return entryPost;
}

std::vector<EntryConverter> EntryConverter::fromJsonArray(const json::Json& json)
{
    std::optional<std::vector<json::Json>> jArrayEntries = json.getArray();
    if (!jArrayEntries)
    {
        throw std::runtime_error {"Cannot get routes table from store. Invalid table format"};
    }

    std::vector<EntryConverter> entries {};
    for (const auto& jEntry : jArrayEntries.value())
    {
        entries.emplace_back(jEntry);
    }

    return entries;
}

template<typename EntryType>
json::Json EntryConverter::toJsonArray(const std::list<EntryType>& entries)
{
    json::Json jArray;
    jArray.setArray();

    for (const auto& entry : entries)
    {
        jArray.appendJson(json::Json(EntryConverter(entry)));
    }
    return jArray;
}

template json::Json EntryConverter::toJsonArray<test::Entry>(const std::list<test::Entry>& entries);
template json::Json EntryConverter::toJsonArray<prod::Entry>(const std::list<prod::Entry>& entries);

} // namespace router
