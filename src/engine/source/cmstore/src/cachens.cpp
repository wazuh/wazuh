#include "cachens.hpp"

constexpr std::string_view KEY_PATH_UUID = "/uuid";
constexpr std::string_view KEY_PATH_NAME = "/name";
constexpr std::string_view KEY_PATH_TYPE = "/type";

namespace cm::store
{
using NameType = std::tuple<std::string, ResourceType>;

// Private

json::Json CacheNS::serialize() const
{
    json::Json j {};
    j.setArray();
    for (const auto& [uuid, entryData] : m_uuidToEntryMap)
    {
        json::Json entry;
        entry.setString(uuid, KEY_PATH_UUID);
        entry.setString(entryData.name, KEY_PATH_NAME);
        entry.setString(std::string(resourceTypeToString(entryData.type)), KEY_PATH_TYPE);
        j.appendJson(entry);
    }
    return j;
}

void CacheNS::deserialize(const json::Json& j)
{
    m_uuidToEntryMap.clear();
    m_nameTypeToUUIDMap.clear();

    const auto array = j.getArray();

    if (!array.has_value())
    {
        throw std::runtime_error("Invalid JSON format for CacheNS deserialization: expected array");
    }

    const auto& value = array.value();

    for (const auto& entry : value)
    {
        if (!entry.isString(KEY_PATH_UUID) || !entry.isString(KEY_PATH_NAME) || !entry.isString(KEY_PATH_TYPE))
        {
            throw std::runtime_error("Invalid JSON format for CacheNS deserialization: missing required fields");
        }

        std::string uuid = entry.getString(KEY_PATH_UUID).value();
        std::string name = entry.getString(KEY_PATH_NAME).value();
        ResourceType type = resourceTypeFromString(entry.getString(KEY_PATH_TYPE).value());
        // Add entry directly without acquiring lock
        NameType nameType = std::make_tuple(name, type);
        if (m_uuidToEntryMap.find(uuid) != m_uuidToEntryMap.end())
        {
            throw std::runtime_error("UUID already exists in cache: " + uuid);
        }
        if (m_nameTypeToUUIDMap.find(nameType) != m_nameTypeToUUIDMap.end())
        {
            throw std::runtime_error("Name-Type pair already exists in cache: " + name + " - "
                                     + std::string(resourceTypeToString(type)));
        }

        EntryData entryData {name, type};
        m_uuidToEntryMap[uuid] = entryData;
        m_nameTypeToUUIDMap[nameType] = uuid;
    }
}

void CacheNS::reset()
{
    m_uuidToEntryMap.clear();
    m_nameTypeToUUIDMap.clear();
}

void CacheNS::addEntry(const std::string& uuid, const std::string& name, ResourceType type)
{
    NameType nameType = std::make_tuple(name, type);
    if (m_uuidToEntryMap.find(uuid) != m_uuidToEntryMap.end())
    {
        throw std::runtime_error("UUID already exists in cache: " + uuid);
    }
    if (m_nameTypeToUUIDMap.find(nameType) != m_nameTypeToUUIDMap.end())
    {
        throw std::runtime_error("Name-Type pair already exists in cache: " + name + " - "
                                 + std::string(resourceTypeToString(type)));
    }

    EntryData entryData {name, type};
    m_uuidToEntryMap[uuid] = entryData;
    m_nameTypeToUUIDMap[nameType] = uuid;
}

void CacheNS::removeEntryByUUID(const std::string& uuid)
{
    auto it = m_uuidToEntryMap.find(uuid);
    if (it != m_uuidToEntryMap.end())
    {
        NameType nameType = std::make_tuple(it->second.name, it->second.type);
        m_uuidToEntryMap.erase(it);
        m_nameTypeToUUIDMap.erase(nameType);
    }
}

void CacheNS::removeEntryByNameType(const std::string& name, ResourceType type)
{
    NameType nameType = std::make_tuple(name, type);
    auto it = m_nameTypeToUUIDMap.find(nameType);
    if (it != m_nameTypeToUUIDMap.end())
    {
        std::string uuid = it->second;
        m_nameTypeToUUIDMap.erase(it);
        m_uuidToEntryMap.erase(uuid);
    }
}

std::optional<EntryData> CacheNS::getEntryByUUID(const std::string& uuid) const
{
    auto it = m_uuidToEntryMap.find(uuid);
    if (it != m_uuidToEntryMap.end())
    {
        return it->second;
    }
    return std::nullopt;
}

std::optional<EntryData> CacheNS::getEntryByNameType(const std::string& name, ResourceType type) const
{
    NameType nameType = std::make_tuple(name, type);
    auto it = m_nameTypeToUUIDMap.find(nameType);
    if (it != m_nameTypeToUUIDMap.end())
    {
        const std::string& uuid = it->second;
        auto entryIt = m_uuidToEntryMap.find(uuid);
        if (entryIt != m_uuidToEntryMap.end())
        {
            return entryIt->second;
        }
    }
    return std::nullopt;
}

std::optional<NameType> CacheNS::getNameTypeByUUID(const std::string& uuid) const
{
    auto it = m_uuidToEntryMap.find(uuid);
    if (it != m_uuidToEntryMap.end())
    {
        return std::make_tuple(it->second.name, it->second.type);
    }
    return std::nullopt;
}

std::optional<std::string> CacheNS::getUUIDByNameType(const std::string& name, ResourceType type) const
{
    NameType nameType = std::make_tuple(name, type);
    auto it = m_nameTypeToUUIDMap.find(nameType);
    if (it != m_nameTypeToUUIDMap.end())
    {
        return it->second;
    }
    return std::nullopt;
}

bool CacheNS::existsUUID(const std::string& uuid) const
{
    return m_uuidToEntryMap.find(uuid) != m_uuidToEntryMap.end();
}

bool CacheNS::existsNameType(const std::string& name, ResourceType type) const
{
    NameType nameType = std::make_tuple(name, type);
    return m_nameTypeToUUIDMap.find(nameType) != m_nameTypeToUUIDMap.end();
}

std::vector<std::tuple<std::string, std::string>> CacheNS::getCollection(ResourceType type) const
{
    std::vector<std::tuple<std::string, std::string>> collection;
    collection.reserve(m_uuidToEntryMap.size());
    for (const auto& [uuid, entryData] : m_uuidToEntryMap)
    {
        if (entryData.type == type)
        {
            collection.emplace_back(uuid, entryData.name);
        }
    }
    return collection;
}

} // namespace cm::store
