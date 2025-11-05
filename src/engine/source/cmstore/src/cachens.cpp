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
    std::shared_lock lock(m_mutex);
    json::Json j {};
    j.setArray();
    for (const auto& [uuid, nameType] : m_uuidToNameTypeMap)
    {
        json::Json entry;
        entry.setString(uuid, KEY_PATH_UUID);
        entry.setString(std::get<0>(nameType), KEY_PATH_NAME);
        entry.setString(std::string(resourceTypeToString(std::get<1>(nameType))), KEY_PATH_TYPE);
        j.appendJson(entry);
    }
    return j;
}

void CacheNS::deserialize(const json::Json& j)
{
    std::unique_lock lock(m_mutex);
    m_uuidToNameTypeMap.clear();
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

        addEntry(uuid, name, type);
    }
}


void CacheNS::reset()
{
    std::unique_lock lock(m_mutex);
    m_uuidToNameTypeMap.clear();
    m_nameTypeToUUIDMap.clear();
}

void CacheNS::addEntry(const std::string& uuid, const std::string& name, ResourceType type)
{
    std::unique_lock lock(m_mutex);
    NameType nameType = std::make_tuple(name, type);
    if (m_uuidToNameTypeMap.find(uuid) != m_uuidToNameTypeMap.end())
    {
        throw std::runtime_error("UUID already exists in cache: " + uuid);
    }
    if (m_nameTypeToUUIDMap.find(nameType) != m_nameTypeToUUIDMap.end())
    {
        throw std::runtime_error("Name-Type pair already exists in cache: " + name + " - "
                                 + std::string(resourceTypeToString(type)));
    }

    m_uuidToNameTypeMap[uuid] = nameType;
    m_nameTypeToUUIDMap[nameType] = uuid;
}

void CacheNS::removeEntryByUUID(const std::string& uuid)
{
    std::unique_lock lock(m_mutex);
    auto it = m_uuidToNameTypeMap.find(uuid);
    if (it != m_uuidToNameTypeMap.end())
    {
        NameType nameType = it->second;
        m_uuidToNameTypeMap.erase(it);
        m_nameTypeToUUIDMap.erase(nameType);
    }
}

void CacheNS::removeEntryByNameType(const std::string& name, ResourceType type)
{
    std::unique_lock lock(m_mutex);
    NameType nameType = std::make_tuple(name, type);
    auto it = m_nameTypeToUUIDMap.find(nameType);
    if (it != m_nameTypeToUUIDMap.end())
    {
        std::string uuid = it->second;
        m_nameTypeToUUIDMap.erase(it);
        m_uuidToNameTypeMap.erase(uuid);
    }
}

std::optional<NameType> CacheNS::getNameTypeByUUID(const std::string& uuid) const
{
    std::shared_lock lock(m_mutex);
    auto it = m_uuidToNameTypeMap.find(uuid);
    if (it != m_uuidToNameTypeMap.end())
    {
        return it->second;
    }
    return std::nullopt;
}

std::optional<std::string> CacheNS::getUUIDByNameType(const std::string& name, ResourceType type) const
{
    std::shared_lock lock(m_mutex);
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
    std::shared_lock lock(m_mutex);
    return m_uuidToNameTypeMap.find(uuid) != m_uuidToNameTypeMap.end();
}

bool CacheNS::existsNameType(const std::string& name, ResourceType type) const
{
    std::shared_lock lock(m_mutex);
    NameType nameType = std::make_tuple(name, type);
    return m_nameTypeToUUIDMap.find(nameType) != m_nameTypeToUUIDMap.end();
}

} // namespace cm::store
