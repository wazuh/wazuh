#ifndef IOCKVDB_HELPERS_HPP
#define IOCKVDB_HELPERS_HPP

#include <array>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <base/json.hpp>

#include <iockvdb/iManager.hpp>

namespace ioc::kvdb::details
{

inline constexpr std::string_view IOC_NAME_KEY = "/name"; ///< Path to the IOC name field, used as the key in KVDB
inline constexpr std::string_view IOC_TYPE_KEY = "/type"; ///< Path to the IOC type field, used for type inference

/**
 * @brief Enumeration of supported IOC types for type inference and DB routing
 *
 * Used to determine which DB an IOC should be stored in based on its type field.
 * The type field is expected to be a string in the IOC document, which is parsed into this enum.
 */
enum class IOCType
{
    CONNECTION = 0,
    URL_FULL = 1,
    URL_DOMAIN = 2,
    HASH_MD5 = 3,
    HASH_SHA1 = 4,
    HASH_SHA256 = 5,
    UNKNOWN = 6,
    DB_COUNT = UNKNOWN
};

struct IOCTypeInfo
{
    std::string_view typeKey; ///< Value expected in IOC "/type"
    IOCType type;
    std::string_view dbName; ///< Target KVDB name
};

// Single source of truth: add new types ONLY here.
constexpr std::array<IOCTypeInfo, 6> IOC_TYPE_TABLE {{
    {"connection", IOCType::CONNECTION, "ioc_connections"},
    {"url_full", IOCType::URL_FULL, "ioc_urls_full"},
    {"url_domain", IOCType::URL_DOMAIN, "ioc_urls_domain"},
    {"hash_md5", IOCType::HASH_MD5, "ioc_hashes_md5"},
    {"hash_sha1", IOCType::HASH_SHA1, "ioc_hashes_sha1"},
    {"hash_sha256", IOCType::HASH_SHA256, "ioc_hashes_sha256"},
}};

inline std::optional<IOCTypeInfo> findIOCTypeInfo(std::string_view key) noexcept
{
    for (const auto& e : IOC_TYPE_TABLE)
    {
        if (e.typeKey == key)
        {
            return e;
        }
    }
    return std::nullopt;
}

inline IOCType parseIOCType(std::string_view key) noexcept
{
    auto info = findIOCTypeInfo(key);
    return info ? info->type : IOCType::UNKNOWN;
}

/**
 * @brief Get the list of supported IOC types
 *
 * This function returns all IOC type strings defined in IOC_TYPE_TABLE.
 * When adding new IOC types, only update IOC_TYPE_TABLE - no need to modify this function.
 *
 * @return std::vector<std::string_view> List of supported IOC type strings
 */
inline std::vector<std::string_view> getSupportedIocTypes()
{
    std::vector<std::string_view> out;
    out.reserve(IOC_TYPE_TABLE.size());
    for (const auto& e : IOC_TYPE_TABLE)
    {
        out.push_back(e.typeKey);
    }
    return out;
}

/**
 * @brief Get the Key From IOC document
 *
 * @param iocDoc The JSON document representing the IOC, expected to contain a "name" field.
 * @return std::string The value of the "name" field, which is used as the key in the KVDB.
 */
inline std::string getKeyFromIOC(const json::Json& iocDoc)
{
    auto name = iocDoc.getString(IOC_NAME_KEY); // Get the name field as the key
    if (!name.has_value() || name->empty())
    {
        throw std::runtime_error("IOC document is missing a valid 'name' field");
    }
    return name.value();
}

/**
 * @brief Get the Type From IOC document
 *
 * @param iocDoc The JSON document representing the IOC, expected to contain a "type" field.
 * @return std::string The value of the "type" field, which is used for type inference and DB routing.
 */
inline std::string getTypeFromIOC(const json::Json& iocDoc)
{
    auto type = iocDoc.getString(IOC_TYPE_KEY); // Get the type field for type inference
    if (!type.has_value() || type->empty())
    {
        throw std::runtime_error("IOC document is missing a valid 'type' field");
    }
    return type.value();
}

/**
 * @brief Initialize the required databases in the KVDB if they don't already exist.
 *
 * @param manager The KVDB manager instance to use for DB operations.
 * @param suffix Optional suffix to append to database names (e.g., for temporary databases).
 * @throws std::runtime_error on RocksDB errors during DB creation.
 */
inline void initializeDBs(const std::shared_ptr<IKVDBManager>& manager, std::string_view suffix = "")
{
    for (const auto& entry : IOC_TYPE_TABLE)
    {
        std::string fullDbName =
            suffix.empty() ? std::string(entry.dbName) : std::string(entry.dbName) + std::string(suffix);

        if (!manager->exists(fullDbName))
        {
            manager->add(fullDbName);
        }
    }
}

/**
 * @brief Extract the DB name and key from an IOC document.
 *
 * @param iocDoc The JSON document representing the IOC, expected to contain "name" and "type" fields.
 * @return std::pair<std::string, std::string> A pair containing the DB name (determined by the IOC type) and the key
 * (the IOC name).
 */
inline std::pair<std::string, std::string> getDbAndKeyFromIOC(const json::Json& iocDoc)
{
    std::string key = getKeyFromIOC(iocDoc);
    std::string typeStr = getTypeFromIOC(iocDoc);

    auto info = findIOCTypeInfo(typeStr);
    if (!info)
    {
        throw std::runtime_error("Unknown IOC type: " + typeStr);
    }

    return {std::string {info->dbName}, key};
}

/**
 * @brief Update a value in the KVDB, appending to an array if the key already exists.
 *
 * @param manager The KVDB manager instance to use for DB operations.
 * @param dbName The name of the database to update.
 * @param key The key to update in the database.
 * @param newValue The new JSON value to add. If the key already exists, this value will be appended to the existing
 * value as an array.
 * @throws std::runtime_error if the DB doesn't exist or on RocksDB errors.
 */
inline void updateValueInDB(const std::shared_ptr<IKVDBManager>& manager,
                            const std::string& dbName,
                            const std::string& key,
                            const json::Json& newValue)
{
    // Check if key exists in DB
    auto existingValueOpt = manager->get(dbName, key);

    if (!existingValueOpt.has_value())
    {
        manager->put(dbName, key, newValue.str());
        return;
    }

    auto& candidateValue = existingValueOpt.value();
    if (!candidateValue.isArray())
    {
        auto oldValue = candidateValue;
        candidateValue.setArray();
        candidateValue.appendJson(oldValue);
    }
    candidateValue.appendJson(newValue);
    manager->put(dbName, key, candidateValue.str());
}

/**
 * @brief Get the target DB name for a given IOC type string.
 *
 * @param typeStr The IOC type as a string, expected to match one of the entries in IOC_TYPE_TABLE.
 * @return std::string_view The corresponding DB name for the given IOC type.
 * @throw std::runtime_error if the IOC type is unknown.
 */
inline std::string_view getDbNameFromType(std::string_view typeStr)
{
    auto info = findIOCTypeInfo(typeStr);
    if (!info)
    {
        throw std::runtime_error("Unknown IOC type: " + std::string(typeStr));
    }
    return info->dbName;
}

} // namespace ioc::kvdb::details

#endif // IOCKVDB_HELPERS_HPP
