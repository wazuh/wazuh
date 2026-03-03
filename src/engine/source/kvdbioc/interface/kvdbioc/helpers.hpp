#ifndef KVDBIOC_HELPERS_HPP
#define KVDBIOC_HELPERS_HPP

#include <string_view>

#include <base/json.hpp>

#include <kvdbioc/iManager.hpp>

namespace kvdbioc::details
{

inline constexpr std::string_view IOC_NAME_KEY = "/name"; ///< JSON pointer to the IOC name field, used as the key in KVDB
inline constexpr std::string_view IOC_TYPE_KEY = "/type"; ///< JSON pointer to the IOC type field, used for type inference

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

/**
 * @brief Parse a string into an IOCType enum value.
 *
 * @param key The string representation of the IOC type.
 * @return IOCType The corresponding enum value, or IOCType::UNKNOWN if not recognized.
 */
inline constexpr IOCType parseIOCType(std::string_view key)
{
    if (key == "connection")
        return IOCType::CONNECTION;
    else if (key == "url-full")
        return IOCType::URL_FULL;
    else if (key == "url-domain")
        return IOCType::URL_DOMAIN;
    else if (key == "hash_md5")
        return IOCType::HASH_MD5;
    else if (key == "hash_sha1")
        return IOCType::HASH_SHA1;
    else if (key == "hash_sha256")
        return IOCType::HASH_SHA256;
    return IOCType::UNKNOWN;
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
 * @brief Get the DB name corresponding to a given IOC type.
 *
 * @param type The IOCType enum value representing the type of the IOC.
 * @return std::string_view The name of the database corresponding to the IOC type.
 * @throws std::runtime_error if the IOC type is unknown.
 */
inline constexpr std::string_view dbNameFromType(IOCType type)
{
    switch (type)
    {
        case IOCType::CONNECTION: return "ioc-connections";
        case IOCType::URL_FULL: return "ioc-urls-full";
        case IOCType::URL_DOMAIN: return "ioc-urls-domain";
        case IOCType::HASH_MD5: return "ioc-hashes-md5";
        case IOCType::HASH_SHA1: return "ioc-hashes-sha1";
        case IOCType::HASH_SHA256: return "ioc-hashes-sha256";
        default: throw std::runtime_error("Unknown IOC type");
    }
}

inline constexpr std::array<std::string_view, static_cast<size_t>(IOCType::DB_COUNT)> DB_NAMES = {
    "ioc-connections", "ioc-urls-full", "ioc-urls-domain", "ioc-hashes-md5", "ioc-hashes-sha1", "ioc-hashes-sha256"};

/**
 * @brief Initialize the required databases in the KVDB if they don't already exist.
 *
 * @param manager The KVDB manager instance to use for DB operations.
 * @throws std::runtime_error on RocksDB errors during DB creation.
 */
inline void initializeDBs(const std::shared_ptr<IKVDBManager>& manager)
{
    for (const auto& dbName : DB_NAMES)
    {
        if (!manager->exists(dbName))
        {
            manager->add(dbName);
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
    IOCType type = parseIOCType(typeStr);
    std::string dbName = std::string(dbNameFromType(type));

    return {dbName, key};
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

} // namespace kvdbioc::details

#endif // KVDBIOC_HELPERS_HPP
