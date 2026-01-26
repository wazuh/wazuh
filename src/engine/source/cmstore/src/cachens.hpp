#ifndef _CMSTORE_CACHENS_HPP
#define _CMSTORE_CACHENS_HPP

#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <tuple>
#include <unordered_map>

#include <base/json.hpp>

#include <cmstore/types.hpp>

namespace cm::store
{
using NameType = std::tuple<std::string, ResourceType>;

// Entry structure to hold name and type
struct EntryData
{
    std::string name;
    ResourceType type;
};

// Hash function for NameType to be used in unordered_map
struct NameTypeHash
{
    std::size_t operator()(const NameType& nt) const noexcept
    {
        std::size_t h1 = std::hash<std::string> {}(std::get<0>(nt));
        std::size_t h2 = std::hash<uint8_t> {}(static_cast<uint8_t>(std::get<1>(nt)));
        return h1 ^ (h2 << 1); // Combine hashes
    }
};

/**
 * @brief Bidirectional cache for UUID to name-type mappings.
 *
 * This class maintains two internal hash maps to provide O(1) lookup times
 * for both UUID-to-entry-data and name-type-to-UUID queries.
 * @warning This class is not thread-safe. External synchronization is required for concurrent access.
 */
class CacheNS
{
private:
    std::unordered_map<std::string, EntryData> m_uuidToEntryMap; ///< Map from UUID to EntryData (Name, Type)
    std::unordered_map<NameType, std::string, NameTypeHash> m_nameTypeToUUIDMap; ///< Map from (Name, Type) to UUID
public:
    CacheNS() = default;
    ~CacheNS() = default;

    /**
     * @brief Clears all entries from the cache.
     */
    void reset();

    /**
     * @brief Serializes the cache to a JSON object.
     * @return json::Json The serialized JSON representation of the cache.
     */
    json::Json serialize() const;

    /**
     * @brief Deserializes the cache from a JSON object.
     * @param j The JSON object to deserialize from.
     * @note This will clear any existing entries in the cache before deserialization.
     * @throw std::runtime_error if the JSON format is invalid.
     */
    void deserialize(const json::Json& j);

    /**
     * @brief Adds a new entry to the cache with the specified UUID, name, and type.
     * @param uuid The unique identifier string
     * @param name The resource name
     * @param type The resource type
     * @throw std::runtime_error if the UUID or name-type pair already exists in the cache
     */
    void addEntry(const std::string& uuid, const std::string& name, ResourceType type);

    /**
     * @brief Removes an entry from the cache using its UUID.
     * @param uuid The UUID of the entry to remove
     */
    void removeEntryByUUID(const std::string& uuid);

    /**
     * @brief Removes an entry from the cache using its name and type.
     * @param name The name of the entry to remove
     * @param type The type of the entry to remove
     */
    void removeEntryByNameType(const std::string& name, ResourceType type);

    /**
     * @brief Retrieves the entry data associated with the given UUID.
     *
     * @param uuid The UUID to look up
     * @return std::optional<EntryData> The entry data if found, std::nullopt otherwise
     */
    std::optional<EntryData> getEntryByUUID(const std::string& uuid) const;

    /**
     * @brief Retrieve entry data associated with the given NameType
     *
     */
    std::optional<EntryData> getEntryByNameType(const std::string& name, ResourceType type) const;

    /**
     * @brief Retrieves the name-type pair associated with the given UUID.
     *
     * @param uuid The UUID to look up
     * @return std::optional<NameType> The name-type pair if found, std::nullopt otherwise
     */
    std::optional<NameType> getNameTypeByUUID(const std::string& uuid) const;

    /**
     * @brief Retrieves the UUID associated with the given name and type.
     * @param name The name to look up
     * @param type The type to look up
     * @return std::optional<std::string> The UUID if found, std::nullopt otherwise
     */
    std::optional<std::string> getUUIDByNameType(const std::string& name, ResourceType type) const;

    /**
     * @brief Checks if a UUID exists in the cache.
     * @param uuid The UUID to check
     * @return true if the UUID exists, false otherwise
     */
    bool existsUUID(const std::string& uuid) const;
    /**
     * @brief Checks if a name-type pair exists in the cache.
     * @param name The name to check
     * @param type The type to check
     * @return true if the name-type pair exists, false otherwise
     */
    bool existsNameType(const std::string& name, ResourceType type) const;

    /**
     * @brief Get all entries of a specific resource type.
     *
     * @param type ResourceType to filter
     * @return std::vector<std::tuple<std::string, std::string>> Vector of tuples with (UUID, Name)
     */
    std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type) const;
};

} // namespace cm::store

#endif // _CMSTORE_CACHENS_HPP
