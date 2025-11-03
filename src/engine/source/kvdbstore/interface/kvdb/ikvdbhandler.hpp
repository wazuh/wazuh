#ifndef _KVDB_IKVDBHANDLER_H
#define _KVDB_IKVDBHANDLER_H

#include <optional>
#include <string>
#include <string_view>

namespace kvdbStore
{
/**
 * @brief Read-only view over a single in-memory KVDB.
 *
 * A handler is bound to exactly one logical database (namespace, dbName).
 * Keys are plain strings (field names in the original JSON), and values are
 * exposed as JSON-serialized string views into stable storage owned by the map.
 */
class IKVDBHandler
{
public:
    virtual ~IKVDBHandler() = default;

    /**
     * @brief Lookup @p key and return a view of its JSON-serialized value.
     *
     * If present, the view refers to the exact serialized JSON stored in the KV map
     * (object, array, number, boolean, string or null).
     *
     * @param key Entry name inside the KVDB.
     * @return std::nullopt if the key does not exist; otherwise a std::string_view
     *         pointing to stable storage owned by the KV map. The view becomes invalid
     *         if the underlying map is destroyed or replaced.
     */
    virtual std::optional<std::string_view> get(const std::string& key) const noexcept = 0;

    /**
     * @brief Check whether @p key exists in this KVDB.
     *
     * @param key Entry name inside the KVDB.
     * @return true if present; false otherwise.
     */
    virtual bool contains(const std::string& key) const noexcept = 0;
};

} // namespace kvdbStore

#endif // _KVDB_IKVDBHANDLER_H
