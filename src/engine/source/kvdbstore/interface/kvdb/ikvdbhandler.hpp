#ifndef _KVDB_IKVDBHANDLER_H
#define _KVDB_IKVDBHANDLER_H

#include <optional>
#include <string>

#include <base/json.hpp>

namespace kvdbStore
{
/**
 * @brief Read-only view over a single in-memory KVDB.
 *
 * A handler is bound to exactly one logical database (namespace, dbName).
 * Keys are plain strings (field names in the original JSON), and values are
 * exposed as json::Json object.
 */
class IKVDBHandler
{
public:
    virtual ~IKVDBHandler() = default;

    /**
     * @brief Lookup @p key and return a const reference to the stored JSON value.
     *
     * If present, the reference aliases the exact JSON node stored in the KV map
     * (object, array, number, boolean, string or null).
     *
     * @param key Entry name inside the KVDB.
     * @return const reference to the JSON value.
     * @throws std::out_of_range if the key is not found, or the underlying map is not available.
     */
    virtual const json::Json& get(const std::string& key) const = 0;

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
