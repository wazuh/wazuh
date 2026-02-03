#ifndef _KVDBIOC_IREADONLY_HANDLER_HPP
#define _KVDBIOC_IREADONLY_HANDLER_HPP

#include <memory>
#include <string_view>
#include <vector>

#include <base/error.hpp>
#include <base/json.hpp>

#include <kvdbioc/types.hpp>

namespace kvdbioc
{
/**
 * Read-only KVDB handler interface.
 * - Provides read operations (get, multiget)
 * - Exclusive to a single DB name
 * - Transparently follows hot updates
 */
class IReadOnlyKVDBHandler
{
public:
    virtual ~IReadOnlyKVDBHandler() = default;

    /// DB name this handler is bound to (exclusive).
    virtual const DbName& name() const noexcept = 0;

    /**
     * @brief Get value as JSON.
     *
     * Contract:
     * - If key exists: returns json::Json
     * - If key does not exist: throws std::runtime_error (NotFound)
     * - Other failures: throws std::runtime_error
     */
    virtual std::optional<json::Json> get(std::string_view key) const = 0;

    /**
     * @brief Get multiple values as JSON.
     *
     * Contract:
     * - Returns a vector of json::Json, one per key
     * - If a key exists: corresponding entry contains the JSON value
     * - If a key does not exist: corresponding entry contains json::Json() (null)
     * - Other failures: throws std::runtime_error
     */
    virtual std::vector<std::optional<json::Json>> multiGet(const std::vector<std::string_view>& keys) const = 0;

    /**
     * @brief Check if handler has a DB instance loaded.
     */
    virtual bool hasInstance() const noexcept = 0;
};
} // namespace kvdbioc

#endif // _KVDBIOC_IREADONLY_HANDLER_HPP
