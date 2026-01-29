#ifndef _KVDBIOC_IREADONLY_HANDLER_HPP
#define _KVDBIOC_IREADONLY_HANDLER_HPP

#include <memory>
#include <string_view>

#include <base/error.hpp>
#include <base/json.hpp>

#include <kvdbioc/types.hpp>

namespace kvdb
{
class DbInstance;

/**
 * Read-only KVDB handler.
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
    virtual json::Json get(std::string_view key) const = 0;

    /**
     * @brief Atomic load of current DB instance (for hot-swap).
     * Exposed for testing and advanced usage.
     */
    virtual std::shared_ptr<const DbInstance> load() const noexcept = 0;

    /**
     * @brief Atomic store of new DB instance (for hot-swap).
     * Exposed for testing and manager operations.
     */
    virtual void store(std::shared_ptr<const DbInstance> next) noexcept = 0;

    /**
     * @brief Check if handler has a DB instance loaded.
     */
    virtual bool hasInstance() const noexcept = 0;
};
} // namespace kvdb

#endif // _KVDBIOC_IREADONLY_HANDLER_HPP
