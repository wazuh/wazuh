#ifndef _STORE_MANAGER_H
#define _STORE_MANAGER_H

#include <memory>
#include <optional>
#include <variant>

#include <json/json.hpp>

#include "shared.hpp"

/**
 * @brief Store functionallity.
 *
 */
namespace store
{

/**
 * @brief Store read interfaz.
 *
 * This exposes the ability to get jsons from the store.
 *
 */
class IStoreRead
{
public:
    virtual ~IStoreRead() = default;

    /**
     * @brief Get a json from the store.
     *
     * @param name Name of the json to get.
     * @return std::variant<json::Json, Error> The json or an error.
     */
    virtual std::variant<json::Json, Error> get(const Name& name) const = 0;
};

/**
 * @brief Store read/write interfaz.
 *
 * This exposes the ability to add, delete and get jsons from the store.
 *
 */
class IStore : public IStoreRead
{
public:
    virtual ~IStore() = default;

    /**
     * @brief Add a json to the store.
     *
     * @param name Name of the json to add.
     * @param content Json to add.
     * @return std::optional<Error> An error if the operation failed.
     */
    virtual std::optional<Error> add(const Name& name, const json::Json& content) = 0;

    /**
     * @brief Delete a json from the store.
     *
     * @param name Name of the json to delete.
     * @return std::optional<Error> An error if the operation failed.
     */
    virtual std::optional<Error> del(const Name& name) = 0;
};

} // namespace store
#endif // _STORE_MANAGER_H
