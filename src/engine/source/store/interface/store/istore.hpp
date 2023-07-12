#ifndef _STORE_MANAGER_H
#define _STORE_MANAGER_H

#include <memory>
#include <optional>
#include <variant>

#include <error.hpp>
#include <json/json.hpp>
#include <name.hpp>

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
     * @param name base::Name of the json to get.
     * @return std::variant<json::Json, base::Error> The json or an error.
     */
    virtual std::variant<json::Json, base::Error> get(const base::Name& name) const = 0;
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
     * @param name base::Name of the json to add.
     * @param content Json to add.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> add(const base::Name& name, const json::Json& content) = 0;

    /**
     * @brief Delete a json from the store.
     *
     * @param name base::Name of the json to delete.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> del(const base::Name& name) = 0;

    /**
     * @brief Update a json in the store.
     *
     * @param name base::Name of the json to update.
     * @param content Json to update.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> update(const base::Name& name, const json::Json& content) = 0;

    /**
     * @brief Update a json in the store, creating it if it doesn't exist.
     *
     * @param name base::Name of the json to update.
     * @param content Json to update.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> addUpdate(const base::Name& name, const json::Json& content) = 0;
};

} // namespace store
#endif // _STORE_MANAGER_H
