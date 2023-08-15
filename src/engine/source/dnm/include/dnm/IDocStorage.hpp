#ifndef DNM_IDOC_STORAGE_HPP
#define DNM_IDOC_STORAGE_HPP

#include <list>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include <error.hpp>
#include <json/json.hpp>
#include <name.hpp>

#include <dnm/types.hpp>

/**
 * @brief Low-level Store interface.
 *
 */
namespace dnm
{

/**
 * @brief Interface for reading and writing to the store.
 *
 * This interface exposes the ability to:
 * - Read a JSON from the store.
 * - Write a JSON to the store.
 * - Update a JSON in the store.
 * - Remove a JSON from the store.
 * - Upsert a JSON in the store.
 * - List documents and collections under a Key.
 * - Check if a Key is a document or a collection.
 */
class IDocumentStorage
{
public:
    virtual ~IDocumentStorage() = default;

    /**
     * @brief Read a JSON from the store.
     *
     * @param key The key to read from.
     * @return std::variant<json::Json, base::Error> The JSON or an error.
     */
    virtual std::variant<json::Json, base::Error> read(const base::Name& key) const = 0;

    /**
     * @brief Write a JSON to the store.
     *
     * @param key The key to write to.
     * @param json The JSON to write.
     * @return std::optional<base::Error> An error if one occurred.
     */
    virtual std::optional<base::Error> write(const base::Name& key, const json::Json& json) = 0;

    /**
     * @brief Update a JSON in the store.
     *
     * @param key The key to update.
     * @param json The JSON to update with.
     * @return std::optional<base::Error> An error if one occurred.
     */
    virtual std::optional<base::Error> update(const base::Name& key, const json::Json& json) = 0;

    /**
     * @brief Remove a JSON from the store.
     *
     * @param key The key to remove.
     * @return std::optional<base::Error> An error if one occurred.
     */
    virtual std::optional<base::Error> remove(const base::Name& key) = 0;

    /**
     * @brief Upsert a JSON in the store.
     *
     * @param key The key to upsert.
     * @param json The JSON to upsert.
     * @return std::optional<base::Error> An error if one occurred.
     */
    virtual std::optional<base::Error> upsert(const base::Name& key, const json::Json& json) = 0;

    /**
     * @brief List documents and collections under a Key.
     *
     * @param key The key to list under.
     * @return std::variant<std::list<base::Name>, base::Error> A list of keys or an error.
     */
    virtual std::variant<std::list<std::pair<base::Name, KeyType>>, base::Error> list(const base::Name& key) const = 0;

    /**
     * @brief Check if a Key is a document or a collection.
     *
     * @param key The key to check.
     * @return std::variant<base::Name, base::Error> The key or an error.
     */
    virtual std::variant<KeyType, base::Error> getType(const base::Name& key) const = 0;
};

} // namespace dnm
#endif // _STORE_DOC_STORAGE_HPP
