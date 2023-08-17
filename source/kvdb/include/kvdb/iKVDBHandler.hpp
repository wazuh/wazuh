#ifndef _I_KVDB_HANDLER_H
#define _I_KVDB_HANDLER_H

#include <list>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

#include <error.hpp>
#include <json/json.hpp>

namespace kvdbManager
{

/**
 * @brief Interface of KVDB Handler. Holds the basic operations to interact with the database.
 *
 */
class IKVDBHandler
{
public:
    /**
     * @brief Stores a string value in the database given the provided key.
     *
     * @param key Provided key.
     * @param value Provided value. Must be a string.
     * @return std::variant<base::Error> If base::Error not exists the value was stored successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> set(const std::string& key, const std::string& value) = 0;

    /**
     * @brief Stores a Json value in the database given the provided key.
     *
     * @param key Provided key.
     * @param value Provided value. Must be a Json.
     * @return std::optional<base::Error> If base::Error not exists the value was stored successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> set(const std::string& key, const json::Json& value) = 0;

    /**
     * @brief Stores a key. Treats the DB as a key set for further checking existence of the key.
     *
     * @param key Provided key.
     * @return std::optional<base::Error> If base::Error not exists the key was stored successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> add(const std::string& key) = 0;

    /**
     * @brief Removes a key from the DB.
     *
     * @param key Provided key.
     * @return std::variant<base::Error> If base::Error not exists the key was removed successfully. Specific error
     * otherwise.
     *
     */
    virtual std::optional<base::Error> remove(const std::string& key) = 0;

    /**
     * @brief Checks if a key exists in the DB.
     *
     * @param key Provided key.
     * @return std::variant<bool, base::Error> True/False if the key exists or not. Specific error otherwise.
     *
     */
    virtual std::variant<bool, base::Error> contains(const std::string& key) = 0;

    /**
     * @brief Gets the value of a key in string format.
     *
     * @param key Provided key.
     * @return std::variant<std::string, base::Error> String value of the key. Specific error otherwise.
     */
    virtual std::variant<std::string, base::Error> get(const std::string& key) = 0;

    /**
     * @brief Retrieves the entire content of the DB.
     *
     * @param page Page number.
     * @param records Quantity of records for page.
     * @return std::variant<std::list<std::pair<std::string, std::string>>, base::Error> Map of key-value pairs.
     * Specific error otherwise.
     */
    virtual std::variant<std::list<std::pair<std::string, std::string>>, base::Error> dump(const uint32_t page,
                                                                                           const uint32_t records) = 0;
    /**
     * @brief Retrieves all filtered content.
     *
     * @param key Filter value.
     * @return std::variant<std::unordered_map<std::string, std::string>, base::Error> Map of key-value pairs. Specific
     * error otherwise.
     */
    virtual std::variant<std::unordered_map<std::string, std::string>, base::Error>
    search(const std::string& prefix) = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_HANDLER_H
