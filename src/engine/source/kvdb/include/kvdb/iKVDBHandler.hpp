#ifndef _I_KVDB_HANDLER_H
#define _I_KVDB_HANDLER_H

#include <string>
#include <unordered_map>
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
     * @return std::variant<bool, base::Error> True if the value was stored successfully. Specific error otherwise.
     *
    */
    virtual std::variant<bool, base::Error> set(const std::string& key, const std::string& value) = 0;

    /**
     * @brief Stores a Json value in the database given the provided key.
     *
     * @param key Provided key.
     * @param value Provided value. Must be a Json.
     * @return std::variant<bool, base::Error> True if the value was stored successfully. Specific error otherwise.
     *
     */
    virtual std::variant<bool, base::Error> set(const std::string& key, const json::Json& value) = 0;

    /**
     * @brief Stores a key. Treats the DB as a key set for further checking existence of the key.
     *
     * @param key Provided key.
     * @return std::variant<bool, base::Error> True if the key was stored successfully. Specific error otherwise.
     *
     */
    virtual std::variant<bool, base::Error> add(const std::string& key) = 0;

    /**
     * @brief Removes a key from the DB.
     *
     * @param key Provided key.
     * @return std::variant<bool, base::Error> True if the key was removed successfully. Specific error otherwise.
     *
     */
    virtual std::variant<bool, base::Error> remove(const std::string& key) = 0;

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
     * @return std::variant<std::unordered_map<std::string, std::string>, base::Error> Map of key-value pairs. Specific error otherwise.
     */
    virtual std::variant<std::unordered_map<std::string, std::string>, base::Error> dump() = 0;
};

} // namespace kvdbManager

#endif // _I_KVDB_HANDLER_H
