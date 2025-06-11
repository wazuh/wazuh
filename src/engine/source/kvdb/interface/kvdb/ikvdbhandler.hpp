#ifndef _I_KVDB_HANDLER_H
#define _I_KVDB_HANDLER_H

#include <list>
#include <map>
#include <string>
#include <utility>
#include <variant>

#include <base/error.hpp>
#include <base/json.hpp>

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
     * @return base::OptError If base::Error not exists the value was stored successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError set(const std::string& key, const std::string& value) = 0;

    /**
     * @brief Stores a Json value in the database given the provided key.
     *
     * @param key Provided key.
     * @param value Provided value. Must be a Json.
     * @return base::OptError If base::Error not exists the value was stored successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError set(const std::string& key, const json::Json& value) = 0;

    /**
     * @brief Stores a key. Treats the DB as a key set for further checking existence of the key.
     *
     * @param key Provided key.
     * @return base::OptError If base::Error not exists the key was stored successfully. Specific error
     * otherwise.
     *
     */
    virtual base::OptError add(const std::string& key) = 0;

    /**
     * @brief Removes a key from the DB.
     *
     * @param key Provided key.
     * @return base::OptError If base::Error not exists the key was removed successfully. Specific error
     * otherwise.
     * @note Trying to delete a key that does not exist does not generate an error.
     *
     */
    virtual base::OptError remove(const std::string& key) = 0;

    /**
     * @brief Checks if a key exists in the DB.
     *
     * @param key Provided key.
     * @return base::RespOrError<bool> True/False if the key exists or not. Specific error otherwise.
     *
     */
    virtual base::RespOrError<bool> contains(const std::string& key) = 0;

    /**
     * @brief Gets the value of a key in string format.
     *
     * @param key Provided key.
     * @return base::RespOrError<std::string> String value of the key. Specific error otherwise.
     */
    virtual base::RespOrError<std::string> get(const std::string& key) = 0;

    /**
     * @brief Retrieves all content with pagination from the database.
     *
     * To retrieve all the contents of the database, without paging, the parameter page and records must be
     * sent in 0.
     *
     * @param page Page number.
     * @param records Quantity of records for page.
     * @return base::RespOrError<std::list<std::pair<std::string, std::string>>> Map of key-value pairs.
     * Specific error otherwise.
     */
    virtual base::RespOrError<std::list<std::pair<std::string, std::string>>> dump(const unsigned int page,
                                                                                   const unsigned int records) = 0;

    /**
     * @brief Retrieves the entire content of the database.
     *
     * @return base::RespOrError<std::list<std::pair<std::string, std::string>>> Map of key-value pairs.
     * Specific error otherwise.
     */
    inline base::RespOrError<std::list<std::pair<std::string, std::string>>> dump() { return dump(0, 0); };

    /**
     * @brief Retrieves all filtered content with pagination of the database.
     *
     * To retrieve all the contents of the database, without paging, the parameter page and records must be
     * sent in 0.
     *
     * @param prefix Filter value.
     * @param page Page number.
     * @param records Quantity of records for page.
     * @return base::RespOrError<std::list<std::pair<std::string, std::string>>> Map of key-value pairs.
     * Specific error otherwise.
     */
    virtual base::RespOrError<std::list<std::pair<std::string, std::string>>>
    search(const std::string& prefix, const unsigned int page, const unsigned int records) = 0;

    /**
     * @brief Retrieves all filtered content of the database.
     *
     * To retrieve all the contents of the database, without paging, the parameter page and records must be
     * sent in 0.
     *
     * @param prefix Filter value.
     * @return base::RespOrError<std::list<std::pair<std::string, std::string>>> Map of key-value pairs.
     * Specific error otherwise.
     */
    inline base::RespOrError<std::list<std::pair<std::string, std::string>>> search(const std::string& prefix)
    {
        return search(prefix, 0, 0);
    };
};

} // namespace kvdbManager

#endif // _I_KVDB_HANDLER_H
