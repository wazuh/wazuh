#ifndef _KVDB_H
#define _KVDB_H

#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>
#include <variant>

#include <json/json.hpp>
#include <utils/baseMacros.hpp>

constexpr static const char* DEFAULT_CF_NAME {"default"};

class KVDB
{
public:
    enum class CreationStatus
    {
        OkCreated,
        OkInitialized,
        ErrorDatabaseAlreadyExists,
        ErrorDatabaseBusy,
        ErrorUnknown
    };

    /**
     * @brief Construct a new KVDB object
     *
     * @param dbName name of the DB
     * @param folder where the DB will be stored
     */
    KVDB(const std::string& dbName, const std::string& folder);

    KVDB();

    /**
     * @brief Destroy the KVDB object
     *
     */
    ~KVDB();

    /**
     *
     * @brief Open and initialize the db
     *
     * @param createIfMissing if true, creates the database when it does not exist
     * @param errorIfExists if true, it generates an error when the database does exist
     */
    CreationStatus init(bool createIfMissing = true, bool errorIfExists = false);

    /**
     * @brief Get the db name
     *
     */
    std::string_view getName() const;

    /**
     * @brief Returns if the db is ready for operation
     *
     */
    bool isReady() const;

    /**
     * @brief Returns if the db was initialized
     *
     */
    bool isValid() const;

    /**
     * @brief Create a Column object
     *
     * @param columnName name of the object that will be created
     * @return true successfull creation of Column in DB
     * @return false unsuccessfull creation or already created object
     */
    bool createColumn(const std::string& columnName);

    /**
     * @brief Delete a Column object
     *
     * @param columnName name of the object that will be deleted
     * @return true successfull deletion of Column in DB
     * @return false unsuccessfull creation or object not found
     */
    // TODO: all the default column names should be changed, one option is to
    // define a KVDB default CF in order to avoid using a deleteColumn or
    // cleanColumn without any argument
    bool deleteColumn(const std::string& columnName);

    /**
     * @brief cleaning of all elements in Column
     //TODO: when trying to clean a default CF rocksdb doesn't allow it: <return
     Status::InvalidArgument("Can't drop default column family")> this needs to
     be fixed differently in order to avoid costly proccess on large DBs.
     * @param columnName that will be cleaned
     * @return true when successfully cleaned
     * @return false when unsuccessfully cleaned
     */
    bool cleanColumn(const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief write a key-value into the DB
     *
     * @param key the key that will be written
     * @param value the value that will be written
     * @param columnName column where to write the key-value
     * @return true If the proccess finished successfully
     * @return false If the proccess didn't finished successfully
     */
    bool write(const std::string& key,
               const std::string& value,
               const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief write a key into the DB
     *
     * @param key the key that will be written
     * @param columnName column where to write the key-value
     * @return true If the proccess finished successfully
     * @return false If the proccess didn't finished successfully
     */
    bool writeKeyOnly(const std::string& key,
                      const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief write vector of pair key values to DB in a pessimistic transaction
     * manner.
     * @param pairsVector input data of string pairs
     * @param columnName where the data will be written to
     * @return true when written and commited without any problem
     * @return false when one or more items weren't succesfully written.
     */
    bool writeToTransaction(
        const std::vector<std::pair<std::string, std::string>>& pairsVector,
        const std::string& columnName = DEFAULT_CF_NAME);
    /**
     * @brief check key existence in Column
     *
     * @param key used to check existence
     * @param columnName where to look for the key
     * @return true if key was found
     * @return false if key wasn't found
     */
    bool hasKey(const std::string& key, const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief read a value from a key inside a CF without value copying
     *
     * @param key where to find the value
     * @param value that the result of the proccess will modify
     * @param columnName where to search the key
     * @return value read If the proccess finished successfully
     * @return nullopt If the proccess didn't finished successfully
     */
    std::variant<std::string, base::Error> read(const std::string& key,
                                    const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief
     * //TODO: this should be returning a PinnableSlice and the consumer should reset it
     * and read it's value. Check what methods should we add in order to decouple rocksdb
     * library from the client, wrapping all the functions and objects needed.
     * @param key key where to find the value
     * @param value value that the result of the proccess will modify
     * @param columnName where to search the key
     * @return true If the proccess finished successfully
     * @return false If the proccess didn't finished successfully
     */
    bool readPinned(const std::string& key,
                    std::string& value,
                    const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief delete a key of a CF
     *
     * @param key that will be deleted
     * @param columnName where to search for the key
     * @return true if the key was successfully deleted
     * @return false if the key wasn't successfully deleted
     */
    std::optional<base::Error> deleteKey(const std::string& key,
                   const std::string& columnName = DEFAULT_CF_NAME);

    /**
     * @brief Returns a JSON array of all pair key-values of a CF
     *
     * @param dump where the result will be stored.
     * @return std::string error message if it could finish properly.
     */
    json::Json jDump();

    /**
     * @brief DB closing cleaning all elements used to acces it
     *
     * @return true succesfully closed
     * @return false unsuccesfully closed
     */
    bool close();

    void cleanupOnClose();

private:
    WAZUH_DISABLE_COPY_ASSIGN(KVDB);
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};

#endif // _KVDB_H
