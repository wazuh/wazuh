#pragma once

#include "builder.hpp"
#include "commonDefs.h"
#include "json.hpp"

#include <functional>
#include <string>

using ResultCallbackData = const std::function<void(ReturnTypeCallback, const nlohmann::json&)>;

class IDBSync
{
    public:
        /// @brief DBSync Destructor.
        virtual ~IDBSync() = default;

        /// @brief Generates triggers that execute actions to maintain consistency between tables.
        /// @param jsInput      JSON information with tables relationship.
        virtual void addTableRelationship(const nlohmann::json& jsInput) = 0;

        /// @brief Insert the \p jsInsert data in the database.
        /// @param jsInsert JSON information with values to be inserted.
        virtual void insertData(const nlohmann::json& jsInsert) = 0;

        /// @brief Sets the max rows in the \p table table.
        /// @param table    Table name to apply the max rows configuration.
        /// @param maxRows  Max rows number to be applied in the table \p table table.
        /// @details The table will work as a queue if the limit is exceeded.
        virtual void setTableMaxRow(const std::string& table, const long long maxRows) = 0;

        /// @brief Inserts (or modifies) a database record.
        /// @param jsInput        JSON information used to add/modified a database record.
        /// @param callbackData   Result callback(std::function) will be called for each result.
        virtual void syncRow(const nlohmann::json& jsInput, ResultCallbackData callbackData) = 0;

        /// @brief Select data, based in \p jsInput data, from the database table.
        /// @param jsInput         JSON with table name, fields and filters to apply in the query.
        /// @param callbackData    Result callback(std::function) will be called for each result.
        virtual void selectRows(const nlohmann::json& jsInput, ResultCallbackData callbackData) = 0;

        /// @brief Deletes a database table record and its relationships based on \p jsInput value.
        /// @param jsInput JSON information to be applied/deleted in the database.
        virtual void deleteRows(const nlohmann::json& jsInput) = 0;

        /// @brief Updates data table with \p jsInput information. \p jsResult value will
        ///  hold/contain the results of this operation (rows insertion, modification and/or deletion).
        /// @param jsInput    JSON information with snapshot values.
        /// @param jsResult   JSON with deletes, creations and modifications (diffs) in rows.
        virtual void updateWithSnapshot(const nlohmann::json& jsInput, nlohmann::json& jsResult) = 0;

        /// @brief Update data table, based on json_raw_snapshot bulk data based on json string.
        /// @param jsInput       JSON with snapshot values.
        /// @param callbackData  Result callback(std::function) will be called for each result.
        virtual void updateWithSnapshot(const nlohmann::json& jsInput, ResultCallbackData callbackData) = 0;

        /// @brief Get current dbsync handle in the instance.
        /// @return DBSYNC_HANDLE to be used in all internal calls.
        virtual DBSYNC_HANDLE handle() = 0;

        /// @brief Closes the database connection and deletes the database file using the stored path.
        virtual void closeAndDeleteDatabase() = 0;

        /// @brief Gets the concatenated checksums from all the elements of a table
        /// @param tableName Name of the table to query
        /// @return the concatenated checksum
        virtual std::string getConcatenatedChecksums(const std::string& tableName) = 0;

        /// @brief Gets the concatenated checksums from a filtered set of elements
        /// @param tableName The table to read from
        /// @param rowFilter Filter applied to the query
        /// @return the concatenated checksum
        virtual std::string getConcatenatedChecksums(const std::string& tableName,
                                                     const std::string& rowFilter) = 0;

        /// @brief Calculate the checksum-of-checksums for a table
        /// @param tableName The table to calculate checksum for
        /// @return The SHA1 checksum-of-checksums as a hex string
        virtual std::string calculateTableChecksum(const std::string& tableName) = 0;

        /// @brief Calculate the checksum-of-checksums for a filtered set of elements
        /// @param tableName The table to calculate checksum for
        /// @param rowFilter Filter applied to the query
        /// @return The SHA1 checksum-of-checksums as a hex string
        virtual std::string calculateTableChecksum(const std::string& tableName,
                                                   const std::string& rowFilter) = 0;

        /// @brief Increases the version of each entry in a table by 1
        /// @param tableName Name of the table to update
        /// @throws std::exception if an error occurs during the version update
        virtual void increaseEachEntryVersion(const std::string& tableName) = 0;

        /// @brief Gets all synced elements from a table (WHERE sync = 1)
        /// @param tableName Name of the table to query
        /// @return Vector of JSON objects representing all rows where sync = 1
        virtual std::vector<nlohmann::json> getEverySyncElement(const std::string& tableName) = 0;
};
