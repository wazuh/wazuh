#include "dbsync.hpp"
#include <stdexcept>
#include <string>
#include <hashHelper.h>

// TODO: description for the class
// TODO: maybe call this sth else
class Recovery{
public:
    /**
     * @brief Calculate the checksum-of-checksums for a table
     * @param dbHandle DBSync handle for database operations
     * @param tableName The table to calculate checksum for
     * @return The SHA1 checksum-of-checksums as a hex string
     */
    static std::string calculateTableChecksum(DBSYNC_HANDLE dbHandle, const std::string& tableName)
    {
        DBSync db(dbHandle);
        std::string concatenated_checksums = db.getConcatenatedChecksums(tableName);

        // Build checksum-of-checksums
        Utils::HashData hash(Utils::HashType::Sha1);
        std::string final_checksum;

        hash.update(concatenated_checksums.c_str(), concatenated_checksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        final_checksum = Utils::asciiToHex(hashResult);

        return final_checksum;
    }

    static int64_t getLastSyncTime(DBSYNC_HANDLE dbHandle, const std::string& tableName)
    {
        DBSync db(dbHandle);
        int64_t lastSyncTime = 0;

        auto callback = [&lastSyncTime, &tableName](ReturnTypeCallback result, const nlohmann::json & data)
            {
                if (result == ReturnTypeCallback::SELECTED)
                {
                    if (!data.contains("last_sync_time")) {
                        throw std::runtime_error(tableName + " does not contain a last_sync_time attribute.");
                    }
                    lastSyncTime = data.at("last_sync_time").get<int64_t>();
                }
            };

        auto selectQuery = SelectQuery::builder()
            .table("table_metadata")
            .columnList({"last_sync_time"})
            .rowFilter("WHERE table_name = '" + tableName + "'")
            .build();

        db.selectRows(selectQuery.query(), callback);

        return lastSyncTime;
    }

    static void updateLastSyncTime(DBSYNC_HANDLE dbHandle, const std::string& tableName, int64_t timestamp)
    {
        DBSync db(dbHandle);
        auto emptyCallback = [](ReturnTypeCallback, const nlohmann::json&) {};

        auto syncQuery = SyncRowQuery::builder()
            .table("table_metadata")
            .data(nlohmann::json{{"table_name", tableName}, {"last_sync_time", timestamp}})
            .build();

        db.syncRow(syncQuery.query(), emptyCallback);
    }
};
