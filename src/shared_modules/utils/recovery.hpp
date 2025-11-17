#include "dbsync.hpp"
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
};
