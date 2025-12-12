#pragma once

#include "idbsync.hpp"
#include <stdexcept>
#include <string>
#include <hashHelper.h>

/*
 * Common recovery methods used by FIM, SCA and IT Hygiene modules.
 */
class Recovery{
public:
    /**
     * @brief Calculate the checksum-of-checksums for a table
     * @param dbSync IDBSync object for database operations
     * @param tableName The table to calculate checksum for
     * @return The SHA1 checksum-of-checksums as a hex string
     */
    static std::string calculateTableChecksum(IDBSync& dbSync, const std::string& tableName)
    {
        std::string concatenated_checksums = dbSync.getConcatenatedChecksums(tableName);

        // Build checksum-of-checksums
        Utils::HashData hash(Utils::HashType::Sha1);
        std::string final_checksum;

        hash.update(concatenated_checksums.c_str(), concatenated_checksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        final_checksum = Utils::asciiToHex(hashResult);

        return final_checksum;
    }
};
