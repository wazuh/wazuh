
#ifndef _WDB_H
#define _WDB_H

#include <filesystem>

/**
 * @brief
 *
 * @warning NOT A THREAD SAFE IMPLEMENTATION
 */
class WazuhDB
{
private:
    constexpr static const char* WDB_PATH {"queue/db/wdb"};
    /** @brief Path to the wdb socket (From the chrooted jail directory) */
    std::filesystem::path path; // Relative by default
    int fd {-1};                                 ///< File descriptor to the wdb socket
public:
    /** @brief Construc from a path */
    WazuhDB(std::string_view strPath = WDB_PATH);
    // Create move copy and assign operators
    /** @brief Destructor */
    ~WazuhDB();
    /** @brief Connect to the wdb socket */
    int connect();
};

#endif
