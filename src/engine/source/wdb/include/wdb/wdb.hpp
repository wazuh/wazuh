
#ifndef _WDB_H
#define _WDB_H

#include <filesystem>

#include <map>
#include <string>

namespace wazuhdb
{
enum class QueryResult
{
    OK,     ///< Command processed successfully
    DUE,    ///< Command processed successfully with pending data
    ERROR,  ///< An error occurred
    IGNORE, ///< Command ignored
    UNKNOWN ///< Unknown status
};

const std::map<const char*, QueryResult> QueryResultStrings = {
    {"ok", QueryResult::OK},
    {"due", QueryResult::DUE },
    {"err", QueryResult::ERROR },
    {"ign", QueryResult::IGNORE }};

/**
 * @brief
 *
 * @warning NOT A THREAD SAFE IMPLEMENTATION
 */
class WazuhDB
{
private:
    constexpr static const char* WDB_PATH {"queue/db/wdb"};
    constexpr static int SOCKET_NOT_CONNECTED {-1};
    /** @brief Path to the wdb socket (From the chrooted jail directory) */
    std::filesystem::path m_path;    // Relative by default
    int m_fd {SOCKET_NOT_CONNECTED}; ///< File descriptor to the wdb socket
public:
    /** @brief Construc from a path */
    WazuhDB(std::string_view strPath = WDB_PATH)
        : m_path(strPath) {};
    // Create move copy and assign operators
    /** @brief Destructor */
    ~WazuhDB();
    /**
     * @brief Connect to the wdb socket
     *
     * @throw std::runtime_error if cannot connect to the wdb socket
     */
    void connect();
    void query(std::string_view query, char* response, int length);
    QueryResult parseResult(char* result, char** payload);
};
} // namespace wazuhdb
#endif
