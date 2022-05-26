
#ifndef _WDB_H
#define _WDB_H

#include <filesystem>

#include <map>
#include <string>

namespace wazuhdb
{

enum class QueryResultCodes
{
    OK,     ///< Command processed successfully
    DUE,    ///< Command processed successfully with pending data
    ERROR,  ///< An error occurred
    IGNORE, ///< Command ignored
    UNKNOWN ///< Unknown status
};

/** Assoiates the result (string) of a query with a queryResult enum */
const static std::map<std::string_view, QueryResultCodes> QueryResStr2Code = {
    {"ok", QueryResultCodes::OK},
    {"due", QueryResultCodes::DUE},
    {"err", QueryResultCodes::ERROR},
    {"ign", QueryResultCodes::IGNORE}};

constexpr auto WDB_PATH {"queue/db/wdb"}; ///< Default wdb socket path
constexpr auto SOCKET_NOT_CONNECTED {-1}; ///< Socket not connected (status)

/**
 * @brief WazuhDB class
 *
 * This class is used to interact with the WazuhDB database.
 *
 * @warning Not a thread-safe implementation.
 */
class WazuhDB final
{
private:
    // State and configuration
    const std::filesystem::path m_path; ///< WDB socket path
    int m_fd {SOCKET_NOT_CONNECTED};    ///< File descriptor to the wdb socket

public:
    /** @brief Create a WazuhDB object from a path
     *
     * @param path Path to the wdb socket
     */
    WazuhDB(std::string_view strPath = WDB_PATH)
        : m_path(strPath) {};

    // TODO: Create move copy and assign operators

    /** @brief Destructor */
    ~WazuhDB();

    /**
     * @brief Connect to the wdb socket
     *
     * @throw std::runtime_error if cannot connect to the wdb socket
     */
    void connect();

    /**
     * @brief Send a query to the wdb socket
     *
     * @param query Query to send
     * @return std::string Result of the query. Empty if the query is empty or too long.
     *
     * @throw socketinterface::RecoverableError if cannot send the query because the
     * remote socket is closed (EPIPE, ECONNRESET or gracefully closed).
     * @throw std::runtime_error if cannot send the query because of other reasons.
     */
    std::string query(const std::string& query);

    // QueryResultCodes parseResult(char* result, char** payload);
};
} // namespace wazuhdb
#endif
