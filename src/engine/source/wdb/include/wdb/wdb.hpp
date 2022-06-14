
#ifndef _WDB_H
#define _WDB_H

#include <filesystem>
#include <map>
#include <string>

#include <utils/socketInterface/unixSecureStream.hpp>

namespace wazuhdb
{

enum class QueryResultCodes
{
    OK,     ///< Command processed successfully
    DUE,    ///< Command processed successfully with pending data
    ERROR,  ///< An error occurred
    IGNORE, ///< Command ignored
    UNKNOWN ///< Unknown status / Unknown protocol
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
    base::utils::socketInterface::unixSecureStream m_socket; ///< Socket to the wdb

public:
    /** @brief Create a WazuhDB object from a path
     *
     * @param path Path to the wdb socket
     */
    WazuhDB(std::string_view strPath = WDB_PATH)
        : m_socket(strPath) {};

    /** @brief Destructor */
    ~WazuhDB() = default;

    /**
     * @brief Connect to the wdb socket
     *
     * @throw std::runtime_error if cannot connect to the wdb socket
     */
    void connect() { m_socket.sConnect(); };

    /**
     * @brief perform a query to the wdb socket
     *
     * @param query Query to perform
     * @return std::string Result of the query. Empty if the query is empty or too long.
     *
     * @throw socketinterface::RecoverableError if cannot perform the query because the
     * remote socket is closed (EPIPE, ECONNRESET or gracefully closed).
     * @throw std::runtime_error if cannot perform the query because of other reasons.
     */
    std::string query(const std::string& query);

    /**
     * @brief Try to perform a query to the wdb socket `attempts` times
     *
     * @param query Query to perform
     * @param attempts Number of attempts to perform the query
     * @return std::string Result of the query. Empty if the query fail (And log the
     * error).
     */
    std::string tryQuery(const std::string& query,
                         const unsigned int attempts = 2) noexcept;

    /**
     * @brief Parse a query result
     *
     * @param result Result of the query
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    std::tuple<QueryResultCodes, std::optional<std::string>>
    parseResult(const std::string& result) const noexcept;

    /**
     * @brief Perform a query and parse result
     *
     * @param query Query to perform
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     *
     * @throw socketinterface::RecoverableError if cannot perform the query because the
     * remote socket is closed (EPIPE, ECONNRESET or gracefully closed).
     * @throw std::runtime_error if cannot perform the query because of other reasons.
     */
    std::tuple<QueryResultCodes, std::optional<std::string>>
    queryAndParseResult(const std::string& query);

    /**
     * @brief Try perform a query and parse result `attempts` times
     *
     * @param query Query to perform
     * @param attempts Number of attempts to perform the query
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    std::tuple<QueryResultCodes, std::optional<std::string>>
    tryQueryAndParseResult(const std::string& query,
                           const unsigned int attempts = 2) noexcept;

    auto getQueryMaxSize() const noexcept { return this->m_socket.getMaxMsgSize(); };
};
} // namespace wazuhdb
#endif
