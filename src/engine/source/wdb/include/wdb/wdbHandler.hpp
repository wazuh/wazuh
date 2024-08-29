
#ifndef _WDB_WDB_HANDLER_H
#define _WDB_WDB_HANDLER_H

#include <filesystem>
#include <map>
#include <optional>
#include <string>

#include <sockiface/isockHandler.hpp>
#include <wdb/iwdbHandler.hpp>

namespace wazuhdb
{

constexpr std::string_view CFG_AR_SOCK_PATH {"/var/ossec/queue/alerts/cfgarq"};
constexpr std::string_view WDB_SOCK_PATH {"/var/ossec/queue/db/wdb"};

constexpr auto SOCKET_NOT_CONNECTED {-1}; ///< Socket not connected (status)

/**
 * @brief WazuhDB class
 *
 * This class is used to interact with the WazuhDB database.
 *
 * @warning Not a thread-safe implementation.
 */
class WDBHandler final : public IWDBHandler
{
private:
    // State and configuration
    std::shared_ptr<sockiface::ISockHandler> m_socket; ///< Socket to the wdb

public:
    /** @brief Create a WazuhDB object from a path
     *
     * @param path Path to the wdb socket
     */
    WDBHandler(std::shared_ptr<sockiface::ISockHandler> socket)
        : m_socket(socket) {};

    /** @brief Destructor */
    ~WDBHandler() = default;

    /**
     * @brief Connect to the wdb socket
     *
     * @throw std::runtime_error if cannot connect to the wdb socket
     */
    void connect() override { m_socket->socketConnect(); };

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
    std::string query(const std::string& query) override;

    /**
     * @brief Try to perform a query to the wdb socket `attempts` times
     *
     * @param query Query to perform
     * @param attempts Number of attempts to perform the query
     * @return std::string Result of the query. Empty if the query fail (And log the
     * error).
     */
    std::string tryQuery(const std::string& query, uint attempts) noexcept override;

    /**
     * @brief Parse a query result
     *
     * @param result Result of the query
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    std::tuple<QueryResultCodes, std::optional<std::string>>
    parseResult(const std::string& result) const noexcept override;

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
    std::tuple<QueryResultCodes, std::optional<std::string>> queryAndParseResult(const std::string& query) override;

    /**
     * @brief Try perform a query and parse result `attempts` times
     *
     * @param query Query to perform
     * @param attempts Number of attempts to perform the query
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    std::tuple<QueryResultCodes, std::optional<std::string>>
    tryQueryAndParseResult(const std::string& query, const unsigned int attempts) noexcept override;

    size_t getQueryMaxSize() const noexcept override { return this->m_socket->getMaxMsgSize(); };
};
} // namespace wazuhdb
#endif // _WDB_WDB_HANDLER_H
