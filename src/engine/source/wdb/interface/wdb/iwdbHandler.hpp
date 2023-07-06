#ifndef _WDB_IWDB_HANDLER_HPP
#define _WDB_IWDB_HANDLER_HPP

#include <optional>
#include <string>
#include <tuple>

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
constexpr auto qrcToStr(QueryResultCodes code)
{
    switch (code)
    {
        case QueryResultCodes::OK: return "ok";
        case QueryResultCodes::DUE: return "due";
        case QueryResultCodes::ERROR: return "err";
        case QueryResultCodes::IGNORE: return "ign";
        default: return "unknown";
    }
}

constexpr auto strToQrc(std::string_view str)
{
    if (str == qrcToStr(QueryResultCodes::OK))
        return QueryResultCodes::OK;
    else if (str == qrcToStr(QueryResultCodes::DUE))
        return QueryResultCodes::DUE;
    else if (str == qrcToStr(QueryResultCodes::ERROR))
        return QueryResultCodes::ERROR;
    else if (str == qrcToStr(QueryResultCodes::IGNORE))
        return QueryResultCodes::IGNORE;
    else
        return QueryResultCodes::UNKNOWN;
}

constexpr auto DEFAULT_TRY_ATTEMPTS = 2;

class IWDBHandler
{
public:
    virtual ~IWDBHandler() = default;

    /**
     * @brief Connect to the wdb socket
     *
     * @throw std::runtime_error if cannot connect to the wdb socket
     */
    virtual void connect() = 0;

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
    virtual std::string query(const std::string& query) = 0;

    /**
     * @brief perform a query to the wdb socket
     *
     * @param query Query to perform
     * @param attempts Number of attempts to perform the query
     * @return std::string Result of the query. Empty if the query is empty or too long.
     *
     * @throw socketinterface::RecoverableError if cannot perform the query because the
     * remote socket is closed (EPIPE, ECONNRESET or gracefully closed).
     * @throw std::runtime_error if cannot perform the query because of other reasons.
     */
    virtual std::string tryQuery(const std::string& query, uint attempts) noexcept = 0;

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
    std::string tryQuery(const std::string& query) noexcept { return tryQuery(query, DEFAULT_TRY_ATTEMPTS); }

    /**
     * @brief Parse a query result
     *
     * @param result Result of the query
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    virtual std::tuple<QueryResultCodes, std::optional<std::string>>
    parseResult(const std::string& result) const noexcept = 0;

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
    virtual std::tuple<QueryResultCodes, std::optional<std::string>> queryAndParseResult(const std::string& query) = 0;

    /**
     * @brief Try perform a query and parse result `attempts` times
     *
     * @param query Query to perform
     * @param attempts Number of attempts to perform the query
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    virtual std::tuple<QueryResultCodes, std::optional<std::string>> tryQueryAndParseResult(const std::string& query,
                                                                                            uint attempts) noexcept = 0;

    /**
     * @brief Try perform a query and parse result `attempts` times
     *
     * @param query Query to perform
     * @return std::tuple<QueryResultCodes, std::optional<std::string>> Tuple with the
     * code and the optional data (payload)
     */
    std::tuple<QueryResultCodes, std::optional<std::string>> tryQueryAndParseResult(const std::string& query) noexcept
    {
        return tryQueryAndParseResult(query, DEFAULT_TRY_ATTEMPTS);
    }

    virtual size_t getQueryMaxSize() const noexcept = 0;
};
} // namespace wazuhdb

#endif // _WDB_IWDB_HANDLER_HPP
