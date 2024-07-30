#include "wdbHandler.hpp"

#include <iostream>
#include <unistd.h>

#include <base/logging.hpp>

namespace wazuhdb
{

using RecoverableError = sockiface::ISockHandler::RecoverableError;
using SendRetval = sockiface::ISockHandler::SendRetval;

std::string WDBHandler::query(const std::string& query)
{
    std::string result {};

    if (0 == query.length())
    {
        LOG_WARNING("Engine WDB: The query to send is empty.");
        return {};
    }
    else if (query.length() > m_socket->getMaxMsgSize())
    {
        LOG_WARNING("Engine WDB: The query to send is too long: {} characters (Maximum allowed size is {} characters).",
                    query.length(),
                    m_socket->getMaxMsgSize());
        return {};
    }

    // Send the query (connect if not connected) ), throw runtime_error if cannot send
    const auto sendStatus {m_socket->sendMsg(query)};
    if (SendRetval::SUCCESS == sendStatus)
    {
        // Receive the result, throw runtime_error if cannot receive
        result = m_socket->recvString();
    }
    else if (SendRetval::SOCKET_ERROR == sendStatus)
    {
        const auto msgError {fmt::format("Engine WDB: sendMsg() method failed: {} ({})", strerror(errno), errno)};
        throw std::runtime_error(msgError);
    }
    else
    {
        // SIZE_ZERO, SIZE_TOO_LONG never reach here
        const auto logicErrorStr {
            fmt::format("Engine WDB: sendMsg() method reached a condition that should never happen (Query status = {})",
                        sendStatus == SendRetval::SIZE_ZERO ? 1 : 2)};
        throw std::logic_error(logicErrorStr);
    }

    return result;
}

std::tuple<QueryResultCodes, std::optional<std::string>>
WDBHandler::parseResult(const std::string& result) const noexcept
{

    QueryResultCodes code {QueryResultCodes::OK};
    std::optional<std::string> payload {};

    /* Split code and payload: (<code> | <code> <payload>) */
    std::string_view codeStr {};
    const auto splitIndex {result.find(' ')};
    if (std::string::npos != splitIndex)
    {
        payload = result.length() + 1 > splitIndex ? result.substr(splitIndex + 1) : "";
        codeStr = std::string_view {result.c_str(), splitIndex};
    }
    else
    {
        codeStr = result;
    }

    /* Map the code string to the enum */
    code = strToQrc(codeStr);
    if (code == QueryResultCodes::UNKNOWN)
    {
        if (result.length() > 0)
        {
            LOG_ERROR("Engine WDB: Unknown query result code. Message received: '{}'.", result);
        }
        payload = {};
    }

    return std::make_tuple(code, std::move(payload));
}

std::string WDBHandler::tryQuery(const std::string& query, uint attempts) noexcept
{

    std::string result {};
    std::optional<std::string> disconnectError {};

    for (unsigned int i {0}; i < attempts; i++)
    {
        try
        {
            result = this->query(query);
            break;
        }
        catch (const RecoverableError& e)
        {
            LOG_DEBUG("Engine WDB: Query failed (attempt {}): {}.", i, e.what());
            disconnectError = e.what();
            try
            {
                this->m_socket->socketConnect();
            }
            catch (const std::runtime_error& e)
            {
                LOG_ERROR("Engine WDB: Reconnect attempt {} failed: {}.", i + 1, e.what());
                continue;
            }
        }
        catch (const std::runtime_error& e)
        {
            LOG_WARNING("Engine WDB: WDBHandler::tryQuery() method failed in an irrecuperable way: {}.", e.what());
            this->m_socket->socketDisconnect();
            break;
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Engine WDB: WDBHandler::tryQuery() method failed in an irrecuperable way: {}.", e.what());
            this->m_socket->socketDisconnect();
            break;
        }
        catch (...)
        {
            LOG_WARNING("Engine WDB: WDBHandler::tryQuery() method failed in an irrecuperable way: unknown error.");
            this->m_socket->socketDisconnect();
            break;
        }
    }

    if (0 == result.length() && disconnectError.has_value())
    {
        LOG_WARNING("Engine WDB: WDBHandler::tryQuery() method failed: {}.", disconnectError.value());
    }

    return result;
}

std::tuple<QueryResultCodes, std::optional<std::string>> WDBHandler::queryAndParseResult(const std::string& q)
{
    auto result {query(q)};
    return parseResult(result);
}

std::tuple<QueryResultCodes, std::optional<std::string>>
WDBHandler::tryQueryAndParseResult(const std::string& q, const uint attempts) noexcept
{
    auto result {tryQuery(q, attempts)};
    return parseResult(result);
}

} // namespace wazuhdb
