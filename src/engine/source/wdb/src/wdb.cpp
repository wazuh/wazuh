#include <wdb/wdb.hpp>

#include <iostream>
#include <unistd.h>

#include <logging/logging.hpp>
#include <utils/socketInterface/unixStream.hpp>

namespace wazuhdb
{

using base::utils::socketInterface::RecoverableError;
using base::utils::socketInterface::SendRetval;

std::string WazuhDB::query(const std::string& query)
{
    std::string result {};

    if (query.length() == 0)
    {
        WAZUH_LOG_WARN("wdb: The query to send is empty.");
        return {};
    }
    else if (query.length() > m_socket.getMaxMsgSize())
    {
        WAZUH_LOG_WARN("wdb: The query to send is too long: {}.", query.c_str());
        return {};
    }

    // Send the query (connect if not connected) ), throw runtime_error if cannot send
    const auto sendStatus = m_socket.sendMsg(query);
    if (SendRetval::SUCCESS == sendStatus)
    {
        // Receive the result, throw runtime_error if cannot receive
        result = m_socket.recvString();
    }
    else if (SendRetval::SOCKET_ERROR == sendStatus)
    {
        const auto msgError = fmt::format ("wdb: sendMsg failed: {} ({})",
                                             strerror(errno), errno);
        throw std::runtime_error(msgError);
    }
    else
    {
        // SIZE_ZERO, SIZE_TOO_LONG never reach here
        const auto logicErrorStr =
            "wdb: sendMsg reached a condition that should never happen: ";
        throw std::logic_error(logicErrorStr);
    }

    return result;
}

std::tuple<QueryResultCodes, std::optional<std::string>>
WazuhDB::parseResult(const std::string& result) const noexcept
{

    QueryResultCodes code {QueryResultCodes::OK};
    std::optional<std::string> payload {};

    /* Split code and payload: (<code> | <code> <payload>) */
    std::string_view codeStr {};
    const auto splitIndex {result.find(" ")};
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
    {
        const auto res {QueryResStr2Code.find(codeStr)};
        // If key not found, the code is unknown (protocol error)
        if (QueryResStr2Code.end() == res)
        {
            if (result.length() > 0)
            {
                WAZUH_LOG_ERROR("wdb: Unknown query result code. Message received: {}",
                                result);
            }
            payload = {};
            code = QueryResultCodes::UNKNOWN;
        }
        else
        {
            code = res->second;
        }
    }

    return std::make_tuple(code, std::move(payload));
}

std::string WazuhDB::tryQuery(const std::string& query,
                              const unsigned int attempts) noexcept
{

    std::string result {};
    std::optional<std::string> disconnectError {};

    for (unsigned int i = 0; i < attempts; i++)
    {
        try
        {
            result = this->query(query);
            break;
        }
        catch (const RecoverableError& e)
        {
            WAZUH_LOG_DEBUG("wdb: Query failed (attempt {}): {}", i, e.what());
            disconnectError = e.what();
            try
            {
                this->m_socket.socketConnect();
            }
            catch (const std::runtime_error& e)
            {
                WAZUH_LOG_ERROR("wdb: reconnect attempt {} failed: {}", i + 1, e.what());
                continue;
            }
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_WARN(
                "wdb: tryQuery irrecuperable failed (attempt {}): {}", i, e.what());
            break;
        }
    }

    if (result.length() == 0 && disconnectError.has_value())
    {
        WAZUH_LOG_WARN("wdb: tryQuery failed: {}", disconnectError.value());
    }

    return result;
}

std::tuple<QueryResultCodes, std::optional<std::string>>
WazuhDB::queryAndParseResult(const std::string& query)
{
    auto result {this->query(query)};
    return this->parseResult(result);
}

std::tuple<QueryResultCodes, std::optional<std::string>>
WazuhDB::tryQueryAndParseResult(const std::string& query,
                                const unsigned int attempts) noexcept
{
    auto result {tryQuery(query, attempts)};
    return parseResult(result);
}

} // namespace wazuhdb
