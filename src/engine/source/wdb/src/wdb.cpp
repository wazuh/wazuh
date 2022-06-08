#include <wdb/wdb.hpp>

#include <iostream>
#include <unistd.h>

#include <logging/logging.hpp>
#include <utils/socketInterface/unixStream.hpp>

namespace wazuhdb
{

namespace socketCommin = base::utils::socketInterface;
namespace unixStreamSocket = base::utils::socketInterface::unixStream;

WazuhDB::~WazuhDB()
{
    if (0 < this->m_fd)
    {
        WAZUH_LOG_DEBUG("Closing the wdb conexion...");
        close(this->m_fd);
    }
};

void WazuhDB::connect()
{
    if (std::filesystem::exists(m_path) == false)
    {
        const std::string msg {"The wdb socket does not exist:" + m_path.string()};
        throw std::runtime_error(msg);
    }
    else if (std::filesystem::is_socket(m_path) == false)
    {
        const std::string msg {"The wdb socket path is not a socket:" + m_path.string()};
        throw std::runtime_error(msg);
    }

    if (SOCKET_NOT_CONNECTED != this->m_fd)
    {
        WAZUH_LOG_INFO("Reconnecting to wdb socket.");
        close(this->m_fd);
        this->m_fd = SOCKET_NOT_CONNECTED;
    }

    this->m_fd = unixStreamSocket::socketConnect(m_path.c_str());
};

std::string WazuhDB::query(const std::string& query)
{
    std::string result {};

    if (query.length() == 0)
    {
        WAZUH_LOG_WARN("wdb: The query to send is empty.");
        return {};
    }
    else if (query.length() > unixStreamSocket::MSG_MAX_SIZE)
    {
        WAZUH_LOG_WARN("wdb: The query to send is too long: {}.", query.c_str());
        return {};
    }

    // Check the connection
    if (SOCKET_NOT_CONNECTED == this->m_fd)
    {
        WAZUH_LOG_DEBUG("Not connected to the wdb socket.. connecting");
        // runtime_error if cannot connect
        this->connect();
    }

    // Send the query, throw runtime_error if cannot send
    const auto sendStatus = unixStreamSocket::sendMsg(this->m_fd, query);

    if (socketCommin::CommRetval::SUCCESS == sendStatus)
    {
        // Receive the result, throw runtime_error if cannot receive
        result = unixStreamSocket::recvString(this->m_fd);
    }
    else if (socketCommin::CommRetval::SOCKET_ERROR == sendStatus)
    {
        const auto msgError = std::string {"wdb: sendMsg failed: "} + std::strerror(errno)
                              + " (" + std::to_string(errno) + ")";
        throw std::runtime_error(msgError);
    }
    else
    {
        // INVALID_SOCKET, SIZE_ZERO, SIZE_TOO_LONG never reach here
        const auto logicErrorStr =
            "wdb: sendMsg reached a condition that should never happen: ";
        throw std::logic_error(logicErrorStr
                               + socketCommin::CommRetval2Str.at(sendStatus));
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
        catch (const unixStreamSocket::RecoverableError& e)
        {
            WAZUH_LOG_DEBUG("wdb: Query failed (attempt {}): {}", i, e.what());
            disconnectError = e.what();
            try
            {
                this->connect();
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
