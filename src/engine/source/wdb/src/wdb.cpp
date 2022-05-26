#include <wdb/wdb.hpp>

#include <iostream>
#include <unistd.h>

#include <logging/logging.hpp>

#include "unixSocketInterface.hpp"

namespace wazuhdb
{

WazuhDB::~WazuhDB()
{
    if (this->m_fd > 0)
    {
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
        const std::string msg {"The wdb socket does not a socket:" + m_path.string()};
        throw std::runtime_error(msg);
    }

    if (this->m_fd != SOCKET_NOT_CONNECTED)
    {
        WAZUH_LOG_DEBUG("Already connected to the wdb socket.. closing it");
        close(this->m_fd);
        this->m_fd = SOCKET_NOT_CONNECTED;
    }

    this->m_fd = socketinterface::socketConnect(m_path.c_str());
};

std::string WazuhDB::query(const std::string& query)
{
    std::string result {};

    if (query.length() == 0)
    {
        WAZUH_LOG_WARN("wdb: query to send its empty");
        return {};
    }
    else if (query.length() > socketinterface::MSG_MAX_SIZE)
    {
        WAZUH_LOG_WARN("wdb: query to send its too long: {}", query.c_str());
    }

    // Check the connection
    if (SOCKET_NOT_CONNECTED == this->m_fd)
    {
        WAZUH_LOG_DEBUG("Not connected to the wdb socket.. connecting");
        // runtime_error if cannot connect
        this->connect();
    }

    // Send the query, throw runtime_error if cannot send
    const auto sendStatus = socketinterface::sendMsg(this->m_fd, query);

    if (socketinterface::CommRetval::SUCCESS == sendStatus)
    {
        // Receive the result, throw runtime_error if cannot receive
        result = socketinterface::recvString(this->m_fd);
    }
    else if (socketinterface::CommRetval::SOCKET_ERROR == sendStatus)
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
                               + socketinterface::CommRetval2Str.at(sendStatus));
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
        code = (QueryResStr2Code.end() == res) ? QueryResultCodes::UNKNOWN : res->second;
    }

    return std::make_tuple(code, std::move(payload));
}
} // namespace wazuhdb
