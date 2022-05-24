#include <wdb/wdb.hpp>

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

void WazuhDB::query(std::string_view query, char* response, int length)
{
    // Check the query
    if (query.empty())
    {
        throw std::runtime_error("The query is empty");
    }
    else if (length < 0)
    {
        throw std::runtime_error("The response buffer length is negative");
    }
    else if (response == nullptr)
    {
        throw std::runtime_error("The response buffer is null");
    }

    // Check the connection
    if (this->m_fd == SOCKET_NOT_CONNECTED)
    {
        WAZUH_LOG_DEBUG("Not connected to the wdb socket.. connecting");
        // TODO TRY CATCH
        this->connect();
    }

    // Send the query
    switch (socketinterface::sendMsg(this->m_fd, query.data(), query.size()))
    {

        case socketinterface::INVALID_SOCKET:
            WAZUH_LOG_ERROR("The socket is invalid");
            return; // if reach this point there is an error in logic
        case socketinterface::NULL_PTR:
            WAZUH_LOG_ERROR("The pointer to query is null");
            return; // if reach this point there is an error in logic
        case socketinterface::SIZE_ZERO:
            WAZUH_LOG_ERROR("The size of the query is zero");
            return; // if reach this point there is an error in logic
        case socketinterface::SIZE_TOO_LONG:
            throw std::runtime_error("Query size is too long");
            break;
        case socketinterface::SOCKET_ERROR:
        {
            const std::string errMsg = std::string {"Cannot send the query: "}
                                       + strerror(errno) + " (" + std::to_string(errno)
                                       + ")";
            throw std::runtime_error(errMsg);
        }
        default: break;
    }

    // Go to find the response
    switch (socketinterface::recvMsg(this->m_fd, response, length))
    {
        case socketinterface::INVALID_SOCKET:
            WAZUH_LOG_ERROR("The socket is invalid");
            return; // if reach this point there is an error in logic
        case socketinterface::NULL_PTR:
            WAZUH_LOG_ERROR("The pointer to response is null");
            return; // if reach this point there is an error in logic
        case socketinterface::SIZE_ZERO:
            WAZUH_LOG_ERROR("The size of the response is zero");
            return; // if reach this point there is an error in logic
        case socketinterface::SIZE_TOO_LONG:
            throw std::runtime_error("Response size is too long");
            break;
        case socketinterface::SOCKET_ERROR:
        {
            const std::string errMsg = std::string {"Cannot receive the response: "}
                                       + strerror(errno) + " (" + std::to_string(errno)
                                       + ")";
            throw std::runtime_error(errMsg);
            break;
        }
        case 0: throw std::runtime_error("Timeout or remote gracefully closed"); break;

        default: break;
    }
}

QueryResultCodes WazuhDB::parseResult(char* result, char** payload) {

    // if (result == nullptr)

    // Separete the code result and the payload
    char * wptr {strchr(result, ' ')};

    if (wptr != nullptr) {
        *wptr = '\0';
        wptr++;
    } else {
        wptr = result;
    }

    // Parse payload
    if (payload) {
        *payload = wptr;
    }

    // Parse code
    auto res = QueryResStr2Code.find(result);
    if (res == QueryResStr2Code.end()) {
        return QueryResultCodes::UNKNOWN;
    }
    return res->second;
}

} // namespace wazuhdb
