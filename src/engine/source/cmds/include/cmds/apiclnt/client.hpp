#ifndef _APICLNT_CLIENT_HPP
#define _APICLNT_CLIENT_HPP

#include <exception>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include <uvw/pipe.hpp>

#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <error.hpp>

#include <cmds/apiExcept.hpp>

namespace cmd::apiclnt
{
class Client
{
private:
    std::string m_socketPath;
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::PipeHandle> m_clientHandle;

public:
    Client(const std::string& socketPath)
        : m_socketPath(socketPath)
        , m_loop(uvw::Loop::getDefault())
        , m_clientHandle(m_loop->resource<uvw::PipeHandle>())
    {
    }

    base::utils::wazuhProtocol::WazuhResponse send(const base::utils::wazuhProtocol::WazuhRequest& request)
    {
        // Prepare request
        auto requestStr = request.toStr();

        // Add protocol header
        int32_t length = requestStr.size();
        std::unique_ptr<char[]> buffer(new char[sizeof(length) + length]);
        std::memcpy(buffer.get(), &length, sizeof(length));
        std::memcpy(buffer.get() + sizeof(length), requestStr.data(), length);
        auto requestWithHeader = std::string(buffer.get(), sizeof(length) + length);

        // Stablish connection, send request and receive response
        auto clientHandle = m_loop->resource<uvw::PipeHandle>();
        std::string error;
        std::string response;
        clientHandle->on<uvw::ErrorEvent>(
            [&error](const uvw::ErrorEvent& event, uvw::PipeHandle& handle)
            {
                error = "Socket communication error: ";
                error += event.what();
                handle.close();
            });

        clientHandle->once<uvw::ConnectEvent>(
            [&requestWithHeader](const uvw::ConnectEvent&, uvw::PipeHandle& handle)
            {
                std::vector<char> buffer {requestWithHeader.begin(), requestWithHeader.end()};
                handle.write(buffer.data(), buffer.size());
                handle.read();
            });

        clientHandle->on<uvw::DataEvent>(
            [&response](const uvw::DataEvent& event, uvw::PipeHandle& handle)
            {
                response = std::string(event.data.get() + sizeof(int), event.length - sizeof(int));
                handle.close();
            });

        clientHandle->once<uvw::EndEvent>([](const uvw::EndEvent&, uvw::PipeHandle& handle) { handle.close(); });

        // Stablish connection
        clientHandle->connect(m_socketPath);
        m_loop->run();

        // Return response
        if (!error.empty())
        {
            throw ClientException(error, ClientException::Type::SOCKET_COMMUNICATION_ERROR);
        }

        // Parse response
        base::utils::wazuhProtocol::WazuhResponse parsedResponse;
        try
        {
            parsedResponse = base::utils::wazuhProtocol::WazuhResponse::fromStr(response);
        }
        catch (const std::exception& e)
        {
            throw ClientException("Invalid response from server: " + std::string(e.what()),
                                  ClientException::Type::INVALID_RESPONSE_FROM_SERVER);
        }

        return parsedResponse;
    }
};
} // namespace cmd::apiclnt

#endif // _APICLNT_CLIENT_HPP
