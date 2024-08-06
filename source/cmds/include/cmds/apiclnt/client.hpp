#ifndef _APICLNT_CLIENT_HPP
#define _APICLNT_CLIENT_HPP

#include <exception>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include <uvw/pipe.h>
#include <uvw/timer.h>

#include <base/error.hpp>
#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>

#include <cmds/apiExcept.hpp>

namespace cmd::apiclnt
{

class Client
{
private:
    std::string m_socketPath;
    int m_timeout;
    std::shared_ptr<uvw::Loop> m_loop;

public:
    Client(const std::string& socketPath, int timeout)
        : m_socketPath(socketPath)
        , m_loop(uvw::Loop::getDefault())
        , m_timeout(timeout)
    {
    }

    base::utils::wazuhProtocol::WazuhResponse send(const base::utils::wazuhProtocol::WazuhRequest& request)
    {
        const auto requestStr = request.toStr();

        int32_t length = requestStr.size();
        std::unique_ptr<char[]> buffer(new char[sizeof(length) + length]);
        std::memcpy(buffer.get(), &length, sizeof(length));
        std::memcpy(buffer.get() + sizeof(length), requestStr.data(), length);
        auto requestWithHeader = std::string(buffer.get(), sizeof(length) + length);

        auto clientHandle = m_loop->resource<uvw::PipeHandle>();
        auto wClientHandle = std::weak_ptr<uvw::PipeHandle>(clientHandle);

        auto timer = m_loop->resource<uvw::TimerHandle>();

        std::string error {};
        std::string response {};

        auto gracefullEnd = [loop = m_loop, timer](uvw::PipeHandle& client)
        {
            if (!timer->closing())
            {
                timer->stop();
                timer->close();
            }
            if (!client.closing())
            {
                client.close();
            }
            loop->stop();
        };

        clientHandle->on<uvw::ErrorEvent>(
            [&error, gracefullEnd](const uvw::ErrorEvent& event, uvw::PipeHandle& handle)
            {
                gracefullEnd(handle);
                error = "Socket communication error: ";
                error += event.what();
            });

        clientHandle->once<uvw::ConnectEvent>(
            [&requestWithHeader, timer, timeout = m_timeout](const uvw::ConnectEvent&, uvw::PipeHandle& handle)
            {
                std::vector<char> buffer {requestWithHeader.begin(), requestWithHeader.end()};
                handle.write(buffer.data(), buffer.size());
                timer->start(uvw::TimerHandle::Time {timeout}, uvw::TimerHandle::Time {timeout});
                handle.read();
            });

        clientHandle->on<uvw::DataEvent>(
            [&response, timer, gracefullEnd](const uvw::DataEvent& event, uvw::PipeHandle& handle)
            {
                // Restart the timmer
                if (timer->closing())
                {
                    std::cout << "Timer already closed, discarding data by timeout..." << std::endl;
                    return;
                }
                timer->again();

                // Recive data
                static uint32_t size = 0;
                if (0 == size)
                {
                    memcpy(&size, event.data.get(), sizeof(uint32_t));
                    response = std::string(event.data.get() + sizeof(uint32_t), event.length - sizeof(uint32_t));
                    size -= (event.length - sizeof(uint32_t));
                }
                else
                {
                    response += std::string(event.data.get(), event.length);
                    size -= event.length;
                }
                if (0 == size)
                {
                    gracefullEnd(handle);
                }
            });

        clientHandle->once<uvw::EndEvent>(
            [gracefullEnd, &error](const uvw::EndEvent&, uvw::PipeHandle& handle)
            {
                error = "Connection closed by server";
                gracefullEnd(handle);
            });

        clientHandle->once<uvw::CloseEvent>([gracefullEnd](const uvw::CloseEvent&, uvw::PipeHandle& handle)
                                            { gracefullEnd(handle); });

        timer->on<uvw::TimerEvent>(
            [wClientHandle, gracefullEnd, &error](const uvw::TimerEvent&, uvw::TimerHandle& timerRef)
            {
                auto client = wClientHandle.lock();
                if (client)
                {
                    gracefullEnd(*client);
                }
                error = "Connection timeout";
            });

        timer->on<uvw::ErrorEvent>(
            [&error](const uvw::ErrorEvent& errorUvw, uvw::TimerHandle& timerRef)
            {
                timerRef.close();
                error = errorUvw.what();
            });

        timer->on<uvw::CloseEvent>([](const uvw::CloseEvent&, uvw::TimerHandle& timer) {});

        // Stablish connection
        clientHandle->connect(m_socketPath);
        m_loop->run<uvw::Loop::Mode::DEFAULT>();

        // Return response and handle errors
        if (!error.empty())
        {
            throw ClientException(error, ClientException::Type::SOCKET_COMMUNICATION_ERROR);
        }

        // Parse answer
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
