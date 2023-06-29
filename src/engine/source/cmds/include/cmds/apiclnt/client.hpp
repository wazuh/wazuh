#ifndef _APICLNT_CLIENT_HPP
#define _APICLNT_CLIENT_HPP

#include <exception>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include <uvw/pipe.hpp>
#include <uvw/timer.hpp>

#include <base/utils/wazuhProtocol/wazuhProtocol.hpp>
#include <error.hpp>

#include <cmds/apiExcept.hpp>

namespace cmd::apiclnt
{

constexpr auto DEFAULT_TIMEOUT = 1000;

class Client
{
private:
    std::string m_socketPath;
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<uvw::PipeHandle> m_clientHandle;
    std::shared_ptr<uvw::TimerHandle> m_timer;
    bool m_isFirstExecution;

public:
    Client(const std::string& socketPath)
        : m_socketPath(socketPath)
        , m_loop(uvw::Loop::getDefault())
        , m_clientHandle(m_loop->resource<uvw::PipeHandle>())
        , m_timer(m_loop->resource<uvw::TimerHandle>())
        , m_isFirstExecution(true)
    {
        setupTimer();
    }

    void setupTimer()
    {
        m_timer->on<uvw::TimerEvent>(
            [this](const uvw::TimerEvent&, uvw::TimerHandle& timerRef)
            {
                if (!m_clientHandle->closing())
                {
                    m_clientHandle->close();
                }
                timerRef.close();
            });
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
                    handle.close();
                }
            });

        clientHandle->once<uvw::EndEvent>(
            [this](const uvw::EndEvent&, uvw::PipeHandle& handle)
            {
                // Stop the loop after receiving the first response
                m_loop->stop();
            });

        clientHandle->once<uvw::CloseEvent>(
            [this](const uvw::CloseEvent&, uvw::PipeHandle& handle)
            {
                // Stop the loop after closing the connection
                m_loop->stop();
            });

        auto timer = m_loop->resource<uvw::TimerHandle>();
        timer->on<uvw::TimerEvent>(
            [&clientHandle, &timer, &error](const uvw::TimerEvent&, uvw::TimerHandle& timerRef)
            {
                if (!clientHandle->closing())
                {
                    clientHandle->close();
                }
                timer->close();
                error = "Connection timeout";
            });

        timer->on<uvw::ErrorEvent>(
            [&timer, &error](const uvw::ErrorEvent& errorUvw, uvw::TimerHandle& timerRef)
            {
                timer->close();
                error = errorUvw.what();
            });

        timer->on<uvw::CloseEvent>(
            [this](const uvw::CloseEvent&, uvw::TimerHandle& timer)
            {
                // Stop loop only after first run
                if (m_isFirstExecution)
                {
                    m_loop->stop();
                }
            });

        clientHandle->once<uvw::ConnectEvent>(
            [this, &timer](const uvw::ConnectEvent&, uvw::PipeHandle& handle)
            {
                // Start timer for first run only
                if (m_isFirstExecution)
                {
                    timer->start(uvw::TimerHandle::Time {DEFAULT_TIMEOUT}, uvw::TimerHandle::Time {DEFAULT_TIMEOUT});
                }
            });

        // Stablish connection
        clientHandle->connect(m_socketPath);
        m_isFirstExecution = false; // Mark that it is no longer the first run
        m_loop->run();

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
