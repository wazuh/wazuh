#include <server/unixStream.hpp>

#include <unistd.h> // Unlink
#include <sys/un.h>     // Unix socket datagram bind


#include <logging/logging.hpp>

namespace
{
/**
 * @brief Create a Timer resource, this timer will be used to close the client connection if it doesn't send any data
 *
 * @param loop Loop to create the timer
 * @param client Client to close if the timer expires
 * @return Timer resource
 */
std::shared_ptr<uvw::TimerHandle> createTimer(std::shared_ptr<uvw::Loop> loop, std::shared_ptr<uvw::PipeHandle> client)
{
    auto timer = client->loop().resource<uvw::TimerHandle>();

    // Timeout, close the client
    timer->on<uvw::TimerEvent>(
        [client, timer](const uvw::TimerEvent&, uvw::TimerHandle& _timerRef)
        {
            WAZUH_LOG_DEBUG("Client timeout, close connection.");
            if (!client->closing())
            {
                client->close();
            }
            timer->close();
        });

    timer->on<uvw::ErrorEvent>(
        [timer](const uvw::ErrorEvent& error, uvw::TimerHandle& _timerRef)
        {
            WAZUH_LOG_ERROR("Timer error: {}", error.what());
            timer->close();
        });

    timer->on<uvw::CloseEvent>([](const uvw::CloseEvent&, uvw::TimerHandle& timer)
                               { WAZUH_LOG_DEBUG("Timer closed"); });

    return timer;
}

/**
 * @brief Configure the client to close the connection gracefully
 *
 * @param client Client to close
 * @param timer Timer to close if the client closes the connection
 */
void configureCloseClient(std::shared_ptr<uvw::PipeHandle> client, std::shared_ptr<uvw::TimerHandle> timer)
{

    auto gracefullEnd = [timer, client]()
    {
        if (timer && !timer->closing())
        {
            timer->stop();
            timer->close();
        }
        if (!client->closing())
        {
            client->close();
        }
    };

    // On error
    client->on<uvw::ErrorEvent>(
        [gracefullEnd](const uvw::ErrorEvent& error, uvw::PipeHandle& client)
        {
            WAZUH_LOG_WARN("Client error: {}", error.what());
            gracefullEnd();
        });

    // On close
    client->on<uvw::CloseEvent>(
        [gracefullEnd](const uvw::CloseEvent&, uvw::PipeHandle& client)
        {
            WAZUH_LOG_DEBUG("Client closed connection gracefully");
            gracefullEnd();
        });

    // On Shutdown
    client->on<uvw::ShutdownEvent>(
        [gracefullEnd](const uvw::ShutdownEvent&, uvw::PipeHandle& client)
        {
            WAZUH_LOG_DEBUG("Client shutdown connection");
            gracefullEnd();
        });

    // End event
    client->on<uvw::EndEvent>(
        [gracefullEnd](const uvw::EndEvent&, uvw::PipeHandle& client)
        {
            WAZUH_LOG_DEBUG("Client disconnected gracefully");
            gracefullEnd();
        });

}

} // namespace

namespace engineserver::endpoint
{

UnixStream::UnixStream(const std::string& address,
                       std::shared_ptr<ProtocolHandlerFactory> factory,
                       const std::size_t taskQueueSize,
                       std::size_t timeout)
    : Endpoint(address, taskQueueSize)
    , m_handle(nullptr)
    , m_timeout(timeout)
    , m_factory(factory)
{
    if (m_timeout == 0)
    {
        throw std::runtime_error("Timeout must be greater than 0");
    }

    if (3600000 < m_timeout)
    {
        throw std::runtime_error("Timeout must be less than 3600000 (1 hour)");
    }

    if (!m_factory)
    {
        throw std::runtime_error("ProtocolHandlerFactory must be set");
    }

    if (address.empty())
    {
        throw std::runtime_error("Address must not be empty");
    }

    if (address.length() >= sizeof(sockaddr_un::sun_path))
    {
        auto msg = fmt::format("Path '{}' too long, maximum length is {} ", address, sizeof(sockaddr_un::sun_path));
        throw std::runtime_error(std::move(msg));
    }

    if (m_address[0] != '/')
    {
        throw std::runtime_error("Address must start with '/'");
    }
}

UnixStream::~UnixStream()
{
    close();
}

void UnixStream::bind(std::shared_ptr<uvw::Loop> loop)
{
    if (m_loop)
    {
        throw std::runtime_error("Endpoint already bound");
    }
    m_loop = loop;
    // Create server
    m_handle = m_loop->resource<uvw::PipeHandle>();

    // Check if the socket file exists, if so, delete it
    // #TODO, CHECK IF THE FILE IS A SOCKET
    unlink(m_address.c_str());
    m_handle->bind(m_address);

    // Server in case of error
    m_handle->on<uvw::ErrorEvent>(
        [this](const uvw::ErrorEvent& event, uvw::PipeHandle& handle)
        {
            WAZUH_LOG_ERROR("Engine '{}' endpoint: Error on socket: {} ({})", m_address, event.name(), event.what());
            close();
        });

    // Server in case of close
    m_handle->on<uvw::CloseEvent>(
        [this](const uvw::CloseEvent&, uvw::PipeHandle& handle)
        {
            // TODO Unlink the socket file
            WAZUH_LOG_INFO("Engine '{}' endpoint: Socket closed", m_address);
        });

    // Server in case of connection
    m_handle->on<uvw::ListenEvent>(
        [this](const uvw::ListenEvent&, uvw::PipeHandle& handle)
        {
            WAZUH_LOG_DEBUG("Engine '{}' endpoints: New connection", m_address);
            auto client = createClient();
            handle.accept(*client);
            client->read();
        });

    // Listen for incoming connections
    m_running = true;
    m_handle->listen();
}

void UnixStream::close()
{
    if (isBound())
    {
        m_handle->close();
        m_handle.reset();
        m_loop.reset();
        m_running = false;
    }
}

bool UnixStream::pause()
{
    if (m_running && isBound())
    {
        m_handle->stop();
        m_running = false;
        return true;
    }
    return false;
}

bool UnixStream::resume()
{
    if (!m_running && isBound())
    {
        m_handle->listen();
        m_running = true;
        return true;
    }
    return false;
}

std::shared_ptr<uvw::PipeHandle> UnixStream::createClient()
{
    // Create a new client
    auto client = m_loop->resource<uvw::PipeHandle>();

    // Create a new timer for the client timeout
    std::shared_ptr<uvw::TimerHandle> timer = createTimer(m_loop, client);

    // Configure the close events for the client
    configureCloseClient(client, timer);

    // Create 1 protocol handler per client
    auto protocolHandler = m_factory->create();
    client->on<uvw::DataEvent>(
        [this, timer, client, protocolHandler](const uvw::DataEvent& data, uvw::PipeHandle& _clienRef)
        {
            // Avoid use _clientRef, it's a reference to the client, but we want to use the shared_ptr
            // to avoid the client release the memory before the workers finish the processing

            if (timer->closing())
            {
                WAZUH_LOG_DEBUG("Timer already closed, discarding data by timeout...");
                return;
            }
            timer->again();

            // Process the data
            std::optional<std::vector<std::string>> result = std::nullopt;
            try
            {
                result = protocolHandler->onData(std::string_view(data.data.get(), data.length));
            }
            catch (const std::exception& e)
            {
                WAZUH_LOG_WARN("Error processing data, close conexion: {}", e.what());
                timer->close();
                client->close();
                return;
            }

            if (!result)
            {
                return; // No data to process (Incomplete input)
            }

            // Send each message to the queue worker
            processMessages(client, protocolHandler, std::move(result.value()));
        });

    // Accept the connection
    timer->start(uvw::TimerHandle::Time {m_timeout}, uvw::TimerHandle::Time {m_timeout});
    return client;
}

void UnixStream::processMessages(std::shared_ptr<uvw::PipeHandle> client,
                                 std::shared_ptr<ProtocolHandler> protocolHandler,
                                 std::vector<std::string>&& messages)
{
    for (auto& message : messages)
    {
        // No queue worker, process the message in the main thread
        if (0 == m_taskQueueSize)
        {
            auto response = std::make_shared<std::string>();
            try
            {
                *response = protocolHandler->onMessage(message);
            }
            catch (const std::exception& e)
            {
                WAZUH_LOG_WARN("Engine '{}' endpoint: Error processing message [callback]: {}", m_address, e.what());
                *response = protocolHandler->getErrorResponse();
            }
            auto [buffer, size] = protocolHandler->streamToSend(std::move(response));
            client->write(std::move(buffer), size);
            continue;
        }
        // Send the message to the queue worker (#TODO: Should be add the size of the worker?)
        if (m_currentTaskQueueSize >= m_taskQueueSize)
        {
            WAZUH_LOG_DEBUG("Engine '{}' endpoint: No queue worker available, disarting...", m_address);
            auto [buffer, size] = protocolHandler->getBusyResponse();
            client->write(std::move(buffer), size);
            continue;
        }

        createAndEnqueueTask(client, protocolHandler, std::move(message));
    }
}

void UnixStream::createAndEnqueueTask(std::shared_ptr<uvw::PipeHandle> client,
                            std::shared_ptr<ProtocolHandler> protocolHandler,
                            std::string&& message)
{

    auto response = std::make_shared<std::string>();
    ++m_currentTaskQueueSize;

    // Create a new queue worker for the request
    auto work = m_loop->resource<uvw::WorkReq>(
        [this, response, message, protocolHandler]()
        {
            try
            {
                *response = protocolHandler->onMessage(message);
            }
            catch (const std::exception& e)
            {
                WAZUH_LOG_WARN("Engine '{}' endpoint: Error processing message [callback]: {}", m_address, e.what());
                *response = protocolHandler->getErrorResponse();
            }
        });

    // On error
    work->on<uvw::ErrorEvent>(
        [this](const uvw::ErrorEvent& error, uvw::WorkReq& worker)
        {
            WAZUH_LOG_ERROR("Engine '{}' endpoint: Error processing message: {}", m_address, error.what());
            --m_currentTaskQueueSize;
        });

    // On finish
    work->on<uvw::WorkEvent>(
        [this, client, response, protocolHandler](const uvw::WorkEvent&, uvw::WorkReq& work)
        {
            --m_currentTaskQueueSize;

            // Check if client is closed
            if (client->closing())
            {
                WAZUH_LOG_DEBUG("Engine '{}' endpoint: Client closed, discarding response", m_address);
                return;
            }

            // Send the response
            auto [buffer, size] = protocolHandler->streamToSend(response);
            client->write(std::move(buffer), size);
        });

    work->queue();
}

} // namespace engineserver::endpoint
