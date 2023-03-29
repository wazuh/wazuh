#include <server/unixStream.hpp>

#include <unistd.h> // Unlink

#include <logging/logging.hpp>

namespace
{
std::shared_ptr<uvw::TimerHandle>
createTimer(std::shared_ptr<uvw::Loop> loop, std::shared_ptr<uvw::PipeHandle> client)
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

    // On data
}

} // namespace

namespace engineserver::endpoint
{

UnixStream::UnixStream(const std::string& address, std::shared_ptr<ProtocolHandlerFactory> factory, std::size_t timeout)
    : Endpoint(address)
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
}

UnixStream::~UnixStream()
{
    close();
}

// TODO Aca tengo que recibir un cliente, que tenga los metodos de separacion de mensajes, preocesamiento de mensajes y
// generacion de paquetes
void UnixStream::bind(std::shared_ptr<uvw::Loop> loop, const std::size_t queueWorkerSize)
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
    // #TODO, CHECK THE LENGHT
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
        [this, queueWorkerSize](const uvw::ListenEvent&, uvw::PipeHandle& handle)
        {
            WAZUH_LOG_DEBUG("Engine '{}' endpoints: New connection", m_address);
            // Create a new client
            auto client = m_loop->resource<uvw::PipeHandle>();

            // Create a new timer for the client timeout
            std::shared_ptr<uvw::TimerHandle> timer = createTimer(m_loop, client);

            // Configure the close events for the client
            configureCloseClient(client, timer);

            // Create 1 protocol handler per client
            auto protocolHandler = m_factory->create();
            client->on<uvw::DataEvent>(
                [this, timer, client, protocolHandler, queueWorkerSize](const uvw::DataEvent& data,
                                                                        uvw::PipeHandle& _clienRef)
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
                    auto result = protocolHandler->onData(std::string_view(data.data.get(), data.length));
                    if (!result)
                    {
                        // Close client? Actually, the client will close but if a message is bigger than the buffer, it
                        // will be closed before processing the message
                        // If the size is invalid, the client should be closed
                        timer->close();
                        client->close();
                        return; // No data to process (Incomplete input or error)
                    }

                    // Send each message to the queue worker
                    for (auto& message : result.value())
                    {
                        // No queue worker, process the message in the main thread
                        if (0 == queueWorkerSize)
                        {
                            std::string response;
                            response = protocolHandler->onMessage(message); // #TODO Try and catch
                            auto [buffer, size] =
                                protocolHandler->streamToSend(std::make_shared<std::string>(std::move(response)));
                            client->write(std::move(buffer), size);
                            continue;
                        }
                        // Send the message to the queue worker (#TODO: Should be add the size of the worker?)
                        if (m_currentQWSize >= queueWorkerSize)
                        {
                            WAZUH_LOG_DEBUG("Engine '{}' endpoint: No queue worker available, disarting...", m_address);
                            auto [buffer, size] = protocolHandler->getBusyResponse();
                            client->write(std::move(buffer), size);
                            continue;
                        }

                        auto work = createWork(client, protocolHandler, std::move(message));
                    }
                });

            // Accept the connection
            timer->start(uvw::TimerHandle::Time {m_timeout}, uvw::TimerHandle::Time {m_timeout});
            handle.accept(*client);
            client->read();
        });

    // Listen for incoming connections
    m_running = true;
    m_handle->listen();
}

std::shared_ptr<std::string> UnixStream::createWork(std::shared_ptr<uvw::PipeHandle> client,
                                                    std::shared_ptr<ProtocolHandler> protocolHandler,
                                                    std::string&& message)
{

    auto response = std::make_shared<std::string>();
    ++m_currentQWSize;

    // Create a new queue worker
    auto work = m_loop->resource<uvw::WorkReq>(
        [this, response, message, protocolHandler]()
        {
            // TODO: Process the message (Try and catch?)
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
            --m_currentQWSize;
        });

    // On finish
    work->on<uvw::WorkEvent>(
        [this, client, response, protocolHandler](const uvw::WorkEvent&, uvw::WorkReq& work)
        {
            --m_currentQWSize;

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

    return response;
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

} // namespace engineserver::endpoint
