#include <server/endpoints/unixStream.hpp>

#include <sys/un.h> // Unix socket datagram bind

#include <base/logging.hpp>
#include <base/timer.hpp>

namespace engineserver::endpoint
{

UnixStream::UnixStream(const std::string& address,
                       std::shared_ptr<ProtocolHandlerFactory> factory,
                       std::shared_ptr<metricsManager::IMetricsScope> metricsScope,
                       std::shared_ptr<metricsManager::IMetricsScope> metricsScopeDelta,
                       const std::size_t taskQueueSize,
                       std::size_t timeout)
    : Endpoint(address, taskQueueSize)
    , m_handle(nullptr)
    , m_timeout(timeout)
    , m_factory(std::move(factory))
{
    if (0 == m_timeout)
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
        throw std::runtime_error(msg);
    }

    if (m_address[0] != '/')
    {
        throw std::runtime_error("Address must start with '/'");
    }

    m_metric.m_metricsScope = std::move(metricsScope);
    m_metric.m_totalRequest = m_metric.m_metricsScope->getCounterUInteger("TotalRequest");
    m_metric.m_responseTime = m_metric.m_metricsScope->getHistogramUInteger("ResponseTime");
    m_metric.m_queueSize = m_metric.m_metricsScope->getHistogramUInteger("QueueSize");
    m_metric.m_connectedClients = m_metric.m_metricsScope->getUpDownCounterInteger("ConnectedClients");
    m_metric.m_serverBusy = m_metric.m_metricsScope->getCounterUInteger("ServerBusy");

    m_metric.m_metricsScopeDelta = std::move(metricsScopeDelta);
    m_metric.m_requestPerSecond = m_metric.m_metricsScopeDelta->getCounterUInteger("RequestPerSecond");
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
    unlinkUnixSocket();

    m_handle->bind(m_address);

    // Server in case of error
    m_handle->on<uvw::ErrorEvent>(
        [this](const uvw::ErrorEvent& event, uvw::PipeHandle& handle)
        {
            LOG_ERROR("[Endpoint: {}] Error on socket: {} ({})", m_address, event.name(), event.what());
            close();
        });

    // Server in case of close
    m_handle->on<uvw::CloseEvent>([address = m_address](const uvw::CloseEvent&, uvw::PipeHandle& handle)
                                  { LOG_INFO("[Endpoint: {}] Closed", address); });

    // Server in case of connection
    m_handle->on<uvw::ListenEvent>(
        [this](const uvw::ListenEvent&, uvw::PipeHandle& handle)
        {
            LOG_DEBUG("[Endpoint: {}] New connection", m_address);
            auto client = createClient();
            handle.accept(*client);
            client->read();
            m_metric.m_connectedClients->addValue(1L);
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
    auto weakClient = std::weak_ptr<uvw::PipeHandle>(client);

    auto sharedAsyncs = std::make_shared<std::vector<std::weak_ptr<uvw::AsyncHandle>>>();

    // Create a new timer for the client timeout
    auto timer = createTimer(weakClient, sharedAsyncs);

    // Configure the close events for the client
    configureCloseClient(client, timer, sharedAsyncs);

    // Create protocol handler per client
    auto protocolHandler = m_factory->create();

    client->on<uvw::DataEvent>(
        [this, weakClient, sharedAsyncs, timer, protocolHandler](const uvw::DataEvent& data, uvw::PipeHandle& clientRef)
        {
            // Avoid use _clientRef, it's a reference to the client, but we want to use the shared_ptr
            // to avoid the client release the memory before the workers finish the processing

            if (timer->closing())
            {
                LOG_DEBUG("[Endpoint: {}] Timer already closed, discarding data by timeout...", m_address);
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
                LOG_WARNING("[Endpoint: {}] Error processing data, close conexion: {}", m_address, e.what());
                timer->close();
                clientRef.close();
                return;
            }

            if (!result)
            {
                return; // No data to process (Incomplete input)
            }

            // Send each message to the queue worker
            m_metric.m_totalRequest->addValue(result->size());
            m_metric.m_requestPerSecond->addValue(result->size());

            processMessages(weakClient, sharedAsyncs, protocolHandler, std::move(result.value()));
        });

    // Accept the connection
    timer->start(uvw::TimerHandle::Time {m_timeout}, uvw::TimerHandle::Time {m_timeout});
    return client;
}

void UnixStream::processMessages(std::weak_ptr<uvw::PipeHandle> wClient,
                                 std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs,
                                 std::shared_ptr<ProtocolHandler> protocolHandler,
                                 std::vector<std::string>&& requests)
{
    for (auto& request : requests)
    {
        // No queue worker, process the message in the main thread
        if (0 == m_taskQueueSize)
        {
            auto callbackFn =
                [wClient, address = m_address, protocolHandler, metric = m_metric](const std::string& response) -> void
            {
                auto responseTimer = std::make_shared<base::chrono::Timer>();

                // Check if client is closed
                auto client = wClient.lock();
                if (!client)
                {
                    LOG_DEBUG("[Endpoint: {}] endpoint: Client already closed (remote close), discarting response",
                              address);
                    return;
                }
                else if (client->closing())
                {
                    LOG_DEBUG("[Endpoint: {}] Client closed, discarding response", address);
                    return;
                }

                // Send the response
                auto [buffer, size] = protocolHandler->streamToSend(response);
                client->write(std::move(buffer), size);
                auto elapsedTime = responseTimer->elapsed<std::chrono::milliseconds>();
                metric.m_responseTime->recordValue(static_cast<uint64_t>(elapsedTime));
            };

            protocolHandler->onMessage(request, callbackFn);

            continue;
        }
        // Send the message to the queue worker (#TODO: Should be add the size of the worker?)
        if (m_currentTaskQueueSize >= m_taskQueueSize)
        {
            auto responseTimer = base::chrono::Timer();
            LOG_DEBUG("[Endpoint: {}] endpoint: No queue worker available, disarting...", m_address);
            auto [buffer, size] = protocolHandler->getBusyResponse();
            auto client = wClient.lock();
            if (!client)
            {
                LOG_WARNING("[Endpoint: {}] endpoint: Client already closed", m_address);
                return;
            }
            client->write(std::move(buffer), size);

            auto elapsedTime = responseTimer.elapsed<std::chrono::milliseconds>();
            m_metric.m_responseTime->recordValue(static_cast<uint64_t>(elapsedTime));
            m_metric.m_serverBusy->addValue(1L);
            continue;
        }

        createAndEnqueueTask(wClient, asyncs, protocolHandler, std::move(request));
    }
}

void UnixStream::createAndEnqueueTask(std::weak_ptr<uvw::PipeHandle> wClient,
                                      std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs,
                                      std::shared_ptr<ProtocolHandler> protocolHandler,
                                      std::string&& request)
{
    ++m_currentTaskQueueSize;

    auto response = std::make_shared<std::string>();
    auto responseTimer = std::make_shared<base::chrono::Timer>();

    // Create a Async Handle for asynchronous sending of responses
    auto async = m_loop->resource<uvw::AsyncHandle>();
    auto wAsync = std::weak_ptr<uvw::AsyncHandle>(async);
    asyncs->push_back(wAsync);

    async->on<uvw::AsyncEvent>(
        [wClient,
         address = m_address,
         metric = m_metric,
         responseTimer,
         protocolHandler,
         response,
         asyncs](const uvw::AsyncEvent&, uvw::AsyncHandle& syncHandle)
        {
            // Check if client is closed
            auto client = wClient.lock();
            if (!client)
            {
                LOG_DEBUG("[Endpoint: {}] endpoint: Client already closed (remote close), discarting response",
                          address);
                return;
            }
            else if (client->closing())
            {
                LOG_DEBUG("[Endpoint: {}] Client closed, discarding response", address);
                return;
            }

            // Send the response
            auto [buffer, size] = protocolHandler->streamToSend(response);
            client->write(std::move(buffer), size);
            auto elapsedTime = responseTimer->elapsed<std::chrono::milliseconds>();
            metric.m_responseTime->recordValue(static_cast<uint64_t>(elapsedTime));

            // Find and remove the corresponding AsyncHandle from the array
            auto it = std::find_if(asyncs->begin(), asyncs->end(),
                                [&syncHandle](const auto& weakAsync) {
                                    auto async = weakAsync.lock();
                                    return async && async.get() == &syncHandle;
                                });

            if (it != asyncs->end())
            {
                auto async = it->lock();
                if (async)
                {
                    // Release the resources associated with the AsyncHandle
                    async->close();
                }

                // Remove the AsyncHandle from the vector
                asyncs->erase(it);
            }
        });

    auto callbackFn = [asyncs, wAsync, address = m_address, response](const std::string& res) -> void
    {
        *response = res;

        auto async = wAsync.lock();
        if (!async)
        {
            LOG_DEBUG("[Endpoint: {}] endpoint: Async already closed (remote close), discarting response", address);
            return;
        }
        else if (async->closing())
        {
            LOG_DEBUG("[Endpoint: {}] endpoint: Async already closed, discarting response", address);
            return;
        }

        async->send();
    };

    // Create a new queue worker for the request
    auto work = m_loop->resource<uvw::WorkReq>([request, callbackFn, protocolHandler, address = m_address]()
                                               { protocolHandler->onMessage(request, callbackFn); });

    // On error
    work->on<uvw::ErrorEvent>(
        [address = m_address, metric = m_metric, &currentTaskQueueSize = m_currentTaskQueueSize](
            const uvw::ErrorEvent& error, uvw::WorkReq& worker)
        {
            LOG_ERROR("[Endpoint: {}] endpoint: Error processing message: {}", address, error.what());
            --currentTaskQueueSize;
            metric.m_queueSize->recordValue(currentTaskQueueSize.load());
        });

    // On finish
    work->on<uvw::WorkEvent>(
        [address = m_address, metric = m_metric, &currentTaskQueueSize = m_currentTaskQueueSize](const uvw::WorkEvent&,
                                                                                                 uvw::WorkReq& work)
        {
            --currentTaskQueueSize;
            metric.m_queueSize->recordValue(currentTaskQueueSize.load());
            LOG_DEBUG("[Endpoint: {}] endpoint: Finish", address);
        });

    work->queue();
    m_metric.m_queueSize->recordValue(m_currentTaskQueueSize.load());
}

std::shared_ptr<uvw::TimerHandle> UnixStream::createTimer(std::weak_ptr<uvw::PipeHandle> wClient,
                                                          std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs)
{
    auto timer = m_loop->resource<uvw::TimerHandle>();

    // Timeout, close the client
    timer->on<uvw::TimerEvent>(
        [wClient, asyncs, address = m_address](const uvw::TimerEvent&, uvw::TimerHandle& timerRef)
        {
            LOG_DEBUG("[Endpoint: {}] Client timeout, close connection.", address);
            auto client = wClient.lock();
            if (wClient.expired())
            {
                LOG_DEBUG("[Endpoint: {}] Client already closed", address);
            }
            else if (client && !client->closing())
            {
                client->close();
            }

            for (auto& wAsync : *asyncs)
            {
                auto async = wAsync.lock();
                if (wAsync.expired())
                {
                    LOG_DEBUG("[Endpoint: {}] Async Handle already closed", address);
                }
                else if (async && !async->closing())
                {
                    async->close();
                }
            }

            timerRef.close();
        });

    timer->on<uvw::ErrorEvent>(
        [address = m_address](const uvw::ErrorEvent& error, uvw::TimerHandle& timerRef)
        {
            LOG_ERROR("[Endpoint: {}] Timer error: {}", address, error.what());
            timerRef.close();
        });

    timer->on<uvw::CloseEvent>([address = m_address](const uvw::CloseEvent&, uvw::TimerHandle&)
                               { LOG_DEBUG("[Endpoint: {}] Timer closed", address); });

    return timer;
}

void UnixStream::configureCloseClient(std::shared_ptr<uvw::PipeHandle> client,
                                      std::shared_ptr<uvw::TimerHandle> timer,
                                      std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs)
{

    auto gracefullEnd = [timer, asyncs, metric = m_metric, address = m_address](uvw::PipeHandle& client)
    {
        if (!timer->closing())
        {
            timer->stop();
            timer->close();
        }
        for (auto& wAsync : *asyncs)
        {
            auto sAsync = wAsync.lock();
            if (wAsync.expired())
            {
                LOG_DEBUG("[Endpoint: {}] Async Handle already closed", address);
            }
            else if (sAsync && !sAsync->closing())
            {
                sAsync->close();
            }
        }
        if (!client.closing())
        {
            client.close();
            metric.m_connectedClients->addValue(-1L);
        }
    };

    // On error
    client->on<uvw::ErrorEvent>(
        [gracefullEnd, address = m_address](const uvw::ErrorEvent& error, uvw::PipeHandle& client)
        {
            LOG_WARNING("[Endpoint: {}] Client error: {}", address, error.what());
            gracefullEnd(client);
        });

    // On close
    client->on<uvw::CloseEvent>(
        [gracefullEnd, address = m_address](const uvw::CloseEvent&, uvw::PipeHandle& client)
        {
            LOG_DEBUG("[Endpoint: {}] Client closed connection gracefully", address);
            gracefullEnd(client);
        });

    // On Shutdown
    client->on<uvw::ShutdownEvent>(
        [gracefullEnd, address = m_address](const uvw::ShutdownEvent&, uvw::PipeHandle& client)
        {
            LOG_DEBUG("[Endpoint: {}] Client shutdown connection", address);
            gracefullEnd(client);
        });

    // End event
    client->on<uvw::EndEvent>(
        [gracefullEnd, address = m_address](const uvw::EndEvent&, uvw::PipeHandle& client)
        {
            LOG_DEBUG("[Endpoint: {}] Client disconnected gracefully", address);
            gracefullEnd(client);
        });
}

} // namespace engineserver::endpoint
