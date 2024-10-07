#include <server/endpoints/unixStream.hpp>

#include <sys/un.h> // Unix socket datagram bind

#include <base/logging.hpp>
#include <base/timer.hpp>
#include <metrics/imanager.hpp>

namespace engineserver::endpoint
{

UnixStream::UnixStream(const std::string& address,
                       std::shared_ptr<ProtocolHandlerFactory> factory,
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

    metrics::getManager().addMetric(
        metrics::MetricType::UINTCOUNTER, "api_endpoint.total_request", "Total requests received", "requests");

    metrics::getManager().addMetric(
        metrics::MetricType::UINTHISTOGRAM, "api_endpoint.response_time", "Response time", "ms");

    metrics::getManager().addMetric(
        metrics::MetricType::UINTHISTOGRAM, "api_endpoint.queue_size", "Queue size", "requests");

    metrics::getManager().addMetric(
        metrics::MetricType::INTUPDOWNCOUNTER, "api_endpoint.connected_clients", "Connected clients", "clients");

    metrics::getManager().addMetric(
        metrics::MetricType::UINTCOUNTER, "api_endpoint.server_busy", "Server busy", "events");

    // TODO: Rate is not implemented
    metrics::getManager().addMetric(
        metrics::MetricType::UINTCOUNTER, "api_endpoint.request_per_second", "Requests per second", "requests/s");
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
        [this, functionName = logging::getLambdaName(__FUNCTION__, "handleErrorEvent")](const uvw::ErrorEvent& event,
                                                                                        uvw::PipeHandle& handle)
        {
            LOG_ERROR_L(
                functionName.c_str(), "[Endpoint: {}] Error on socket: {} ({})", m_address, event.name(), event.what());
            close();
        });

    // Server in case of close
    m_handle->on<uvw::CloseEvent>(
        [address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "handleCloseEvent")](
            const uvw::CloseEvent&, uvw::PipeHandle& handle)
        { LOG_INFO(functionName, "[Endpoint: {}] Closed", address); });

    // Server in case of connection
    m_handle->on<uvw::ListenEvent>(
        [this, functionName = logging::getLambdaName(__FUNCTION__, "handleListenEvent")](const uvw::ListenEvent&,
                                                                                         uvw::PipeHandle& handle)
        {
            LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] New connection", m_address);
            auto client = createClient();
            handle.accept(*client);
            client->read();
            metrics::getManager().getMetric("api_endpoint.connected_clients")->update<int64_t>(1L);
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
        [this,
         weakClient,
         sharedAsyncs,
         timer,
         protocolHandler,
         functionName = logging::getLambdaName(__FUNCTION__, "clientDataEvent")](const uvw::DataEvent& data,
                                                                                 uvw::PipeHandle& clientRef)
        {
            // Avoid use _clientRef, it's a reference to the client, but we want to use the shared_ptr
            // to avoid the client release the memory before the workers finish the processing
            if (timer->closing())
            {
                LOG_DEBUG_L(functionName.c_str(),
                            "[Endpoint: {}] Timer already closed, discarding data by timeout...",
                            m_address);
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
                LOG_WARNING_L(functionName.c_str(),
                              "[Endpoint: {}] Error processing data, close conexion: {}",
                              m_address,
                              e.what());
                timer->close();
                clientRef.close();
                return;
            }

            if (!result)
            {
                return; // No data to process (Incomplete input)
            }

            // Send each message to the queue worker
            metrics::getManager().getMetric("api_endpoint.total_request")->update<int64_t>(result->size());
            metrics::getManager().getMetric("api_endpoint.request_per_second")->update<int64_t>(result->size());

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
            auto callbackFn = [wClient,
                               address = m_address,
                               protocolHandler,
                               functionName = logging::getLambdaName(__FUNCTION__, "handleClientResponse")](
                                  const std::string& response) -> void
            {
                auto responseTimer = std::make_shared<base::chrono::Timer>();

                // Check if client is closed
                auto client = wClient.lock();
                if (!client)
                {
                    LOG_DEBUG_L(functionName.c_str(),
                                "[Endpoint: {}] endpoint: Client already closed (remote close), discarting response",
                                address);
                    return;
                }
                else if (client->closing())
                {
                    LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client closed, discarding response", address);
                    return;
                }

                // Send the response
                auto [buffer, size] = protocolHandler->streamToSend(response);
                client->write(std::move(buffer), size);
                auto elapsedTime = responseTimer->elapsed<std::chrono::milliseconds>();
                metrics::getManager().getMetric("api_endpoint.response_time")->update<uint64_t>(elapsedTime);
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
            metrics::getManager().getMetric("api_endpoint.response_time")->update<uint64_t>(elapsedTime);
            metrics::getManager().getMetric("api_endpoint.server_busy")->update<int64_t>(1L);
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
         responseTimer,
         protocolHandler,
         response,
         asyncs,
         functionName = logging::getLambdaName(__FUNCTION__, "asyncEvent")](const uvw::AsyncEvent&,
                                                                            uvw::AsyncHandle& syncHandle)
        {
            // Check if client is closed
            auto client = wClient.lock();

            if (!client)
            {
                LOG_DEBUG_L(functionName.c_str(),
                            "[Endpoint: {}] endpoint: Client already closed (remote close), discarting response",
                            address);
                return;
            }
            else if (client->closing())
            {
                LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client closed, discarding response", address);
                return;
            }

            // Send the response
            auto [buffer, size] = protocolHandler->streamToSend(response);
            client->write(std::move(buffer), size);
            auto elapsedTime = responseTimer->elapsed<std::chrono::milliseconds>();
            // metric.m_responseTime->recordValue(static_cast<uint64_t>(elapsedTime));

            // Find and remove the corresponding AsyncHandle from the array
            auto it = std::find_if(asyncs->begin(),
                                   asyncs->end(),
                                   [&syncHandle](const auto& weakAsync)
                                   {
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

    auto callbackFn =
        [asyncs,
         wAsync,
         address = m_address,
         response,
         functionName = logging::getLambdaName(__FUNCTION__, "handleResponseAndSend")](const std::string& res) -> void
    {
        *response = res;
        auto async = wAsync.lock();
        if (!async)
        {
            LOG_DEBUG_L(functionName.c_str(),
                        "[Endpoint: {}] endpoint: Async already closed (remote close), discarting response",
                        address);
            return;
        }
        else if (async->closing())
        {
            LOG_DEBUG_L(
                functionName.c_str(), "[Endpoint: {}] endpoint: Async already closed, discarting response", address);
            return;
        }

        async->send();
    };

    // Create a new queue worker for the request
    auto work = m_loop->resource<uvw::WorkReq>([request, callbackFn, protocolHandler, address = m_address]()
                                               { protocolHandler->onMessage(request, callbackFn); });

    // On error
    work->on<uvw::ErrorEvent>(
        [address = m_address,
         &currentTaskQueueSize = m_currentTaskQueueSize,
         functionName = logging::getLambdaName(__FUNCTION__, "workerErrorEvent")](const uvw::ErrorEvent& error,
                                                                                  uvw::WorkReq& worker)
        {
            LOG_ERROR_L(
                functionName.c_str(), "[Endpoint: {}] endpoint: Error processing message: {}", address, error.what());
            --currentTaskQueueSize;
            // metric.m_queueSize->recordValue(currentTaskQueueSize.load());
        });

    // On finish
    work->on<uvw::WorkEvent>(
        [address = m_address,
         &currentTaskQueueSize = m_currentTaskQueueSize,
         functionName = logging::getLambdaName(__FUNCTION__, "WorkerEvent")](const uvw::WorkEvent&, uvw::WorkReq& work)
        {
            --currentTaskQueueSize;
            metrics::getManager().getMetric("api_endpoint.queue_size")->update<uint64_t>(currentTaskQueueSize.load());
            LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] endpoint: Finish", address);
        });

    work->queue();
    metrics::getManager().getMetric("api_endpoint.queue_size")->update<uint64_t>(m_currentTaskQueueSize.load());
}

std::shared_ptr<uvw::TimerHandle>
UnixStream::createTimer(std::weak_ptr<uvw::PipeHandle> wClient,
                        std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs)
{
    auto timer = m_loop->resource<uvw::TimerHandle>();

    // Timeout, close the client
    timer->on<uvw::TimerEvent>(
        [wClient, asyncs, address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "timerEvent")](
            const uvw::TimerEvent&, uvw::TimerHandle& timerRef)
        {
            LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client timeout, close connection.", address);
            auto client = wClient.lock();
            if (wClient.expired())
            {
                LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client already closed", address);
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
                    LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Async Handle already closed", address);
                }
                else if (async && !async->closing())
                {
                    async->close();
                }
            }

            timerRef.close();
        });

    timer->on<uvw::ErrorEvent>(
        [address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "timerErrorEvent")](
            const uvw::ErrorEvent& error, uvw::TimerHandle& timerRef)
        {
            LOG_ERROR_L(functionName.c_str(), "[Endpoint: {}] Timer error: {}", address, error.what());
            timerRef.close();
        });

    timer->on<uvw::CloseEvent>(
        [address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "timerCloseEvent")](
            const uvw::CloseEvent&, uvw::TimerHandle&)
        { LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Timer closed", address); });

    return timer;
}

void UnixStream::configureCloseClient(std::shared_ptr<uvw::PipeHandle> client,
                                      std::shared_ptr<uvw::TimerHandle> timer,
                                      std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs)
{

    auto gracefullEnd =
        [timer, asyncs, address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "gracefullEnd")](
            uvw::PipeHandle& client)
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
                LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Async Handle already closed", address);
            }
            else if (sAsync && !sAsync->closing())
            {
                sAsync->close();
            }
        }
        if (!client.closing())
        {
            client.close();
            // metric.m_connectedClients->addValue(-1L);
        }
    };

    // On error
    client->on<uvw::ErrorEvent>(
        [gracefullEnd, address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "clientErrorEvent")](
            const uvw::ErrorEvent& error, uvw::PipeHandle& client)
        {
            LOG_WARNING_L(functionName.c_str(), "[Endpoint: {}] Client error: {}", address, error.what());
            gracefullEnd(client);
        });

    // On close
    client->on<uvw::CloseEvent>(
        [gracefullEnd, address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "clientCloseEvent")](
            const uvw::CloseEvent&, uvw::PipeHandle& client)
        {
            LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client closed connection gracefully", address);
            gracefullEnd(client);
        });

    // On Shutdown
    client->on<uvw::ShutdownEvent>(
        [gracefullEnd, address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "clientShutdownEvent")](
            const uvw::ShutdownEvent&, uvw::PipeHandle& client)
        {
            LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client shutdown connection", address);
            gracefullEnd(client);
        });

    // End event
    client->on<uvw::EndEvent>(
        [gracefullEnd, address = m_address, functionName = logging::getLambdaName(__FUNCTION__, "clientEndEvent")](
            const uvw::EndEvent&, uvw::PipeHandle& client)
        {
            LOG_DEBUG_L(functionName.c_str(), "[Endpoint: {}] Client disconnected gracefully", address);
            gracefullEnd(client);
        });
}

} // namespace engineserver::endpoint
