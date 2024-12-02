#include <server/endpoints/unixDatagram.hpp>

#include <cstring>      // Unix  socket datagram bind
#include <fcntl.h>      // Unix socket datagram bind
#include <sys/socket.h> // Unix socket datagram bind
#include <sys/un.h>     // Unix socket datagram bind
#include <unistd.h>     // Unix socket datagram bind

#include <base/logging.hpp>
#include <metrics/imanager.hpp>
#include <uvw.hpp>

namespace
{
constexpr unsigned int MAX_MSG_SIZE {65536 + 512}; ///< Maximum message size (TODO: I think this should be 65507)
} // namespace

namespace engineserver::endpoint
{
UnixDatagram::UnixDatagram(const std::string& address,
                           const std::function<void(const std::string&)>& callback,
                           const std::size_t taskQueueSize)
    : Endpoint(address, taskQueueSize)
    , m_callback(callback)
    , m_handle(nullptr)
    , m_bufferSize(-1)
{
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

    if (!callback)
    {
        throw std::runtime_error("Callback must be set");
    }

    // Metrics initialization
    metrics::getManager().addMetric(
        metrics::MetricType::UINTCOUNTER, "event_endpoint.bytes_received", "Bytes received by the server", "bytes");

    metrics::getManager().addMetric(
        metrics::MetricType::UINTCOUNTER, "event_endpoint.busy_queue", "Server busy queue", "events");

    metrics::getManager().addMetric(
        metrics::MetricType::UINTHISTOGRAM, "event_endpoint.queue_history", "Events queued history", "events");

    metrics::getManager().addMetric(
        metrics::MetricType::UINTHISTOGRAM, "event_endpoint.event_size_history", "Event size history", "bytes");

    // TODO: Rate is not implemented
    metrics::getManager().addMetric(metrics::MetricType::UINTCOUNTER,
                                    "event_endpoint.bytes_received_per_second",
                                    "Bytes received per second",
                                    "bytes/s");

    // TODO: Rate is not implemented
    metrics::getManager().addMetric(metrics::MetricType::UINTCOUNTER,
                                    "event_endpoint.events_received_per_second",
                                    "Events received per second",
                                    "events/s");
}

UnixDatagram::~UnixDatagram()
{
    if (isBound())
    {
        // Close
        m_handle->close();
        m_handle = nullptr;
        unlink(m_address.c_str());
    }
}

void UnixDatagram::bind(std::shared_ptr<uvw::Loop> loop)
{
    if (isBound())
    {
        throw std::runtime_error("Endpoint already bound");
    }

    m_loop = loop;
    m_handle = m_loop->resource<uvw::UDPHandle>();

    // Listen for incoming data
    m_handle->on<uvw::UDPDataEvent>(
        [this, functionName = logging::getLambdaName(__FUNCTION__, "handleUDPDataEvent")](
            const uvw::UDPDataEvent& event, uvw::UDPHandle& handle)
        {
            // Get the data
            auto data = std::string {event.data.get(), event.length};

            metrics::getManager().getMetric("event_endpoint.bytes_received")->update<uint64_t>(event.length);
            metrics::getManager().getMetric("event_endpoint.bytes_received_per_second")->update<uint64_t>(event.length);
            metrics::getManager().getMetric("event_endpoint.events_received_per_second")->update<uint64_t>(1UL);
            metrics::getManager().getMetric("event_endpoint.event_size_history")->update<uint64_t>(event.length);

            // Call the callback if is synchronous
            if (0 == m_taskQueueSize)
            {
                try
                {
                    m_callback(data);
                }
                catch (const std::exception& e)
                {
                    LOG_WARNING_L(
                        functionName.c_str(), "[Endpoint: {}] Error calling the callback: {}", m_address, e.what());
                }

                return;
            }

            // Call the callback if is asynchronous, (TODO: Should be decrement the size of the workers?)
            if (++m_currentTaskQueueSize >= m_taskQueueSize)

            {
                LOG_WARNING_L(functionName.c_str(), "[Endpoint: {}] Queue is full, pause listening.", m_address);
                pause();
                metrics::getManager().getMetric("event_endpoint.busy_queue")->update<uint64_t>(1UL);
            }
            metrics::getManager()
                .getMetric("event_endpoint.queue_history")
                ->update<uint64_t>(m_currentTaskQueueSize.load());

            // Create a job to the worker thread
            std::shared_ptr<std::string> dataPtr {std::make_shared<std::string>(std::move(data))};
            auto workerJob = m_loop->resource<uvw::WorkReq>(
                [this, dataPtr, functionName = logging::getLambdaName(__FUNCTION__, "handleWorkerRequest")]()
                {
                    try
                    {
                        m_callback(*dataPtr);
                    }
                    catch (const std::exception& e)
                    {
                        LOG_WARNING_L(
                            functionName.c_str(), "[Endpoint: {}] Error calling the callback: {}", m_address, e.what());
                    }
                });

            // Listen for the job completion
            workerJob->on<uvw::WorkEvent>(
                [this, functionName = logging::getLambdaName(__FUNCTION__, "handleWorkerEvent")](const uvw::WorkEvent&,
                                                                                                 uvw::WorkReq& work)
                {
                    m_currentTaskQueueSize--;
                    if (resume())
                    {
                        LOG_WARNING_L(functionName.c_str(), "[Endpoint: {}] Resume listening.", m_address);
                    }
                    metrics::getManager()
                        .getMetric("event_endpoint.queue_history")
                        ->update<uint64_t>(m_currentTaskQueueSize.load());
                });

            workerJob->on<uvw::ErrorEvent>(
                [this, functionName = logging::getLambdaName(__FUNCTION__, "handleWorkerErrorEvent")](
                    const uvw::ErrorEvent& error, uvw::WorkReq& work)
                {
                    LOG_WARNING_L(functionName.c_str(),
                                  "[Endpoint: {}] Error calling the callback: {}",
                                  m_address,
                                  error.what(),
                                  error.code());
                    m_currentTaskQueueSize--;
                    if (resume())
                    {
                        LOG_WARNING_L(functionName.c_str(), "[Endpoint: {}] Resume listening.", m_address);
                    }
                    metrics::getManager()
                        .getMetric("event_endpoint.queue_history")
                        ->update<uint64_t>(m_currentTaskQueueSize.load());
                });
            workerJob->queue();
        });

    // Listen for errors
    m_handle->on<uvw::ErrorEvent>(
        [this, functionName = logging::getLambdaName(__FUNCTION__, "handleErrorEvent")](const uvw::ErrorEvent& event,
                                                                                        uvw::UDPHandle& handle)
        {
            // Log the error
            LOG_WARNING_L(functionName.c_str(),
                          "[Endpoint: {}] Error: code=[{}]; name=[{}]; message=[{}].",
                          m_address,
                          event.code(),
                          event.name(),
                          event.what());
        });

    m_handle->on<uvw::CloseEvent>(
        [this, functionName = logging::getLambdaName(__FUNCTION__, "handleCloseEvent")](const uvw::CloseEvent& event,
                                                                                        uvw::UDPHandle& handle)
        {
            // Log the error
            LOG_INFO_L(functionName.c_str(), "[Endpoint: {}] Closed.", m_address);
        });
    // Bind the socket
    auto socketFd = bindUnixDatagramSocket(m_bufferSize);
    m_handle->open(socketFd);
    resume();
}

void UnixDatagram::close()
{
    if (isBound())
    {
        m_handle->close();
        m_handle.reset();
        m_loop.reset();
        m_running = false;
    }
}

bool UnixDatagram::pause()
{
    if (m_running && isBound())
    {
        m_handle->stop();
        m_running = false;
        return true;
    }
    return false;
}

bool UnixDatagram::resume()
{
    if (!m_running && isBound())
    {
        m_handle->recv();
        m_running = true;
        return true;
    }
    return false;
}

int UnixDatagram::bindUnixDatagramSocket(int& bufferSize)
{
    sockaddr_un n_us {};

    // Remove the socket file if it already exists
    unlinkUnixSocket();

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, m_address.c_str(), sizeof(n_us.sun_path) - 1);

    const int socketFd {socket(PF_UNIX, SOCK_DGRAM, 0)};
    if (0 > socketFd)
    {
        auto msg = fmt::format("Cannot create the socket '{}': {} ({})", m_address, strerror(errno), errno);
        throw std::runtime_error(msg);
    }

    if (::bind(socketFd, reinterpret_cast<sockaddr*>(&n_us), SUN_LEN(&n_us)) < 0)
    {

        auto msg = fmt::format("Cannot bind the socket '{}': {} ({})", m_address, strerror(errno), errno);
        ::close(socketFd);
        throw std::runtime_error(msg);
    }

    // Change permissions
    if (chmod(m_address.c_str(), 0660) < 0) // TODO: Save the permissions in a constant
    {
        auto msg =
            fmt::format("Cannot change permissions of the socket '{}': {} ({})", m_address, strerror(errno), errno);
        ::close(socketFd);
        throw std::runtime_error(msg);
    }

    // Get current maximum size
    socklen_t optlen {sizeof(bufferSize)};
    if (-1 == getsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<void*>(&bufferSize), &optlen))
    {
        bufferSize = 0;
    }

    // Set maximum message size
    if (MAX_MSG_SIZE > bufferSize)
    {
        bufferSize = MAX_MSG_SIZE;
        if (setsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const void*>(&bufferSize), optlen) < 0)
        {
            auto msg = fmt::format(
                "Cannot set maximum message size of the socket '{}': {} ({})", m_address, strerror(errno), errno);
            ::close(socketFd);
            throw std::runtime_error(msg);
        }
    }

    // Set close-on-exec
    if (-1 == fcntl(socketFd, F_SETFD, FD_CLOEXEC))
    {
        LOG_WARNING(
            "[Endpoint: {}] Cannot set close-on-exec flag to socket: {} ({})", m_address, strerror(errno), errno);
    }

    return socketFd;
}

} // namespace engineserver::endpoint
