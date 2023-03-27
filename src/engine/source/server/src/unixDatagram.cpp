#include <server/unixDatagram.hpp>

#include <cstring>      // Unix  socket datagram bind
#include <fcntl.h>      // Unix socket datagram bind
#include <sys/socket.h> // Unix socket datagram bind
#include <sys/un.h>     // Unix socket datagram bind
#include <unistd.h>     // Unix socket datagram bind

#include <logging/logging.hpp>
#include <uvw.hpp>

namespace
{

constexpr unsigned int MAX_MSG_SIZE {65536 + 512}; ///< Maximum message size (TODO: I think this should be 65507)

/**
 * @brief This function opens, binds and configures a Unix datagram socket.
 * @param path Contains the absolute path to the Unix datagram socket. The path must be less than 108 bytes.
 * @return Returns either the file descriptor value
 * @throw std::runtime_error if the path is too long or the socket cannot be created or bound.
 */
inline int bindUnixDatagramSocket(const std::string& path, int& bufferSize)
{
    sockaddr_un n_us;

    // Check the path length
    if (path.length() >= sizeof(n_us.sun_path))
    {
        auto msg = fmt::format("Path '{}' too long, maximum length is {} ", path, sizeof(n_us.sun_path));
        throw std::runtime_error(std::move(msg));
    }

    // Remove the socket file if it already exists
    unlink(path.c_str());

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path.c_str(), sizeof(n_us.sun_path) - 1);

    const int socketFd {socket(PF_UNIX, SOCK_DGRAM, 0)};
    if (0 > socketFd)
    {
        auto msg = fmt::format("Cannot create the socket '{}': {} ({})", path, strerror(errno), errno);
        throw std::runtime_error(std::move(msg));
    }

    if (bind(socketFd, reinterpret_cast<sockaddr*>(&n_us), SUN_LEN(&n_us)) < 0)
    {

        auto msg = fmt::format("Cannot bind the socket '{}': {} ({})", path, strerror(errno), errno);
        close(socketFd);
        throw std::runtime_error(std::move(msg));
    }

    // Change permissions
    if (chmod(path.c_str(), 0660) < 0) // TODO: Save the permissions in a constant
    {
        auto msg = fmt::format("Cannot change permissions of the socket '{}': {} ({})", path, strerror(errno), errno);
        close(socketFd);
        throw std::runtime_error(std::move(msg));
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
                "Cannot set maximum message size of the socket '{}': {} ({})", path, strerror(errno), errno);
            close(socketFd);
            throw std::runtime_error(std::move(msg));
        }
    }

    // Set close-on-exec
    if (-1 == fcntl(socketFd, F_SETFD, FD_CLOEXEC))
    {
        WAZUH_LOG_WARN("Cannot set close-on-exec flag to socket: {} ({})", strerror(errno), errno);
    }

    return socketFd;
}
} // namespace

namespace engineserver::endpoint
{
UnixDatagram::UnixDatagram(const std::string& address, std::function<void(std::string&&)> callback)
    : Endpoint(address)
    , m_callback(callback)
    , m_handle(nullptr)
    , m_currentQWSize(0)
{
}

UnixDatagram::~UnixDatagram() = default;

void UnixDatagram::bind(std::shared_ptr<uvw::Loop> loop, const std::size_t queueWorkerSize)
{
    if (isBound())
    {
        throw std::runtime_error("Endpoint already bound");
    }

    m_loop = loop;
    m_handle = m_loop->resource<uvw::UDPHandle>();

    // Listen for incoming data
    m_handle->on<uvw::UDPDataEvent>(
        [this, queueWorkerSize](const uvw::UDPDataEvent& event, uvw::UDPHandle& handle)
        {
            // Get the data
            auto data = std::string {event.data.get(), event.length};

            // Call the callback if is synchronous
            if (0 == queueWorkerSize)
            {
                m_callback(std::move(data));
                return;
            }

            // Call the callback if is asynchronous,
            if (++m_currentQWSize >= queueWorkerSize)

            {
                WAZUH_LOG_WARN("Engine event endpoints: Queue is full, pause listening.");
                pause();
            }

            // Create a job to the worker thread
            // TODO: Check if this
            std::shared_ptr<std::string> dataPtr {std::make_shared<std::string>(std::move(data))};
            auto workerJob = m_loop->resource<uvw::WorkReq>([this, dataPtr]() { m_callback(std::move(*dataPtr)); });

            // Listen for the job completion
            workerJob->on<uvw::WorkEvent>(
                [this](const uvw::WorkEvent&, uvw::WorkReq& work)
                {
                    m_currentQWSize--;
                    resume();
                });

            workerJob->on<uvw::ErrorEvent>(
                [this](const uvw::ErrorEvent& error, uvw::WorkReq& work)
                {
                    WAZUH_LOG_WARN("Engine event endpoints: Error on worker job: {} ({})", error.what(), error.code());
                    m_currentQWSize--;
                    resume();
                });
            workerJob->queue();
        });

    // Listen for errors
    m_handle->on<uvw::ErrorEvent>(
        [this](const uvw::ErrorEvent& event, uvw::UDPHandle& handle)
        {
            // Log the error
            WAZUH_LOG_WARN("Engine event endpoints: Event error on datagram socket "
                           "({}): code=[{}]; name=[{}]; message=[{}].",
                           m_address,
                           event.code(),
                           event.name(),
                           event.what());
        });

    // Bind the socket
    auto socketFd = bindUnixDatagramSocket(m_address, m_bufferSize);

    m_handle->open(socketFd);
}

void UnixDatagram::close()
{
    if (isBound())
    {
        m_handle->close();
        m_handle = nullptr;
        m_loop = nullptr;
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

} // namespace engineserver::endpoint
