#ifndef _UDServer_HPP
#define _UDServer_HPP

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace udsrv
{

/**
 * @class Server
 * @brief UNIX‐domain datagram socket server that dispatches received messages to a handler using a thread pool.
 *
 * Clients send datagrams to this socket; each datagram is handed off to a user-provided handler function.
 * Call start(pool_size) to spawn @c pool_size worker threads, each of which loops receiving datagrams and
 * invoking the handler. Call stop() to shut down the threads and close the socket.
 *
 * The destructor ensures stop() is called and unlinks the socket file.
 */
class Server
{

private:
    /**
     * @brief Worker loop: receives datagrams from the socket and invokes the handler.
     *
     * Each worker allocates a buffer of size 65536 bytes (max datagram),
     * calls recv(), and then constructs a std::string from the received bytes.
     * The std::string always contains exactly n bytes and is null‐terminated internally by std::string.
     * It is then moved into the handler.
     */
    void workerLoop();

    std::function<void(std::string&&)> m_handler; ///< User‐provided handler for each received message
    std::string m_socketPath;                     ///< Filesystem path of the UNIX datagram socket
    int m_sockFd;                                 ///< File descriptor of the bound socket (or -1 if closed)
    std::atomic<bool> m_running;                  ///< True while threads should keep running
    std::vector<std::thread> m_threads;           ///< Worker threads

public:
    /**
     * @brief Construct a Server.
     *
     * @param handler     A callable taking a single std::string argument (the received datagram's bytes).
     * @param socketPath  Filesystem path of the UNIX datagram socket. If it already exists, it will be replaced.
     *
     * @throws std::runtime_error if any step of socket creation, binding, permission setting, or buffer sizing fails.
     *
     * @note The server creates a socket with mode 0660 (read/write for owner, group) based on @c getuid() and
     *       @c getgid().
     */
    explicit Server(std::function<void(std::string&&)> handler, std::string socketPath);

    /// No copy construction
    Server(const Server&) = delete;
    /// No copy assignment
    Server& operator=(const Server&) = delete;
    /// No move construction
    Server(Server&&) = delete;
    /// No move assignment
    Server& operator=(Server&&) = delete;

    /**
     * @brief Start the server with a pool of worker threads.
     *
     * @param poolSize  Number of threads to spawn. Each thread will block on recv() and
     *                   invoke the handler for each received datagram.
     *
     * @throws std::runtime_error if called when already running or if poolSize == 0.
     */
    void start(size_t poolSize);

    /**
     * @brief Stop the server: signal threads to exit, close the socket, and join all threads.
     *
     * If the server is not running, this is a no‐op.
     */
    void stop();

    /**
     * @brief Check if the server is currently running.
     *
     * @return true if the server is running, false otherwise.
     */
    bool isRunning() const { return m_running.load(); }

    /**
     * @brief Destructor: calls stop() and unlinks the socket file.
     */
    ~Server();
};

} // namespace udsrv

#endif // _UDServer_HPP
