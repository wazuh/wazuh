#ifndef _HTTPSRV_SERVER_HPP
#define _HTTPSRV_SERVER_HPP

#include <memory>
#include <thread>

#include <httplib.h>

#include <httpsrv/iserver.hpp>

namespace httpsrv
{

/**
 * @brief Implementation of the server using httplib.
 *
 */
class Server : public IServer<Server>
{
private:
    std::shared_ptr<httplib::Server> m_srv; ///< Httplib Server instance
    std::thread m_thread;                   ///< Server thread
    std::string m_id;                       ///< Server identifier
    std::filesystem::path m_socketPath;    ///< Socket path where the server is listening

    /**
     * @brief Binds the server to a socket and starts listening for incoming connections.
     *
     * This method is blocking and will run until the server is stopped, either by calling stop() or due to an error.
     * If the server fails to bind to the socket or start listening, it will return false.
     * @return true if the server successfully binds and starts listening, false otherwise.
     * @note This method is blockin and should be called in a separate thread if non-blocking behavior is desired.
     */
    bool bindAndListen();

public:
    /**
     * @brief Construct a new Server object
     *
     * @param id Server string identifier
     */
    Server(const std::string& id);

    /**
     * @brief Destroy the Server object
     *
     */
    ~Server() override { stop(); }

    /**
     * @brief Start the server at the specified socket path.
     *
     * @param socketPath Socket path, if the file exists it will be removed, and the parent directory must exist.
     * @param useThread If true, the server will be started in a separate thread.
     *
     * @throws std::runtime_error If the server fails to start.
     */
    void start(const std::filesystem::path& socketPath, bool useThread = true);

    /**
     * @brief Stop the server.
     */
    void stop() noexcept;

    /**
     * @brief Add a route to the server.
     *
     * @param method Method of the route
     * @param route Route path
     * @param handler Handler function
     */
    void addRoute(Method method,
                  const std::string& route,
                  const std::function<void(const httplib::Request&, httplib::Response&)>& handler);

    /**
     * @brief Check if the server is running.
     *
     * @return true If the server is running.
     * @return false Otherwise.
     */
    bool isRunning() const { return m_srv->is_running(); }
};
} // namespace httpsrv

#endif // _HTTPSRV_SERVER_HPP
