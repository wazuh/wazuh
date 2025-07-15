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
