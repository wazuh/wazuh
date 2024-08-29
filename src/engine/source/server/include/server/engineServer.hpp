#ifndef _SERVER_SERVER_H
#define _SERVER_SERVER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include <uvw.hpp>
#include <uvw/async.h>

#include <server/endpoint.hpp>

namespace engineserver
{
/**
 * @brief The EngineServer class is the main class of the server. It is responsible for managing the endpoints and the
 * main loop.
 *
 * The EngineServer class is the main class of the server. It is responsible for managing the endpoints and the main
 * loop. The main loop is implemented using uvw, a C++ wrapper for libuv. The loop is the default loop of the
 * application.
 *
 * @warning the default loop is a singleton. This means that the loop is shared between all the classes of the
 */
class EngineServer
{
    /**
     * @brief The Status enum is used to keep track of the status of the server.
     */
    enum class Status
    {
        STOPPED,
        RUNNING,
        STOPPING
    };

private:
    std::shared_ptr<uvw::Loop> m_loop;                                      ///< The main loop of the application.
    Status m_status;                                                        ///< The status of the server.
    std::shared_ptr<uvw::AsyncHandle> m_stopHandle;                         ///< The handle used to stop the server.
    std::unordered_map<std::string, std::shared_ptr<Endpoint>> m_endpoints; ///< The endpoints of the server.

    void stop();

public:
    /**
     * @brief Construct a new Engine Server object
     * @param threadPoolSize The size of the thread pool worker. This is the number of threads that will be used
     * to process the requests if the request is not processed in the main thread.
     *
     */
    EngineServer(int threadPoolSize = 1);
    ~EngineServer();

    /**
     * @brief Add an endpoint to the server.
     *
     * @param name (const std::string&) The name of the endpoint.
     * @param endpoint (std::shared_ptr<Endpoint>) The endpoint to add.
     *
     * @throw std::runtime_error If the endpoint name is already in use.
     */
    void addEndpoint(const std::string& name, std::shared_ptr<Endpoint> endpoint);

    /**
     * @brief Start the server. This method will start the main loop in blocking mode. (same thread)
     *
     */
    void start();

    /**
     * @brief This method will send a request to stop the server. The server will stop after the current request is
     * processed.
     * @note This method is thread safe and can be called from any thread, this is the recommended way to stop the
     * server.
     */
    void request_stop();
};

} // namespace engineserver

#endif // _SERVER_SERVER_H
