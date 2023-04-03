#ifndef _SERVER_SERVER_H
#define _SERVER_SERVER_H

#include <functional>
#include <memory>
#include <string>

#include <uvw.hpp>
#include <uvw/async.hpp>

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
    enum class Status
    {
        STOPPED,
        RUNNING,
        STOPPING
    };
private:
    std::shared_ptr<uvw::Loop> m_loop;
    Status m_status;
    std::shared_ptr<uvw::AsyncHandle> m_stopHandle;
    std::unordered_map<std::string, std::shared_ptr<Endpoint>> m_endpoints;

    void stop();

public:
    EngineServer();
    ~EngineServer();

    void addEndpoint(const std::string& name, std::shared_ptr<Endpoint> endpoint);

    void start();
    void request_stop();

};

} // namespace server

#endif // _SERVER_SERVER_H
