#include <server/engineServer.hpp>

#include <cstring>      // Unix  socket datagram bind
#include <fcntl.h>      // Unix socket datagram bind
#include <sys/socket.h> // Unix socket datagram bind
#include <sys/un.h>     // Unix socket datagram bind
#include <unistd.h>     // Unix socket datagram bind

#include <exception>

#include <logging/logging.hpp>

namespace engineserver
{

EngineServer::EngineServer()
{

    m_loop = uvw::Loop::getDefault();
    m_status = Status::STOPPED;

    m_stopHandle = m_loop->resource<uvw::AsyncHandle>();
    m_stopHandle->on<uvw::AsyncEvent>(
        [this](const uvw::AsyncEvent&, uvw::AsyncHandle&)
        {
            this->stop();
            this->m_status = Status::STOPPED;
        });

    m_endpoints = std::unordered_map<std::string, std::shared_ptr<Endpoint>>();
}

EngineServer::~EngineServer() {
    this->stop();
    this->m_loop->close();
};

void EngineServer::start()
{
    WAZUH_LOG_INFO("Starting the server");
    m_status = Status::RUNNING;
    m_loop->run<uvw::Loop::Mode::DEFAULT>();
    WAZUH_LOG_INFO("Server stopped");
}

void EngineServer::stop()
{
    WAZUH_LOG_INFO("Stopping the server");
    m_loop->walk([](auto& handle) { handle.close(); });
    m_loop->stop();
}

void EngineServer::request_stop()
{
    WAZUH_LOG_DEBUG("Requesting stop");
    // Send the stop request
    m_stopHandle->send();
}

void EngineServer::addEndpoint(const std::string& name, std::shared_ptr<Endpoint> endpoint) {
    WAZUH_LOG_DEBUG("Adding endpoint " + name);
    // first check if the endpoint already exists
    if (m_endpoints.find(name) != m_endpoints.end()) {
        throw std::runtime_error("Endpoint " + name + " already exists");
    }
    // add the endpoint
    m_endpoints[name] = endpoint;
}
} // namespace engineserver
