#ifndef _ENGINE_SERVER_H
#define _ENGINE_SERVER_H

#include <functional>
#include <memory>
#include <string>

#include <metrics/iMetricsManager.hpp>
#include <metrics/iMetricsScope.hpp>

namespace engineserver
{

class EngineServer
{
public:
    EngineServer();
    ~EngineServer();

    // No response is expected
    void addEndpoint_UnixDatagram_woResponse(const std::string& address, std::function<void(std::string&&)> callback);

    void start();
    void request_stop();

private:
    void stop();

    class Impl;                  // Declaración adelantada
    std::unique_ptr<Impl> pimpl; // Puntero único a la implementación
};

} // namespace server

#endif // _ENGINE_SERVER_H
