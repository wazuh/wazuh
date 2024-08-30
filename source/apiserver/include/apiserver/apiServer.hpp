#ifndef _APISERVER_HPP
#define _APISERVER_HPP

#include <filesystem>
#include <httplib.h>
#include <thread>

namespace apiserver
{
enum class Method
{
    GET,
    POST,
    PUT,
    DELETE
};

class ApiServer final
{
    httplib::Server m_svr;
    std::thread m_thread;

public:
    ~ApiServer() = default;
    ApiServer();

    void start(const std::filesystem::path& socketPath = "sockets/engine.sock");
    void stop();
    void addRoute(Method method,
                  const std::string& route,
                  const std::function<void(const httplib::Request&, httplib::Response&)>& handler);
};
} // namespace apiserver

#endif // _APISERVER_HPP
