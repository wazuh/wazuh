#ifndef _HTTPSRV_ISERVER_HPP
#define _HTTPSRV_ISERVER_HPP

#include <filesystem>
#include <functional>
#include <string>

#include <fmt/format.h>

namespace httpsrv
{
enum class Method
{
    GET,
    POST,
    PUT,
    DELETE,
    ERROR_METHOD
};

constexpr auto methodToStr(Method method)
{
    switch (method)
    {
        case Method::GET: return "GET";
        case Method::POST: return "POST";
        case Method::PUT: return "PUT";
        case Method::DELETE: return "DELETE";
        default: return "ERROR_METHOD";
    }
}

constexpr auto strToMethod(const char* str)
{
    if (methodToStr(Method::GET) == str)
    {
        return Method::GET;
    }
    else if (methodToStr(Method::POST) == str)
    {
        return Method::POST;
    }
    else if (methodToStr(Method::PUT) == str)
    {
        return Method::PUT;
    }
    else if (methodToStr(Method::DELETE) == str)
    {
        return Method::DELETE;
    }
    else
    {
        return Method::ERROR_METHOD;
    }
}

template<class ServerImpl>
class IServer
{
private:
    ServerImpl m_server;

public:
    virtual ~IServer() = default;

    /**
     * @brief Starts the server with the specified socket path.
     *
     * @param socketPath The path to the socket file.
     */
    void start(const std::filesystem::path& socketPath)
    {
        try
        {
            m_server.start(socketPath);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Failed to start server at {}: {}", socketPath, e.what()));
        }
    }

    /**
     * Stops the server.
     */
    void stop() { m_server.stop(); }

    /**
     * @brief Adds a route to the server.
     *
     * This function adds a route to the server based on the specified HTTP method, route path, and handler
     * function. The handler function is called when a request matching the specified method and route is received by
     * the server.
     *
     * @param method The HTTP method for the route (GET, POST, PUT, DELETE).
     * @param route The route path.
     * @param handler The handler function to be called when a request is received. The handler function must take
     * two parameters: a const reference to the request object and a reference to the response object.
     * The request and response objects must be of google::protobuf::Message type or httplib::Request and
     * httplib::Response respectively.
     */
    template<typename Request, typename Response>
    void
    addRoute(Method method, const std::string& route, const std::function<void(const Request&, Response&)>& handler)
    {
        try
        {
            m_server.addRoute(method, route, handler);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Failed to add route {}:{} error: {}", methodToStr(method), route, e.what()));
        }
    }
};
} // namespace httpsrv

#endif // _HTTPSRV_ISERVER_HPP
