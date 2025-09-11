#ifndef _HTTPSRV_ISERVER_HPP
#define _HTTPSRV_ISERVER_HPP

#include <filesystem>
#include <functional>
#include <string>

namespace httpsrv
{

/**
 * @brief An enum class representing the HTTP methods supported by the server.
 *
 */
enum class Method
{
    GET,
    POST,
    PUT,
    DELETE,
    ERROR_METHOD
};

/**
 * @brief Obtain the string representation of the HTTP method.
 *
 * @param method
 * @return constexpr auto
 */
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

/**
 * @brief Obtain the HTTP method from the string representation.
 *
 * @param str
 * @return constexpr auto
 */
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

/**
 * @brief CRTP interface for the server.
 *
 * @tparam ServerImpl The server implementation.
 */
template<class ServerImpl>
class IServer
{
public:
    virtual ~IServer() = default;

    /**
     * @brief Starts the server with the specified socket path.
     *
     * @param socketPath The path to the socket file.
     * @param useThread If true, the server will be started in a separate thread.
     */
    void start(const std::filesystem::path& socketPath, bool useThread = true)
    {
        static_cast<ServerImpl*>(this)->start(socketPath, useThread);
    }

    /**
     * Stops the server.
     */
    void stop() { static_cast<ServerImpl*>(this)->stop(); }

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
     */
    template<typename Request, typename Response>
    void
    addRoute(Method method, const std::string& route, const std::function<void(const Request&, Response&)>& handler)
    {
        static_cast<ServerImpl*>(this)->addRoute(method, route, handler);
    }

    /**
     * @brief Check if the server is running.
     *
     * @return true If the server is running.
     * @return false Otherwise.
     */
    bool isRunning() const { return static_cast<ServerImpl*>(this)->isRunning(); }
};
} // namespace httpsrv

#endif // _HTTPSRV_ISERVER_HPP
