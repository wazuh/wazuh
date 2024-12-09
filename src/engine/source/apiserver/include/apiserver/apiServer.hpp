// Copyright (C) 2024 Wazuh Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

/**
 * @class ServerAlreadyRunningException
 * @brief Exception thrown when the server is already running.
 *
 * This exception is derived from std::logic_error and is thrown when an attempt is made to start the server
 * when it is already running.
 */
class ServerAlreadyRunningException : public std::logic_error
{
public:
    /**
     * @brief Exception thrown when the server is already running.
     */
    ServerAlreadyRunningException()
        : std::logic_error("Server is already running")
    {
    }
};

class ApiServer final
{
    httplib::Server m_svr;
    std::thread m_thread;

public:
    /**
     * @brief Constructs an instance of the ApiServer class.
     *
     * This constructor initializes the ApiServer object by setting up the logger and error handler.
     * The error handler is set to a lambda function that handles invalid requests. It creates a JSON response
     * with an error message and the HTTP status code, and sets the response content type to "application/json".
     */
    ApiServer();

    /**
     * @brief Destructor for the ApiServer class.
     *
     * This destructor stops the ApiServer by calling the stop() function.
     */
    ~ApiServer();

    /**
     * @brief Starts the API server with the specified socket path.
     *
     * @param socketPath The path to the socket file.
     * @throws std::invalid_argument if the socket path is empty.
     * @throws ServerAlreadyRunningException if the server is already running.
     */
    void start(const std::filesystem::path& socketPath = "sockets/engine.sock");

    /**
     * Stops the API server.
     */
    void stop();

    /**
     * @brief Adds a route to the API server.
     *
     * This function adds a route to the API server based on the specified HTTP method, route path, and handler
     * function. The handler function is called when a request matching the specified method and route is received by
     * the server.
     *
     * @param method The HTTP method for the route (GET, POST, PUT, DELETE).
     * @param route The route path.
     * @param handler The handler function to be called when a request is received.
     */
    void addRoute(Method method,
                  const std::string& route,
                  const std::function<void(const httplib::Request&, httplib::Response&)>& handler);

    /**
     * @brief Checks if the API server is currently running.
     *
     * @return true if the API server is running, false otherwise.
     */
    bool isRunning() const;
};
} // namespace apiserver

#endif // _APISERVER_HPP
