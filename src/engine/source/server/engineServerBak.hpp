/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ENGINESERVER_H_
#define _ENGINESERVER_H_

#include <mutex>
#include <optional>
#include <queue>

#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include <uvw/pipe.hpp>
#include <uvw/signal.hpp>
#include <uvw/tcp.hpp>
#include <uvw/timer.hpp>
#include <uvw/udp.hpp>

namespace protocolhandler
{
/**
 * @brief Used to differenciate the Wazuh events source
 */
enum MessageQueue
{
    UNKNOWN = 0,
    SYSLOG,
    IDS,
    FIREWALL,
    RSV1,
    RSV2,
    RSV3,
    APACHE,
    SQUID,
    WINDOWS,
    HOST_INFO,
    WAZUH_RULES,
    WAZUH_ALERTS
};

/**
 * @brief Extracts the Queue; Location and Message from the Wazuh event and creates a JSON object with them
 *
 * @param event String to be parsed
 * @return nlohmann::json Object containing the event in JSON format
 */
nlohmann::json parseEvent(std::string event);
} // namespace protocolhandler

namespace engineserver
{
/**
 * @brief Used to differenciate between server's endpoint types
 */
enum EndpointType
{
    TCP,
    UDP,
    SOCKET
};

class ServerEndpoint
{
private:
    EndpointType m_type;

    std::string m_path;

    std::shared_ptr<uvw::TCPHandle> m_tcphandle;
    std::shared_ptr<uvw::UDPHandle> m_udphandle;
    std::shared_ptr<uvw::PipeHandle> m_sockethandle;

    rxcpp::subjects::subject<nlohmann::json> m_subject;
    rxcpp::subscriber<nlohmann::json> m_subscriber;

public:
    /**
     * @brief Construct a new Server Endpoint object given a TCPHandle
     *
     * @param type Enpoint type
     * @param path Defines the endpoint univocally
     * @param handle Endpoint handler
     */
    ServerEndpoint(EndpointType type, std::string path, std::shared_ptr<uvw::TCPHandle> handle)
        : m_type{type}, m_path{path}, m_tcphandle{handle}, m_subscriber(m_subject.get_subscriber()){};
    /**
     * @brief Construct a new Server Endpoint object given a UDPHandle
     *
     * @param type Enpoint type
     * @param path Defines the endpoint univocally
     * @param handle Endpoint handler
     */
    ServerEndpoint(EndpointType type, std::string path, std::shared_ptr<uvw::UDPHandle> handle)
        : m_type{type}, m_path{path}, m_udphandle{handle}, m_subscriber(m_subject.get_subscriber()){};
    /**
     * @brief Construct a new Server Endpoint object given a PipeHandle (Socket)
     *
     * @param type Enpoint type
     * @param path Defines the endpoint univocally
     * @param handle Endpoint handler
     */
    ServerEndpoint(EndpointType type, std::string path, std::shared_ptr<uvw::PipeHandle> handle)
        : m_type{type}, m_path{path}, m_sockethandle{handle}, m_subscriber(m_subject.get_subscriber()){};

    /**
     * @brief Destroy the Server Endpoint object
     */
    ~ServerEndpoint(){};

    /**
     * @brief Get the Type object
     *
     * @return auto Endpoint type
     */
    auto getType(void)
    {
        return m_type;
    };

    /**
     * @brief Get the Path object
     *
     * @return auto Endpoint path
     */
    auto getPath(void)
    {
        return m_path;
    };

    /**
     * @brief Get the TCP Handle object
     *
     * @return auto Handle object
     */
    auto getTCPHandle(void)
    {
        return m_tcphandle;
    };

    /**
     * @brief Get the UDP Handle object

    * @return auto Handle object
    */
    auto getUDPHandle(void)
    {
        return m_udphandle;
    };

    /**
     * @brief Get the Socket Handle object
     *
     * @return auto Handle object
     */
    auto getSocketHandle(void)
    {
        return m_sockethandle;
    };

    /**
     * @brief Get the Subject object
     *
     * @return auto Subject object
     */
    auto getSubject(void)
    {
        return m_subject;
    };

    /**
     * @brief Get the Subscriber object
     *
     * @return auto Subscriber object
     */
    auto getSubscriber(void)
    {
        return m_subscriber;
    };

    /**
     * @brief Get the Observable object
     *
     * @return auto Observable object
     */
    auto getObservable(void)
    {
        return m_subject.get_observable();
    };
};

class EngineServer
{
private:
    std::shared_ptr<uvw::Loop> m_loop;
    std::list<ServerEndpoint> m_endpointList;

public:
    /**
     * @brief Construct a new Engine Server object
     */
    EngineServer();

    /**
     * @brief Destroy the Engine Server object
     */
    ~EngineServer();

    /**
     * @brief Starts the server's loop
     */
    void run(void);

    /**
     * @brief Stops the server's loop
     */
    void stop(void);

    /**
     * @brief Closes the server's loop
     */
    void close(void);

    /**
     * @brief Get the Subject object from a Server's endpoint
     *
     * @param type Endpoint's type
     * @param path Endpoint's path
     * @return std::optional<rxcpp::subjects::subject<nlohmann::json>> Optional Endpoint's Subject object
     */
    std::optional<rxcpp::subjects::subject<nlohmann::json>> getEndpointSubject(const EndpointType type,
                                                                               const std::string path);
    /**
     * @brief Get the Subject object from a Server's endpoint
     *
     * @param type Endpoint's type
     * @param port Endpoint's port
     * @param ip Endpoint's ip
     * @return std::optional<rxcpp::subjects::subject<nlohmann::json>> Optional Endpoint's Subject object
     */
    std::optional<rxcpp::subjects::subject<nlohmann::json>> getEndpointSubject(const EndpointType type, const int port,
                                                                               const std::string ip = "0.0.0.0");

    /**
     * @brief Get the Subscriber object from a Server's endpoint
     *
     * @param type Endpoint's type
     * @param path Endpoint's path
     * @return std::optional<rxcpp::subscriber<nlohmann::json>> Optional Endpoint's Subject object
     */
    std::optional<rxcpp::subscriber<nlohmann::json>> getEndpointSubscriber(const EndpointType type,
                                                                           const std::string path);
    /**
     * @brief Get the Subscriber object from a Server's endpoint
     *
     * @param type Endpoint's type
     * @param port Endpoint's port
     * @param ip Endpoint's ip
     * @return std::optional<rxcpp::subscriber<nlohmann::json>> Optional Endpoint's Subject object
     */
    std::optional<rxcpp::subscriber<nlohmann::json>> getEndpointSubscriber(const EndpointType type, const int port,
                                                                           const std::string ip = "0.0.0.0");

    /**
     * @brief Get the Observable object from a Server's endpoint
     *
     * @param type Endpoint's type
     * @param path Endpoint's path
     * @return std::optional<rxcpp::observable<nlohmann::json>> Optional Endpoint's Observable object
     */
    std::optional<rxcpp::observable<nlohmann::json>> getEndpointObservable(const EndpointType type,
                                                                           const std::string path);
    /**
     * @brief Get the Observable object from a Server's endpoint
     *
     * @param type Endpoint's type
     * @param port Endpoint's port
     * @param ip Endpoint's ip
     * @return std::optional<rxcpp::observable<nlohmann::json>> Optional Endpoint's Observable object
     */
    std::optional<rxcpp::observable<nlohmann::json>> getEndpointObservable(const EndpointType type, const int port,
                                                                           const std::string ip = "0.0.0.0");

    /**
     * @brief Opens a TCP socket and listens for the incoming events
     *
     * @param ip TCP socket interface IP
     * @param port TCP socket interface Port
     */
    void listenTCP(const int port, const std::string ip = "0.0.0.0");

    /**
     * @brief Opens a UDP socket and listens for the incoming events
     *
     * @param ip UDP socket interface IP
     * @param port UDP socket interface Port
     */
    void listenUDP(const int port, const std::string ip = "0.0.0.0");

    /**
     * @brief Opens a UNIX socket and listens for the incoming events
     *
     * @param path Absolute path to the UNIX socket
     */
    void listenSocket(const std::string path);

    /**
     * @brief Handles a signal given its signal number and a signal wrapping function
     *
     * @param signum Number of UNIX signal to be handled
     * @param signal_wrapper Signal handler function
     */
    void listenSignal(const int signum, void (*const signal_wrapper)(void *));

    /**
     * @brief If timeout is zero, a TimerEvent event is emitted on the next event loop
     * iteration. If repeat is non-zero, a TimerEvent event is emitted first
     * after timeout milliseconds and then repeatedly after repeat milliseconds.
     *
     * @param timeout Milliseconds before to emit an event
     * @param repeat Milliseconds between successive events
     * @param callback Callback to be called when a TimerEvent happens
     */
    void setTimer(const int timeout, const int repeat, void (*const callback)(void *));
};

} // namespace engineserver

#endif
