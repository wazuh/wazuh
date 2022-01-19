/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "engineserver_test.hpp"

using namespace engineserver;
using namespace protocolhandler;

TEST(EngineServer, parse_event)
{
    MessageQueue queue = SYSLOG;
    std::string location = "/var/log/syslog";
    std::string message = "Nov  9 16:06:26 localhost salute: Hello world.";

    auto object = parseEvent(std::to_string(queue) + ":" + location + ":" + message);

    ASSERT_EQ(object["queue"], SYSLOG);
    ASSERT_EQ(object["location"], location);
    ASSERT_EQ(object["message"], message);
}

TEST(EngineServer, listen_TCP)
{
    const int tcpPort{5050};
    EngineServer server;

    server.listenTCP(tcpPort);
    server.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    server.close();
}

TEST(EngineServer, subscribe_TCP)
{
    const int tcpPort{5050};
    EngineServer server;

    server.listenTCP(tcpPort);

    try
    {
        auto tcpObs = server.getEndpointObservable(EndpointType::TCP, tcpPort);

        ASSERT_TRUE(tcpObs);

        tcpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
            [&server](nlohmann::json event)
            { std::cout << "TCP (" << tcpPort << "): " << event.at("message") << "\n"; },
            []() { printf("OnEnd?"); }));
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << '\n';
    }
}

TEST(EngineServer, listen_UDP)
{
    const int udpPort{5051};
    EngineServer server;

    server.listenUDP(udpPort);
    server.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    server.close();
}

TEST(EngineServer, subscribe_UDP)
{
    const int udpPort{5050};
    EngineServer server;

    server.listenUDP(udpPort);

    try
    {
        auto udpObs = server.getEndpointObservable(EndpointType::UDP, udpPort);

        ASSERT_TRUE(udpObs);

        udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
            [&server](nlohmann::json event)
            { std::cout << "UDP (" << udpPort << "): " << event.at("message") << "\n"; },
            []() { printf("OnEnd?"); }));
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << '\n';
    }
}

TEST(EngineServer, listen_socket)
{
    const std::string sockPath{"/tmp/test.sock"};
    EngineServer server;

    server.listenSocket(sockPath);
    server.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    server.close();
}

TEST(EngineServer, subscribe_socket)
{
    const std::string sockPath{"/tmp/test.sock"};
    EngineServer server;

    server.listenSocket(sockPath);

    try
    {
        auto sockObs = server.getEndpointObservable(EndpointType::SOCKET, sockPath);

        ASSERT_TRUE(sockObs);

        sockObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
            [&server, &sockPath](nlohmann::json event)
            { std::cout << "Socket (" << sockPath << "): " << event.at("message") << "\n"; },
            []() { printf("OnEnd?"); }));
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << '\n';
    }
}

TEST(EngineServer, listen_and_subscribe_multiple_endpoints)
{
    const std::string sockPath{"/tmp/test.sock"};
    const int tcpPort{5050};
    const int udpPort{5051};

    EngineServer server;

    server.listenSocket(sockPath);

    server.listenTCP(tcpPort);

    server.listenUDP(udpPort);

    auto sockObs = server.getEndpointObservable(EndpointType::SOCKET, sockPath);

    ASSERT_TRUE(sockObs);

    sockObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
        [&server, &sockPath](nlohmann::json event)
        { std::cout << "SOCKET (" << sockPath << "): " << event.at("message") << "\n"; },
        []() { printf("OnEnd?"); }));

    auto tcpObs = server.getEndpointObservable(EndpointType::TCP, tcpPort);

    ASSERT_TRUE(tcpObs);

    tcpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
        [&server](nlohmann::json event) { std::cout << "TCP (" << tcpPort << "): " << event.at("message") << "\n"; },
        []() { printf("OnEnd?"); }));

    auto udpObs = server.getEndpointObservable(EndpointType::UDP, udpPort);

    ASSERT_TRUE(udpObs);

    udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
        [&server](nlohmann::json event) { std::cout << "UDP (" << udpPort << "): " << event.at("message") << "\n"; },
        []() { printf("OnEnd?"); }));

    server.run();

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    server.close();
}
