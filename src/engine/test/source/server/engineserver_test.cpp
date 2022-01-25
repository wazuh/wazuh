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

/**
 * @brief Test parsing a protocl event
 *
 */
TEST(ProtocolHandler, parse_event)
{
    MessageQueue queue = SYSLOG;
    std::string location{"/var/log/syslog"};
    std::string message{"Nov  9 16:06:26 localhost salute: Hello world."};

    nlohmann::json jsonObject;

    try
    {
        jsonObject = parseEvent(std::to_string(queue) + ":" + location + ":" + message);
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    ASSERT_EQ(jsonObject["queue"], SYSLOG);
    ASSERT_EQ(jsonObject["location"], location);
    ASSERT_EQ(jsonObject["message"], message);
}

/**
 * @brief Test listening to a TCP endpoint
 *
 */
TEST(EngineServer, listen_TCP)
{
    const int tcpPort{5050};

    EngineServer server;

    try
    {
        server.listenTCP(tcpPort);
        server.run();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        server.close();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }
}

/**
 * @brief Test subscribing to a TCP endpoint
 *
 */
TEST(EngineServer, subscribe_TCP)
{
    const int tcpPort{5051};

    EngineServer server;

    try
    {
        server.listenTCP(tcpPort);

        auto tcpObs = server.getEndpointObservable(EndpointType::TCP, tcpPort);

        ASSERT_TRUE(tcpObs);

        tcpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>([&server](nlohmann::json event) {}, []() {}));
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    server.close();
}

/**
 * @brief Test listening, subscribing and publishing to a TCP endpoint
 *
 */
TEST(EngineServer, listen_subscribe_publish_TCP)
{
    const int tcpPort{5052};

    const std::string expectedString{"This is a testing string that has to be completely received by TCP subscribers"};

    EngineServer server;

    try
    {
        server.listenTCP(tcpPort);

        auto tcpObs = server.getEndpointObservable(EndpointType::TCP, tcpPort);

        ASSERT_TRUE(tcpObs);

        tcpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
            [&server, &expectedString](nlohmann::json event)
            { ASSERT_STREQ(expectedString.c_str(), std::string(event["message"]).c_str()); },
            []() {}));

        server.run();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    try
    {
        auto subscriber = server.getEndpointSubscriber(engineserver::EndpointType::TCP, tcpPort);
        if (subscriber)
        {
            nlohmann::json jsonEvent;
            jsonEvent["message"] = expectedString;
            subscriber->on_next(jsonEvent);
        }
        else
        {
            std::cerr << "Subscriber was not found." << std::endl;
        }
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    server.close();
}

/**
 * @brief Test listening to a UDP endpoint
 *
 */
TEST(EngineServer, listen_UDP)
{
    const int udpPort{5060};

    EngineServer server;

    try
    {
        server.listenUDP(udpPort);
        server.run();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        server.close();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }
}

/**
 * @brief Test subscribing to a UDP endpoint
 *
 */
TEST(EngineServer, subscribe_UDP)
{
    const int udpPort{5061};

    EngineServer server;

    try
    {
        server.listenUDP(udpPort);

        auto udpObs = server.getEndpointObservable(EndpointType::UDP, udpPort);

        ASSERT_TRUE(udpObs);

        udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>([&server](nlohmann::json event) {}, []() {}));
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    server.close();
}

/**
 * @brief Test listening, subscribing and publishing to a UDP endpoint
 *
 */
TEST(EngineServer, listen_subscribe_publish_UDP)
{
    const int udpPort{5062};

    const std::string expectedString{"This is a testing string that has to be completely received by UDP subscribers"};

    EngineServer server;

    try
    {
        server.listenUDP(udpPort);

        auto udpObs = server.getEndpointObservable(EndpointType::UDP, udpPort);

        ASSERT_TRUE(udpObs);

        udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
            [&server, &expectedString](nlohmann::json event)
            { ASSERT_STREQ(expectedString.c_str(), std::string(event["message"]).c_str()); },
            []() {}));

        server.run();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    try
    {
        auto subscriber = server.getEndpointSubscriber(engineserver::EndpointType::UDP, udpPort);
        if (subscriber)
        {
            nlohmann::json jsonEvent;
            jsonEvent["message"] = expectedString;
            subscriber->on_next(jsonEvent);
        }
        else
        {
            std::cerr << "Subscriber was not found." << std::endl;
        }
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    server.close();
}

/**
 * @brief Test listening to a Socket endpoint
 *
 */
TEST(EngineServer, listen_Socket)
{
    const std::string sockPath{"/tmp/test_listen.sock"};

    EngineServer server;

    try
    {
        server.listenSocket(sockPath);
        server.run();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        server.close();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }
}

/**
 * @brief Test subscribing to a Socket endpoint
 *
 */
TEST(EngineServer, subscribe_Socket)
{
    const std::string socketPath{"/tmp/test_subscribe.sock"};

    EngineServer server;

    try
    {
        server.listenSocket(socketPath);

        auto udpObs = server.getEndpointObservable(EndpointType::SOCKET, socketPath);

        ASSERT_TRUE(udpObs);

        udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>([&server](nlohmann::json event) {}, []() {}));
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    server.close();
}

/**
 * @brief Test listening, subscribing and publishing to a SOCKET endpoint
 *
 */
TEST(EngineServer, listen_subscribe_publish_SOCKET)
{
    const std::string sockPath{"/tmp/test_listen_subscribe_publish.sock"};

    const std::string expectedString{"This is a testing string that has to be completely received by SOCK subscribers"};

    EngineServer server;

    try
    {
        server.listenSocket(sockPath);

        auto udpObs = server.getEndpointObservable(EndpointType::SOCKET, sockPath);

        ASSERT_TRUE(udpObs);

        udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
            [&server, &expectedString](nlohmann::json event)
            { ASSERT_STREQ(expectedString.c_str(), std::string(event["message"]).c_str()); },
            []() {}));

        server.run();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    try
    {
        auto subscriber = server.getEndpointSubscriber(engineserver::EndpointType::SOCKET, sockPath);
        if (subscriber)
        {
            nlohmann::json jsonEvent;
            jsonEvent["message"] = expectedString;
            subscriber->on_next(jsonEvent);
        }
        else
        {
            std::cerr << "Subscriber was not found." << std::endl;
        }
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    server.close();
}

/**
 * @brief Test listening and subscribing to multiple different endpoints
 *
 */
TEST(EngineServer, listen_and_subscribe_multiple_endpoints)
{
    const int tcpPort{5053};
    const int udpPort{5063};
    const std::string sockPath{"/tmp/test.sock"};

    EngineServer server;

    try
    {
        server.listenSocket(sockPath);
        server.listenTCP(tcpPort);
        server.listenUDP(udpPort);

        auto sockObs = server.getEndpointObservable(EndpointType::SOCKET, sockPath);

        ASSERT_TRUE(sockObs);

        sockObs.value().subscribe(
            rxcpp::make_subscriber<nlohmann::json>([&server, &sockPath](nlohmann::json event) {}, []() {}));

        auto tcpObs = server.getEndpointObservable(EndpointType::TCP, tcpPort);

        ASSERT_TRUE(tcpObs);

        tcpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>([&server](nlohmann::json event) {}, []() {}));

        auto udpObs = server.getEndpointObservable(EndpointType::UDP, udpPort);

        ASSERT_TRUE(udpObs);

        udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>([&server](nlohmann::json event) {}, []() {}));

        server.run();

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        server.close();
    }
    catch (const std::exception & e)
    {
        std::cerr << e.what() << std::endl;
    }
}
