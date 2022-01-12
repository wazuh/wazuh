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


TEST(EngineServer, parseEvent)
{
    MessageQueue queue = SYSLOG;
    std::string location = "/var/log/syslog";
    std::string message = "Nov  9 16:06:26 localhost salute: Hello world.";

    auto object = parseEvent(std::to_string(queue) + ":" + location + ":" + message);

    ASSERT_EQ(object["queue"], SYSLOG);
    ASSERT_EQ(object["location"], location);
    ASSERT_EQ(object["message"], message);
}

// TEST(EngineServer, blocking_test_nc)
// {
//     EngineServer server;

//     server.listenSocket("/tmp/test.sock");

//     server.listenTCP(5050);

//     server.listenUDP(5051);

//     auto sockObs = server.getEndpointObservable(EndpointType::SOCKET, "/tmp/test.sock");
//     if(sockObs)
//     {
//         sockObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
//                                 [&server](nlohmann::json event){ std::cout << "SOCKET: " << event.at("message") << "\n"; },
//                                 [](){printf("OnEnd?");}));
//     }

//     auto tcpObs = server.getEndpointObservable(EndpointType::TCP, 5050);
//     if(tcpObs)
//     {
//         tcpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
//                                 [&server](nlohmann::json event){ std::cout << "TCP (5050): " << event.at("message") << "\n"; },
//                                 [](){printf("OnEnd?");}));
//     }

//     auto udpObs = server.getEndpointObservable(EndpointType::UDP, 5051);
//     if(udpObs)
//     {
//         udpObs.value().subscribe(rxcpp::make_subscriber<nlohmann::json>(
//                                 [&server](nlohmann::json event){ std::cout << "UDP (5051): " << event.at("message") << "\n"; },
//                                 [](){printf("OnEnd?");}));
//     }

//     server.run();
// }
