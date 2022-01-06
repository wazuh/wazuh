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


TEST(EngineServer, tcp)
{
    EngineServer server;

    server.listenSocket("/tmp/test.sock");

    server.listenTCP(5050);

    server.listenUDP(5051);

    auto sockObs = server.getEndpointObservable(EndpointType::SOCKET, "/tmp/test.sock");
    if(sockObs)
    {
        sockObs.value().subscribe(rxcpp::make_subscriber<std::string>(
                                [&server](std::string event){ std::cout << "SOCKET: " << event << "\n"; },
                                [](){printf("OnEnd?");}));
    }

    auto tcpObs = server.getEndpointObservable(EndpointType::TCP, 5050);
    if(tcpObs)
    {
        tcpObs.value().subscribe(rxcpp::make_subscriber<std::string>(
                                [&server](std::string event){ std::cout << "TCP (5050): " << event << "\n"; },
                                [](){printf("OnEnd?");}));
    }

    auto udpObs = server.getEndpointObservable(EndpointType::UDP, 5051);
    if(udpObs)
    {
        udpObs.value().subscribe(rxcpp::make_subscriber<std::string>(
                                [&server](std::string event){ std::cout << "UDP (5051): " << event << "\n"; },
                                [](){printf("OnEnd?");}));
    }

    server.run();
}
