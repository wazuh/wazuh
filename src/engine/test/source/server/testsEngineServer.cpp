#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <string>
#include <uvw/pipe.hpp>
#include <uvw/tcp.hpp>
#include <uvw/udp.hpp>
#include <vector>

#include "server.hpp"

using namespace server;
using namespace std;
using namespace rxcpp;

#define GTEST_COUT std::cerr << "[          ] [ INFO ]"

TEST(ServerTest, InitializesTcp)
{
    vector<string> config = {"tcp:localhost:5054"};
    ASSERT_NO_THROW(Server server(config));
}

TEST(ServerTest, InitializesUdp)
{
    vector<string> config = {"udp:localhost:5054"};
    ASSERT_NO_THROW(Server server(config));
}

TEST(ServerTest, InitializesSocket)
{
    vector<string> config = {"socket:/tmp/testsocket"};
    ASSERT_NO_THROW(Server server(config));
}

TEST(ServerTest, InitializesErrorEndpointType)
{
    vector<string> config = {"error:localhost:5054"};
    ASSERT_THROW(Server server(config), invalid_argument);
}

TEST(ServerTest, RunStopTcp)
{
    vector<string> config = {"tcp:localhost:5054"};
    Server server(config);
    ASSERT_NO_THROW(server.run());
    // Give time to initialize before closing
    this_thread::sleep_for(std::chrono::milliseconds(5));
    ASSERT_NO_THROW(server.close());
}

TEST(ServerTest, RunStopUdp)
{
    vector<string> config = {"udp:localhost:5054"};
    Server server(config);
    ASSERT_NO_THROW(server.run());
    // Give time to initialize before closing
    this_thread::sleep_for(std::chrono::milliseconds(5));
    ASSERT_NO_THROW(server.close());
}

TEST(ServerTest, RunStopSocket)
{
    vector<string> config = {"socket:/tmp/testsocket"};
    Server server(config);
    ASSERT_NO_THROW(server.run());
    // Give time to initialize before closing
    this_thread::sleep_for(std::chrono::milliseconds(5));
    ASSERT_NO_THROW(server.close());
}

TEST(ServerTest, EndToEndTcp)
{
    // Start server
    vector<string> config = {"tcp:localhost:5054"};
    Server server(config);

    // Subscribe to server output
    vector<nlohmann::json> got;
    server.output().subscribe(
        [&](nlohmann::json j)
        {
            GTEST_COUT << j.dump() << endl;
            got.push_back(j);
        });
    server.run();

    // Make and connect client
    string address = "127.0.0.1";
    unsigned int port = 5054;
    auto loop = uvw::Loop::getDefault();
    auto client = loop->resource<uvw::TCPHandle>();

    client->on<uvw::ErrorEvent>([](const auto &, auto &) { FAIL(); });

    client->once<uvw::WriteEvent>([&](const uvw::WriteEvent &, uvw::TCPHandle & handle)
                                  { GTEST_COUT << "on client writeevent" << endl; });

    string message = "1:location:message";
    client->once<uvw::ConnectEvent>([&](const uvw::ConnectEvent &, uvw::TCPHandle & handle)
                                    { handle.write(message.data(), message.size()); });
    client->connect(uvw::Addr{address, port});
    thread t(&uvw::Loop::run, loop.get());

    this_thread::sleep_for(std::chrono::milliseconds(500));
    loop->stop();                                                 /// Stops the loop
    loop->walk([](uvw::BaseHandle & handle) { handle.close(); }); /// Triggers every handle's close callback
    loop->run(); /// Runs the loop again, so every handle is able to receive its close callback
    loop->clear();
    loop->close();
    t.join();
    ASSERT_NO_THROW(server.close());
}
