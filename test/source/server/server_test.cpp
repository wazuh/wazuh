#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "server.hpp"

using namespace server;
using namespace std;

// TEST(Server, Initializes)
// {
//     vector<string> config = {"tcp:localhost:5054"};
//     Server server(config);
//     server.run();
//     std::this_thread::sleep_for(std::chrono::milliseconds(5000));
//     server.stop();
// }

// TEST(Server, TcpInitializes)
// {
//     vector<string> config = {"tcp:localhost:5054", "tcp:localhost:5053"};
//     Server server(config);
//     server.output().subscribe([](nlohmann::json j) { cout << j.dump(2) << endl; });
//     server.run();
//     server.stop();
// }

// TEST(Server, UdpInitializes)
// {
//     vector<string> config = {"udp:localhost:5054"};
//     Server server(config);
//     server.output().subscribe([](nlohmann::json j) { cout << j.dump(2) << endl; });
//     server.run();
//     std::this_thread::sleep_for(std::chrono::milliseconds(50000));
//     server.stop();
// }

TEST(Server, SocketInitializes)
{
    vector<string> config = {"socket:/tmp/testsocket"};
    Server server(config);
    server.output().subscribe([](nlohmann::json j) { cout << j.dump(2) << endl; });
    server.run();
    std::this_thread::sleep_for(std::chrono::milliseconds(50000));
    server.stop();
}
