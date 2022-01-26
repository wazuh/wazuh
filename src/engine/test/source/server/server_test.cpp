#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "server.hpp"

using namespace server;
using namespace std;

TEST(Server, Initializes)
{
    vector<string> config = {"config"};
    Server<int> server(config);
}
