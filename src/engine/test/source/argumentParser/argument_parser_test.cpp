#include "rxcpp/rx.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <string>

#include "argumentParser.hpp"

using namespace argparse;
using namespace std;

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

TEST(ArgumentParserTests, prueba)
{

    ArgumentParser program("test");

    program.add_argument("type");

    program.parse_args("./test tipo");

    ASSERT_TRUE (true);
}
