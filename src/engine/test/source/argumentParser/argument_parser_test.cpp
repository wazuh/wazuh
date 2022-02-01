#include "rxcpp/rx.hpp"
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <string>

#include "argumentParser.hpp"

using namespace std;
using namespace parser;
using namespace argparse;

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

TEST(ArgumentParserTests, PositionalArgument)
{

    ArgumentParser test("test");
    test.add_argument("type")
        .help("tipo")
        .scan<'i',int>();

    char * argv[2];
    argv[0] = "test";
    argv[1] = "123";
    int argc = 2;

    test.parse_args(argc, argv);

    ASSERT_EQ(test.get<int>("type"), 123);
}

TEST(ArgumentParserTests, OptionalArgument)
{

    ArgumentParser test("test");
    test.add_argument("--endpoint", "endpoint")
        .help("Endpoint configuration string")
        .required();

    char * argv[3];
    argv[0] = "test";
    argv[1] = "--endpoint";
    argv[2] = "tcp";
    int argc = 3;

    test.parse_args(argc, argv);

    string result = "tcp";

    ASSERT_EQ(result.compare(test.get("endpoint")),0);
}

TEST(ArgumentParserTests, OptionalArgumentMissing)
{

    ArgumentParser test("test");
    test.add_argument("--endpoint", "endpoint")
        .help("Endpoint configuration string")
        .required();

    char * argv[2];
    argv[0] = "test";
    argv[1] = "--endpoint";
    int argc = 2;

    ASSERT_THROW(test.parse_args(argc, argv),std::exception);
}

TEST(ArgumentParserTests, MultipleOptionalArgument)
{

    ArgumentParser test("test");
    test.add_argument("--endpoint", "endpoint")
        .help("Endpoint configuration string")
        .required();

    test.add_argument("--file_storage", "file_storage")
        .help("Path to storage folder")
        .required();

    char * argv[5];
    argv[0] = "test";
    argv[1] = "--endpoint";
    argv[2] = "tcp";
    argv[3] = "--file_storage";
    argv[4] = "/var/ossec";
    int argc = 5;

    test.parse_args(argc, argv);

    string endpoint_result = "tcp";
    string path_result = "/var/ossec";

    ASSERT_TRUE((endpoint_result.compare(test.get("endpoint")) == 0) && (path_result.compare(test.get("file_storage"))== 0));
}

TEST(ArgumentParserTests, ClassParser)
{

    char * argv[5];
    argv[0] = "./server";
    argv[1] = "--endpoint";
    argv[2] = "tcp";
    argv[3] = "--file_storage";
    argv[4] = "/var/ossec";
    int argc = 5;

    Parser aux(argc, argv);

    string endpoint_result = "tcp";
    string path_result = "/var/ossec";

    ASSERT_TRUE((endpoint_result.compare(aux.getEndpointConfig()) == 0) && (path_result.compare(aux.getStoragePath())== 0));
}
/*
TEST(ArgumentParserTests, ClassParserHelp)
{

    char * argv[2];
    argv[0] = "./server";
    argv[1] = "--help";
    int argc = 2;

    Parser aux(argc, argv);

    //ASSERT_THROW(Parser aux(argc, argv),std::exception);
    ASSERT_TRUE(true);
}*/

TEST(ArgumentParserTests, ClassParserFail)
{

    char * argv[4];
    argv[0] = "./server";
    argv[1] = "--endpoint";
    argv[2] = "tcp";
    argv[3] = "--file_storage";
    int argc = 4;

    ASSERT_THROW(Parser aux(argc, argv),std::exception);
}
