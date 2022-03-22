#include <iostream>
#include <sstream>
#include <string>

#include "cliParser.hpp"

#include <gtest/gtest.h>

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

TEST(ArgumentParserTests, PositionalArgument)
{

    argparse::ArgumentParser test("test");
    test.add_argument("type")
        .help("tipo")
        .scan<'i',int>();

    const char *argv[2] = {"test", "123"};
    int argc = 2;

    test.parse_args(argc, argv);

    ASSERT_EQ(test.get<int>("type"), 123);
}

TEST(ArgumentParserTests, OptionalArgument)
{

    argparse::ArgumentParser test("test");
    test.add_argument("--endpoint", "endpoint")
        .help("Endpoint configuration string")
        .required();

    const char *argv[3] = {"test", "--endpoint", "tcp"};
    int argc = 3;

    test.parse_args(argc, argv);

    std::string result = "tcp";

    ASSERT_EQ(result.compare(test.get("endpoint")),0);
}

TEST(ArgumentParserTests, OptionalArgumentMissing)
{

    argparse::ArgumentParser test("test");
    test.add_argument("--endpoint", "endpoint")
        .help("Endpoint configuration string")
        .required();

    const char *argv[2] = {"test", "--endpoint"};
    int argc = 2;

    ASSERT_THROW(test.parse_args(argc, argv),std::exception);
}

TEST(ArgumentParserTests, MultipleOptionalArgument)
{

    argparse::ArgumentParser test("test");
    test.add_argument("--endpoint", "endpoint")
        .help("Endpoint configuration string")
        .required();

    test.add_argument("--file_storage", "file_storage")
        .help("Path to storage folder")
        .required();

    const char *argv[5] = {
        "test", "--endpoint", "tcp", "--file_storage", "/var/ossec"};
    int argc = 5;

    test.parse_args(argc, argv);

    std::string endpoint_result = "tcp";
    std::string path_result = "/var/ossec";

    ASSERT_TRUE((endpoint_result.compare(test.get("endpoint")) == 0) && (path_result.compare(test.get("file_storage"))== 0));
}

TEST(ArgumentParserTests, ClassParser)
{

    char *argv[5] = {
        "./server", "--endpoint", "tcp", "--file_storage", "/var/ossec"};
    int argc = 5;

    cliparser::CliParser aux(argc, argv);

    std::string endpoint_result = "tcp";
    std::string path_result = "/var/ossec";

    ASSERT_TRUE((endpoint_result.compare(aux.getEndpointConfig()) == 0) &&
                (path_result.compare(aux.getStoragePath()) == 0));
}

TEST(ArgumentParserTests, ClassParserReverse)
{

    char *argv[5] = {
        "./server", "--file_storage", "/var/ossec", "--endpoint", "tcp"};
    int argc = 5;

    cliparser::CliParser aux(argc, argv);

    std::string endpoint_result = "tcp";
    std::string path_result = "/var/ossec";

    ASSERT_TRUE((endpoint_result.compare(aux.getEndpointConfig()) == 0) && (path_result.compare(aux.getStoragePath())== 0));
}
/*
TEST(ArgumentParserTests, ClassParserHelp)
{

    char * argv[2];
    argv[0] = "./server";
    argv[1] = "--help";
    int argc = 2;

    CliParser aux(argc, argv);

    //ASSERT_THROW(Parser aux(argc, argv),std::exception);
    ASSERT_TRUE(true);
}*/

TEST(ArgumentParserTests, ClassParserFail)
{

    char *argv[4] = {"./server", "--endpoint", "tcp", "--file_storage"};
    int argc = 4;

    ASSERT_THROW(cliparser::CliParser aux(argc, argv),std::exception);
}
