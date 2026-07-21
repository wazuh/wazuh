#include "service_scanner.hpp"

#include <gtest/gtest.h>

using wazuh::container_baseline::ParseUnitFile;

TEST(ParseUnitFile, ExtractsDescriptionAndExecutable)
{
    const std::string unit =
        "[Unit]\n"
        "Description=The nginx HTTP server\n"
        "[Service]\n"
        "ExecStart=/usr/sbin/nginx -g 'daemon off;'\n";
    std::string description, executable;
    ParseUnitFile(unit, description, executable);
    EXPECT_EQ(description, "The nginx HTTP server");
    EXPECT_EQ(executable, "/usr/sbin/nginx");
}

TEST(ParseUnitFile, StripsExecPrefixes)
{
    std::string description, executable;
    ParseUnitFile("ExecStart=-/bin/false\n", description, executable);
    EXPECT_EQ(executable, "/bin/false");
}

TEST(ParseUnitFile, FirstExecStartWins)
{
    std::string description, executable;
    ParseUnitFile("ExecStart=/first\nExecStart=/second\n", description, executable);
    EXPECT_EQ(executable, "/first");
}

TEST(ParseUnitFile, HandlesMissingFields)
{
    std::string description, executable;
    ParseUnitFile("[Unit]\nWants=network.target\n", description, executable);
    EXPECT_TRUE(description.empty());
    EXPECT_TRUE(executable.empty());
}
