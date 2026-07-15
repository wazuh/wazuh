#include "network_scanner.hpp"

#include <gtest/gtest.h>

using wazuh::container_baseline::DecodeHexAddress;
using wazuh::container_baseline::TcpStateToString;

TEST(DecodeHexAddress, Ipv4LoopbackOnHttpPort)
{
    // /proc/net/tcp stores IPv4 as 8 hex chars (byte-reversed 32-bit word) and
    // the port as 4 hex chars: 0100007F:0050 == 127.0.0.1:80.
    std::string ip;
    int64_t     port = 0;
    ASSERT_TRUE(DecodeHexAddress("0100007F:0050", /*is_ipv6=*/false, ip, port));
    EXPECT_EQ(ip, "127.0.0.1");
    EXPECT_EQ(port, 80);
}

TEST(DecodeHexAddress, Ipv4AnyAddressOnHighPort)
{
    std::string ip;
    int64_t     port = 0;
    ASSERT_TRUE(DecodeHexAddress("00000000:1F90", false, ip, port));
    EXPECT_EQ(ip, "0.0.0.0");
    EXPECT_EQ(port, 8080);
}

TEST(DecodeHexAddress, Ipv6LoopbackDecodes)
{
    // ::1 stored as 32 hex chars, port 443.
    std::string ip;
    int64_t     port = 0;
    ASSERT_TRUE(DecodeHexAddress("00000000000000000000000001000000:01BB", true, ip, port));
    EXPECT_EQ(port, 443);
    EXPECT_FALSE(ip.empty());
}

TEST(DecodeHexAddress, MissingColonFails)
{
    std::string ip;
    int64_t     port = 0;
    EXPECT_FALSE(DecodeHexAddress("0100007F0050", false, ip, port));
}

TEST(DecodeHexAddress, WrongLengthIpv4Fails)
{
    std::string ip;
    int64_t     port = 0;
    EXPECT_FALSE(DecodeHexAddress("AB:0050", false, ip, port));
}

TEST(TcpStateToString, KnownStates)
{
    EXPECT_EQ(TcpStateToString("01"), "established");
    EXPECT_EQ(TcpStateToString("0A"), "listen");
    EXPECT_EQ(TcpStateToString("06"), "time_wait");
}

TEST(TcpStateToString, UnknownStateFallsBack)
{
    EXPECT_EQ(TcpStateToString("FF"), "unknown");
}

TEST(ScanContainerNetwork, EmptyContainerIdReturnsEmpty)
{
    EXPECT_TRUE(wazuh::container_baseline::ScanContainerNetwork("").empty());
}
