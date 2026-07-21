#include "protocol_scanner.hpp"

#include <gtest/gtest.h>

using wazuh::container_baseline::DecodeRouteGateway;
using wazuh::container_baseline::ParseRouteLine;
using wazuh::container_baseline::ProtocolBaselineRow;

TEST(DecodeRouteGateway, DecodesDockerBridgeGateway)
{
    EXPECT_EQ(DecodeRouteGateway("010011AC"), "172.17.0.1");
}

TEST(DecodeRouteGateway, DecodesPrivateGateway)
{
    EXPECT_EQ(DecodeRouteGateway("0100A8C0"), "192.168.0.1");
}

TEST(DecodeRouteGateway, EmptyForZeroGateway)
{
    EXPECT_TRUE(DecodeRouteGateway("00000000").empty());
}

TEST(ParseRouteLine, ParsesDefaultRoute)
{
    ProtocolBaselineRow row;
    ASSERT_TRUE(ParseRouteLine("eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0", row));
    EXPECT_EQ(row.interface_name, "eth0");
    EXPECT_EQ(row.type, "ipv4");
    EXPECT_EQ(row.gateway, "172.17.0.1");
    EXPECT_EQ(row.metric, 0);
    EXPECT_EQ(row.dhcp, "unknown");
}

TEST(ParseRouteLine, SkipsNonDefaultRoute)
{
    ProtocolBaselineRow row;
    EXPECT_FALSE(ParseRouteLine("eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0", row));
}

TEST(ParseRouteLine, RejectsShortLine)
{
    ProtocolBaselineRow row;
    EXPECT_FALSE(ParseRouteLine("eth0\t00000000\t010011AC", row));
}
