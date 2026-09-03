#include "interface_scanner.hpp"

#include <net/if.h>
#include <unistd.h>

#include <gtest/gtest.h>

using wazuh::container_baseline::ContainerScope;
using wazuh::container_baseline::FlagsToState;
using wazuh::container_baseline::FormatMac;
using wazuh::container_baseline::ScanContainerInterfaces;
using wazuh::container_baseline::ScopeKind;

TEST(FlagsToState, UpFlagMeansUp)
{
    EXPECT_EQ(FlagsToState(IFF_UP), "up");
    EXPECT_EQ(FlagsToState(IFF_UP | IFF_RUNNING | IFF_LOOPBACK), "up");
}

TEST(FlagsToState, NoUpFlagMeansDown)
{
    EXPECT_EQ(FlagsToState(0), "down");
    EXPECT_EQ(FlagsToState(IFF_BROADCAST), "down");
}

TEST(FormatMac, FormatsSixBytes)
{
    const unsigned char mac[] = {0x02, 0x42, 0xac, 0x11, 0x00, 0x0f};
    EXPECT_EQ(FormatMac(mac, sizeof(mac)), "02:42:ac:11:00:0f");
}

TEST(FormatMac, EmptyForZeroLength)
{
    EXPECT_TRUE(FormatMac(nullptr, 0).empty());
}

TEST(ScanContainerInterfaces, SelfScanFindsLoopback)
{
    // Scope is supplied by the caller, so the test can ask for the
    // "real container namespace" treatment on its own PID and exercise the
    // same-netns fast path (no setns, no CAP_SYS_ADMIN needed).
    ContainerScope scope;
    scope.net = ScopeKind::Container;
    scope.pid = ScopeKind::Container;

    const auto scan = ScanContainerInterfaces(getpid(), scope);

    EXPECT_FALSE(scan.host_collapsed);
    EXPECT_FALSE(scan.setns_failed);

    bool lo_iface = false;
    for (const auto& iface : scan.interfaces)
    {
        if (iface.name == "lo")
        {
            lo_iface = true;
            EXPECT_EQ(iface.type, "loopback");
            EXPECT_EQ(iface.state, "up");
            EXPECT_GT(iface.mtu, 0);
        }
    }
    EXPECT_TRUE(lo_iface);

    bool lo_addr = false;
    for (const auto& addr : scan.addresses)
    {
        if (addr.interface_name == "lo" && addr.address == "127.0.0.1")
        {
            lo_addr = true;
            EXPECT_EQ(addr.protocol, "ipv4");
            EXPECT_EQ(addr.netmask, "255.0.0.0");
        }
    }
    EXPECT_TRUE(lo_addr);
}

TEST(ScanContainerInterfaces, HostNetworkCollapseReportsNothing)
{
    // A container sharing the host's netns must not have the node's interfaces
    // attributed to it — every host-network container would otherwise report
    // the full host inventory.
    ContainerScope scope;
    scope.net = ScopeKind::HostCollapsed;

    const auto scan = ScanContainerInterfaces(getpid(), scope);

    EXPECT_TRUE(scan.host_collapsed);
    EXPECT_TRUE(scan.interfaces.empty());
    EXPECT_TRUE(scan.addresses.empty());
}
