#include "container_scope.hpp"

#include <unistd.h>

#include <gtest/gtest.h>

using wazuh::container_baseline::DetectContainerScope;
using wazuh::container_baseline::ScopeKind;
using wazuh::container_baseline::SharesNamespace;

TEST(SharesNamespace, SelfSharesEveryNamespaceWithItself)
{
    const auto self = ::getpid();
    EXPECT_TRUE(SharesNamespace(self, self, "net"));
    EXPECT_TRUE(SharesNamespace(self, self, "pid"));
    EXPECT_TRUE(SharesNamespace(self, self, "mnt"));
}

TEST(SharesNamespace, UnknownPidIsNotShared)
{
    // PID 0 never has a /proc entry, so the namespace id cannot be read and the
    // answer must be a conservative "no", never a false match.
    EXPECT_FALSE(SharesNamespace(::getpid(), 0, "net"));
    EXPECT_FALSE(SharesNamespace(0, ::getpid(), "net"));
}

TEST(SharesNamespace, WorksWithoutPrivilegeOverPidOne)
{
    // Regression guard: keying the host side of the comparison off PID 1 makes
    // the check unreadable (and therefore silently Unknown) for an
    // unprivileged caller. Comparing against the agent's own namespace must
    // always succeed, which is what makes collapse detection dependable.
    const auto self = ::getpid();
    EXPECT_TRUE(SharesNamespace(self, self, "net"));
}

TEST(SharesNamespace, UnknownNamespaceNameIsNotShared)
{
    const auto self = ::getpid();
    EXPECT_FALSE(SharesNamespace(self, self, "not_a_namespace"));
}

TEST(DetectContainerScope, TestProcessCollapsesToHost)
{
    // The unit test runs as an ordinary host process, so it necessarily shares
    // PID 1's namespaces — which is exactly the signature of a host-network /
    // host-pid container and must be classified as such.
    const auto scope = DetectContainerScope(::getpid());

    EXPECT_EQ(scope.net, ScopeKind::HostCollapsed);
    EXPECT_TRUE(scope.netCollapsedToHost());
}

TEST(DetectContainerScope, DeadPidIsUnknownNotCollapsed)
{
    // A PID that cannot be read must not be reported as host-collapsed, or a
    // container whose PID exited mid-scan would silently lose its network rows
    // for the wrong reason.
    const auto scope = DetectContainerScope(0);

    EXPECT_EQ(scope.net, ScopeKind::Unknown);
    EXPECT_EQ(scope.pid, ScopeKind::Unknown);
    EXPECT_FALSE(scope.netCollapsedToHost());
}

TEST(RootfsStillAddressable, TrueForALiveProcess)
{
    EXPECT_TRUE(wazuh::container_baseline::RootfsStillAddressable(::getpid()));
}

TEST(RootfsStillAddressable, FalseForADeadPid)
{
    // The signal that turns "the PID exited partway through the scan" from a
    // silent partial row set into a reported incomplete scan.
    EXPECT_FALSE(wazuh::container_baseline::RootfsStillAddressable(0));
}

TEST(SelectAddressablePid, PicksTheFirstLivePid)
{
    // 0 is never addressable, so a snapshot whose earliest entries have already
    // exited must not make the whole container unscannable.
    const auto self = ::getpid();
    EXPECT_EQ(wazuh::container_baseline::SelectAddressablePid({0, 0, self}), self);
}

TEST(SelectAddressablePid, PrefersTheEarliestCandidate)
{
    const auto self = ::getpid();
    EXPECT_EQ(wazuh::container_baseline::SelectAddressablePid({self, 0}), self);
}

TEST(SelectAddressablePid, ZeroWhenNothingIsAddressable)
{
    EXPECT_EQ(wazuh::container_baseline::SelectAddressablePid({}), 0);
    EXPECT_EQ(wazuh::container_baseline::SelectAddressablePid({0}), 0);
}
