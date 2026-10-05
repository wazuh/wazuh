/*
 * Wazuh container_instances — the /proc walk that produces container keys.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Driven against a synthetic /proc rather than this host's, because every
 * machine this builds on runs a unified hierarchy — so the legacy and hybrid
 * paths would otherwise be first exercised on a customer's RHEL 8 box.
 *
 * Two things here are not covered by the parser tests, and both are the kind
 * of mistake that produces a WRONG key rather than no key:
 *
 *   - the stat path. A v1 cgroup path is relative to its controller's own
 *     mount, so it is <root>/<controller><path>, not <root><path>. Getting
 *     that wrong stats a directory that does not exist, or worse, one that
 *     does and belongs to something else.
 *   - which process supplies the mount-namespace inode. Any process in the
 *     cgroup will do until one of them calls unshare(CLONE_NEWNS), and then
 *     whichever the walk reached first decides the container's identity.
 */

#include "cgroup/proc_cgroup_resolver.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

    /// A synthetic /proc and cgroupfs. Hand-rolled rather than gmock-ed because
    /// what these tests assert is the SHAPE of the lookups — which paths get
    /// stat'd — and recording them is clearer than expectation ceremony.
    class FakeProc
        : public IFileSystemWrapper
        , public IFileIOUtils
        , public IInodeReader
    {
    public:
        std::vector<std::string> pids;
        std::map<std::string, std::vector<std::string>> cgroupFileByPid;
        std::map<std::string, std::uint64_t> inodeByPath;
        mutable std::vector<std::string> statted;

        // --- IFileSystemWrapper: only list_directory is reached -------------
        std::vector<std::filesystem::path> list_directory(const std::filesystem::path&) const override
        {
            std::vector<std::filesystem::path> out;
            for (const auto& pid : pids)
            {
                out.emplace_back(std::filesystem::path {"/proc"} / pid);
            }
            return out;
        }

        // --- IFileIOUtils ---------------------------------------------------
        void readLineByLine(const std::filesystem::path& filePath,
                            const std::function<bool(const std::string&)>& callback) const override
        {
            const auto pid = filePath.parent_path().filename().string();
            const auto it = cgroupFileByPid.find(pid);
            if (it == cgroupFileByPid.end())
            {
                throw std::runtime_error("no such process"); // Exited mid-scan.
            }
            for (const auto& line : it->second)
            {
                if (!callback(line))
                {
                    break;
                }
            }
        }

        // --- IInodeReader ---------------------------------------------------
        std::optional<std::uint64_t> inodeOf(const std::string& path) const override
        {
            statted.push_back(path);
            const auto it = inodeByPath.find(path);
            return (it == inodeByPath.end()) ? std::nullopt : std::optional<std::uint64_t> {it->second};
        }

        // --- the rest of IFileSystemWrapper, never called -------------------
        bool exists(const std::filesystem::path&) const override
        {
            return false;
        }
        bool is_directory(const std::filesystem::path&) const override
        {
            return false;
        }
        bool is_regular_file(const std::filesystem::path&) const override
        {
            return false;
        }
        bool is_socket(const std::filesystem::path&) const override
        {
            return false;
        }
        bool is_symlink(const std::filesystem::path&) const override
        {
            return false;
        }
        bool is_absolute(const std::filesystem::path&) const override
        {
            return false;
        }
        std::filesystem::path canonical(const std::filesystem::path& path) const override
        {
            return path;
        }
        std::uintmax_t remove_all(const std::filesystem::path&) const override
        {
            return 0;
        }
        std::filesystem::path temp_directory_path() const override
        {
            return {};
        }
        bool create_directories(const std::filesystem::path&) const override
        {
            return false;
        }
        void rename(const std::filesystem::path&, const std::filesystem::path&) const override {}
        bool remove(const std::filesystem::path&) const override
        {
            return false;
        }
        int open(const char*, int, int) const override
        {
            return -1;
        }
        int flock(int, int) const override
        {
            return -1;
        }
        int close(int) const override
        {
            return -1;
        }

        std::string getFileContent(const std::string&) const override
        {
            return {};
        }
        std::vector<char> getBinaryContent(const std::string&) const override
        {
            return {};
        }
    };

    constexpr auto kContainerId = "3f2abc9900112233445566778899aabbccddeeff00112233445566778899aabb";

    std::string ContainerLeaf()
    {
        return std::string {"/docker/"} + kContainerId;
    }

    void Log(LogLevel, const std::string&) {}

} // namespace

TEST(ProcCgroupResolverTest, AV1PathIsStattedUnderItsControllerMountNotTheCgroupRoot)
{
    FakeProc proc;
    proc.pids = {"100"};
    proc.cgroupFileByPid["100"] = {"10:memory:" + ContainerLeaf(), "1:name=systemd:" + ContainerLeaf()};
    proc.inodeByPath["/sys/fs/cgroup/memory" + ContainerLeaf()] = 4242;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_LEGACY};
    const auto scan = resolver.scan();

    ASSERT_EQ(1U, scan.containers.size()) << "nothing resolved: the stat path was built without the controller mount";
    EXPECT_EQ(kContainerId, scan.containers.front().containerId);
    EXPECT_EQ(4242U, scan.containers.front().inode);
    EXPECT_EQ("memory", scan.containers.front().keyController)
        << "which controller supplied the inode has to travel with it; two inodes from different "
           "controllers are numbers that cannot be compared";
}

TEST(ProcCgroupResolverTest, AUnifiedPathIsStattedAtTheCgroupRoot)
{
    FakeProc proc;
    proc.pids = {"100"};
    proc.cgroupFileByPid["100"] = {"0::" + ContainerLeaf()};
    proc.inodeByPath["/sys/fs/cgroup" + ContainerLeaf()] = 777;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_UNIFIED};
    const auto scan = resolver.scan();

    ASSERT_EQ(1U, scan.containers.size());
    EXPECT_EQ(777U, scan.containers.front().inode);
    EXPECT_TRUE(scan.containers.front().keyController.empty()) << "no controller is involved on a unified host";
}

TEST(ProcCgroupResolverTest, AHybridHostReadsTheUnifiedHierarchyFromItsOwnMount)
{
    FakeProc proc;
    proc.pids = {"100"};
    proc.cgroupFileByPid["100"] = {"10:memory:" + ContainerLeaf(), "0::" + ContainerLeaf()};
    // Only the /unified path exists, which is the whole point: the host has v1
    // controllers at the root and the v2 hierarchy mounted beside them.
    proc.inodeByPath["/sys/fs/cgroup/unified" + ContainerLeaf()] = 999;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_HYBRID};
    const auto scan = resolver.scan();

    ASSERT_EQ(1U, scan.containers.size()) << "a hybrid host resolved nothing, exactly as a pure v1 one would";
    EXPECT_EQ(999U, scan.containers.front().inode);
}

TEST(ProcCgroupResolverTest, TheMountNamespaceInodeIsReadOnEveryHostNotJustLegacy)
{
    // It is the correlation key only on v1, but reading it everywhere keeps the
    // two paths structurally identical and lets a v2 host cross-check.
    FakeProc proc;
    proc.pids = {"100"};
    proc.cgroupFileByPid["100"] = {"0::" + ContainerLeaf()};
    proc.inodeByPath["/sys/fs/cgroup" + ContainerLeaf()] = 777;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_UNIFIED};
    const auto scan = resolver.scan();

    ASSERT_EQ(1U, scan.containers.size());
    EXPECT_EQ(4026532281U, scan.containers.front().mntNsInode);
}

TEST(ProcCgroupResolverTest, TheLowestPidInTheCgroupSuppliesTheMountNamespace)
{
    /* The unshare(CLONE_NEWNS) case, which is the reason this rule exists.
     *
     * Three processes in one container; the one with the highest pid has made
     * its own mount namespace. Without a deterministic rule the answer depends
     * on readdir order, so the same host would key the same container
     * differently from one scan to the next — and on v1 that key IS the
     * container's identity. The lowest host pid is the container's init, which
     * is the namespace the others were born into. */
    FakeProc proc;
    proc.pids = {"310", "100", "250"}; // deliberately not in order
    for (const auto* pid : {"100", "250", "310"})
    {
        proc.cgroupFileByPid[pid] = {"10:memory:" + ContainerLeaf()};
    }
    proc.inodeByPath["/sys/fs/cgroup/memory" + ContainerLeaf()] = 4242;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281; // init
    proc.inodeByPath["/proc/250/ns/mnt"] = 4026532281;
    proc.inodeByPath["/proc/310/ns/mnt"] = 4026533999; // unshare -m

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_LEGACY};
    const auto scan = resolver.scan();

    ASSERT_EQ(1U, scan.containers.size());
    EXPECT_EQ(4026532281U, scan.containers.front().mntNsInode)
        << "the container was keyed on a namespace one of its processes created, not on its own";
}

TEST(ProcCgroupResolverTest, AProcessThatExitsMidScanIsSkippedNotFatal)
{
    FakeProc proc;
    proc.pids = {"100", "200"}; // 200 has no cgroup file: it exited.
    proc.cgroupFileByPid["100"] = {"10:memory:" + ContainerLeaf()};
    proc.inodeByPath["/sys/fs/cgroup/memory" + ContainerLeaf()] = 4242;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_LEGACY};
    const auto scan = resolver.scan();

    EXPECT_EQ(1U, scan.containers.size());
}

TEST(ProcCgroupResolverTest, AHostProcessContributesToAllInodesButIsNotAContainer)
{
    // allInodes drives verdict liveness eviction, so a host cgroup must still
    // be observed even though it resolves to no container.
    FakeProc proc;
    proc.pids = {"100"};
    proc.cgroupFileByPid["100"] = {"10:memory:/system.slice/sshd.service"};
    proc.inodeByPath["/sys/fs/cgroup/memory/system.slice/sshd.service"] = 55;
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026531840;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_LEGACY};
    const auto scan = resolver.scan();

    EXPECT_TRUE(scan.containers.empty());
    EXPECT_EQ(1U, scan.allInodes.count(55));
}

TEST(ProcCgroupResolverTest, ALegacyHostWithNoUsableControllerResolvesNothing)
{
    FakeProc proc;
    proc.pids = {"100"};
    proc.cgroupFileByPid["100"] = {"11:devices:" + ContainerLeaf()};
    proc.inodeByPath["/proc/100/ns/mnt"] = 4026532281;

    const ProcCgroupResolver resolver {proc, proc, proc, Log, "/proc", "/sys/fs/cgroup", WZ_CGROUP_MODE_LEGACY};
    const auto scan = resolver.scan();

    EXPECT_TRUE(scan.containers.empty()) << "unlisted rather than keyed on an arbitrary hierarchy";
    EXPECT_TRUE(scan.allInodes.empty());
}
