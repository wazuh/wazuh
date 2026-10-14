/*
 * Wazuh remoted module - Installation paths unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 13, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Pins remoted::paths: every installation path the module opens is relative to the working
 * directory (remoted's cwd is the installation directory), each one is defined once, and the
 * consumers' defaults actually resolve against the cwd -- proven for the VD socket with a fake
 * server listening on the relative path inside a scratch directory.
 */

#include "common/installPaths.hpp"
#include "common/vdClient.hpp"
#include "control/controlConfig.hpp"
#include "endpoints/downloadEndpoint.hpp"
#include "fakeVdServer.hpp"
#include "scanvd/scanVdHandler.hpp"
#include "scanvd/scanVdMetrics.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace paths = remoted::paths;
using remoted::common::VdClient;
using remoted::endpoints::scanvd::ScanVdOutcome;
using remoted::endpoints::scanvd::ScanVdResponse;
using remoted::scanvd::makeScanVdMetrics;
using remoted::scanvd::ScanVdHandlerImpl;
using remoted::scanvd::ScanVdMetrics;
using remoted::test::FakeVdServer;

namespace
{
    /// Every path under the installation directory; kSharedDir lives in the configuration directory instead.
    std::vector<std::pair<const char*, const char*>> installationPaths()
    {
        return {{"kWdbSocket", paths::kWdbSocket},
                {"kTaskSocket", paths::kTaskSocket},
                {"kVdSocket", paths::kVdSocket},
                {"kMultigroupsDir", paths::kMultigroupsDir},
                {"kWpkDir", paths::kWpkDir}};
    }
} // namespace

/**
 * Every test runs inside a fresh scratch directory: the cwd is saved in SetUp() and restored in
 * TearDown(), so a failed ASSERT never leaves a later test (some resolve relative sockets against
 * the cwd, e.g. adminServer_test.cpp) running from here.
 */
class InstallPathsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_originalCwd = std::filesystem::current_path();

        std::string pattern = (std::filesystem::temp_directory_path() / "install_paths_test_XXXXXX").string();
        if (::mkdtemp(pattern.data()) == nullptr)
        {
            throw std::runtime_error("mkdtemp failed for the installation paths test's scratch directory");
        }
        m_scratchDir = pattern;
        std::filesystem::current_path(m_scratchDir);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::current_path(m_originalCwd, ec);
        std::filesystem::remove_all(m_scratchDir, ec);
    }

    /// The installed manager's queue/sockets/ layout under the scratch cwd: binding a UDS creates no
    /// parent directories.
    static void createSocketsDir()
    {
        std::filesystem::create_directories(std::filesystem::path {paths::kVdSocket}.parent_path());
    }

    std::filesystem::path m_originalCwd;
    std::filesystem::path m_scratchDir;
};

TEST_F(InstallPathsTest, InstallationPathsAreRelative)
{
    for (const auto& [name, value] : installationPaths())
    {
        ASSERT_NE(value, nullptr) << name;
        EXPECT_NE(std::string {value}, "") << name;
        EXPECT_NE(value[0], '/') << name << " = \"" << value
                                 << "\": installation paths resolve against remoted's cwd, never an absolute root";
    }
}

TEST_F(InstallPathsTest, SharedDirIsInTheConfigurationDirectory)
{
    EXPECT_TRUE(Utils::isInManagerConfDir(paths::kSharedDir)) << paths::kSharedDir;
}

TEST_F(InstallPathsTest, MatchInstallationLayout)
{
    // Same values as the C side: WDB_LOCAL_SOCK, SHAREDCFG_DIR, MULTIGROUPS_DIR (defs.h) and
    // LEGACY_TASK_WPK_DEFAULT_PATH without its trailing slash.
    EXPECT_STREQ(paths::kWdbSocket, "queue/sockets/wdb.sock");
    EXPECT_STREQ(paths::kTaskSocket, "queue/sockets/task-http.sock");
    EXPECT_STREQ(paths::kVdSocket, "queue/sockets/vd-http.sock");
    EXPECT_STREQ(paths::kSharedDir, "/etc/wazuh-manager/shared");
    EXPECT_STREQ(paths::kMultigroupsDir, "var/multigroups");
    EXPECT_STREQ(paths::kWpkDir, "var/upgrade");
}

TEST_F(InstallPathsTest, ControlConfigDefaultsUseThem)
{
    const remoted::control::Config config {};

    EXPECT_EQ(config.wdbSocketPath, paths::kWdbSocket);
    EXPECT_EQ(config.taskSocketPath, paths::kTaskSocket);
    EXPECT_EQ(config.sharedGroupsRoot, paths::kSharedDir);
    EXPECT_EQ(config.multiGroupsRoot, paths::kMultigroupsDir);
}

TEST_F(InstallPathsTest, DownloadResourcePathsUseThem)
{
    const remoted::endpoints::download::ResourcePaths resourcePaths {};

    EXPECT_EQ(resourcePaths.sharedDir, paths::kSharedDir);
    EXPECT_EQ(resourcePaths.multigroupsDir, paths::kMultigroupsDir);
    EXPECT_EQ(resourcePaths.wpkDir, paths::kWpkDir);
}

TEST_F(InstallPathsTest, VdClientDefaultReachesRelativeSocket)
{
    createSocketsDir();
    FakeVdServer server {paths::kVdSocket};
    server.setOffset(4242);

    VdClient client {};

    EXPECT_EQ(client.getOffset(), 4242u);
    EXPECT_EQ(server.offsetRequestCount(), 1u) << "the default socket must be the relative kVdSocket under the cwd";
}

TEST_F(InstallPathsTest, ScanVdHandlerDefaultReachesRelativeSocket)
{
    createSocketsDir();
    FakeVdServer server {paths::kVdSocket};
    server.setOffset(100);
    server.setScanHandler([](const httplib::Request&, httplib::Response& res)
                          { res.set_content("{}", "application/json"); });

    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics = makeScanVdMetrics(metricsManager);
    ScanVdHandlerImpl handler {std::make_shared<VdClient>(), metrics};

    ScanVdResponse response {};
    handler.handleVdScan(7, 100, [&response](const ScanVdResponse& r) { response = r; });

    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(server.scanRequestCount(), 1u) << "the default scan socket must be the relative kVdSocket under the cwd";
}
