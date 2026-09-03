/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testDoubles.hpp"
#include "upgradeDoubles.hpp"

#include "upgrade/upgradeOrchestrator.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

using namespace task_manager;
using namespace task_manager::upgrade;
using task_manager::test::FakeHostOps;
using task_manager::test::FakeWpkRepository;
using task_manager::test::TempDir;

namespace
{
    constexpr const char* CONTENT {"WPK-CONTENT-A"};
    constexpr const char* SHA1 {"bdac63d27983c405531b56e2cd0eafa54b2f1d42"};
    constexpr Timestamp REQUEST_TIME {1756800000};

    /// @brief A repository whose `versions` file lists v5.0.0 at the digest above.
    constexpr const char* VERSIONS_BODY {"v4.14.0 aaaa1111\nv5.0.0 bdac63d27983c405531b56e2cd0eafa54b2f1d42\n"};

    nlohmann::json ubuntuRow(const char* version = "v4.14.0")
    {
        return nlohmann::json {{"os_platform", "ubuntu"},
                               {"os_major", "22"},
                               {"os_minor", "04"},
                               {"os_arch", "x86_64"},
                               {"version", version}};
    }

    nlohmann::json centosRow(const char* version = "v4.14.0")
    {
        return nlohmann::json {
            {"os_platform", "centos"}, {"os_major", "9"}, {"os_arch", "x86_64"}, {"version", version}};
    }

    nlohmann::json windowsRow(const char* version = "v4.14.0")
    {
        return nlohmann::json {{"os_platform", "windows"}, {"os_arch", "x86_64"}, {"version", version}};
    }

    class OrchestratorTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_store = task_manager::test::makeMemoryStore();

            WpkCache::Options wpkOptions;
            wpkOptions.upgradeDir = m_dir.path();
            wpkOptions.downloadAttempts = 1;
            wpkOptions.retryBackoff = std::chrono::milliseconds {1};
            m_wpkCache = std::make_unique<WpkCache>(m_repository, wpkOptions);

            m_versionsCache = std::make_unique<VersionsCache>(m_repository, std::chrono::seconds {60});

            UpgradeOrchestrator::Options options;
            options.managerVersion = "v5.0.0";
            options.upgradeDir = m_dir.path();
            m_orchestrator = std::make_unique<UpgradeOrchestrator>(
                m_hostOps, *m_store, m_pendingCache, *m_wpkCache, *m_versionsCache, options);
        }

        /// @brief Script the repository for a platform's directory, and the WPK it serves.
        void scriptRepo(const std::string& path, const std::string& file)
        {
            const std::string base {"https://packages.wazuh.com/5.x/wpk/" + path};
            m_repository.scriptVersions(base + "versions", {true, VERSIONS_BODY, 200, 0});
            m_repository.scriptDownload(base + file, {true, CONTENT, 200, 0, {}, false});
        }

        UpgradeRequest requestFor(std::vector<int> agentIds)
        {
            UpgradeRequest request;
            request.agentIds = std::move(agentIds);
            request.requestTime = REQUEST_TIME;
            return request;
        }

        RemotedSettings permissive() const
        {
            return {true, true, RemotedSettings::VERIFY_NONE};
        }

        TempDir m_dir;
        FakeHostOps m_hostOps;
        FakeWpkRepository m_repository;
        cache::PendingCache m_pendingCache;
        StopToken m_stop;
        std::unique_ptr<storage::SqliteTaskStore> m_store;
        std::unique_ptr<WpkCache> m_wpkCache;
        std::unique_ptr<VersionsCache> m_versionsCache;
        std::unique_ptr<UpgradeOrchestrator> m_orchestrator;
    };
} // namespace

// ---- the batch win -------------------------------------------------------------------------------

TEST_F(OrchestratorTest, AHomogeneousFleetCostsOneFetchOneDownloadAndOneTransaction)
{
    // THE TEST THIS WHOLE SUBSYSTEM EXISTS FOR. The retired implementation did all three of these
    // things ONCE PER AGENT: 500 `versions` fetches over fresh TLS connections, up to 500 downloads
    // and digests of the same 50-100 MB file under one global mutex, and 500 separately committed
    // transactions reached through 500 short-lived curl handles.
    constexpr int AGENTS {200};

    std::vector<int> agentIds;
    for (int index = 1; index <= AGENTS; ++index)
    {
        agentIds.push_back(index);
        m_hostOps.agentRows[index] = ubuntuRow();
    }
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    const auto outcomes {m_orchestrator->process(requestFor(agentIds), permissive(), m_stop)};

    ASSERT_EQ(outcomes.size(), static_cast<std::size_t>(AGENTS));
    for (const auto& outcome : outcomes)
    {
        EXPECT_EQ(outcome.error, UpgradeError::Success);
    }

    EXPECT_EQ(m_repository.totalVersionsCalls(), 1U);
    EXPECT_EQ(m_repository.totalDownloadCalls(), 1U);
    // Every agent still got its own row, in one transaction.
    EXPECT_EQ(m_store->countManagerTasks("remote_upgrade", TaskStatus::Pending), 0); // Not a manager task.
    for (int index = 1; index <= AGENTS; ++index)
    {
        EXPECT_EQ(m_store->takePendingAgentTasks(index < 10 ? "00" + std::to_string(index)
                                                           : (index < 100 ? "0" + std::to_string(index)
                                                                          : std::to_string(index)),
                                                 10)
                      .size(),
                  1U);
    }
}

TEST_F(OrchestratorTest, AMixedFleetCostsOneOfEachPerDistinctPackage)
{
    // Three platforms, so three repository paths -- not three hundred.
    for (int index = 1; index <= 100; ++index)
    {
        m_hostOps.agentRows[index] = ubuntuRow();
    }
    for (int index = 101; index <= 200; ++index)
    {
        m_hostOps.agentRows[index] = centosRow();
    }
    for (int index = 201; index <= 300; ++index)
    {
        m_hostOps.agentRows[index] = windowsRow();
    }

    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");
    scriptRepo("linux/rpm/x86_64/", "wazuh_agent_v5.0.0_linux_x86_64.rpm.wpk");
    scriptRepo("windows/", "wazuh_agent_v5.0.0_windows.wpk");

    std::vector<int> agentIds;
    for (int index = 1; index <= 300; ++index)
    {
        agentIds.push_back(index);
    }

    const auto outcomes {m_orchestrator->process(requestFor(agentIds), permissive(), m_stop)};

    ASSERT_EQ(outcomes.size(), 300U);
    for (const auto& outcome : outcomes)
    {
        EXPECT_EQ(outcome.error, UpgradeError::Success);
    }

    EXPECT_EQ(m_repository.totalVersionsCalls(), 3U);
    EXPECT_EQ(m_repository.totalDownloadCalls(), 3U);
}

// ---- the task rows -------------------------------------------------------------------------------

TEST_F(OrchestratorTest, WritesTheAgentTaskShapeTheDeliveryPathsExpect)
{
    m_hostOps.agentRows[5] = ubuntuRow();
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    ASSERT_EQ(m_orchestrator->process(requestFor({5}), permissive(), m_stop).front().error,
              UpgradeError::Success);

    // Zero-padded to three, which is how both remoted pollers look their tasks up.
    const auto tasks {m_store->takePendingAgentTasks("005", 10)};
    ASSERT_EQ(tasks.size(), 1U);
    EXPECT_EQ(tasks[0].taskType, "remote_upgrade");
    EXPECT_EQ(tasks[0].createTime, REQUEST_TIME);

    const auto payload = nlohmann::json::parse(tasks[0].payload);
    // A BARE file name. Both delivery paths join it to var/upgrade/, so a path here would not resolve.
    EXPECT_EQ(payload.at("wpk_file"), "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");
    EXPECT_EQ(payload.at("wpk_sha1"), SHA1);
    EXPECT_EQ(payload.at("installer"), "upgrade.sh");
}

TEST_F(OrchestratorTest, EvictsTheAgentFromTheNegativeCacheSoTheTaskIsVisible)
{
    // REGRESSION. The pending-tasks route answers from a cache of agents known to have NOTHING
    // pending, and skips the database entirely for them. Writing a row without evicting that entry
    // does not delay the task -- it hides it. There is no TTL on the cache and no other eviction
    // path, so the upgrade would stay invisible until the module restarted and then expire at
    // task_ttl, having never been delivered, with nothing anywhere reporting a failure.
    m_hostOps.agentRows[5] = ubuntuRow();
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    // The agent polled and found nothing, exactly as an idle agent does continuously.
    m_pendingCache.markEmpty("005");
    ASSERT_TRUE(m_pendingCache.knownEmpty("005"));

    ASSERT_EQ(m_orchestrator->process(requestFor({5}), permissive(), m_stop).front().error,
              UpgradeError::Success);

    EXPECT_FALSE(m_pendingCache.knownEmpty("005"));
}

TEST_F(OrchestratorTest, EvictsEveryAgentInTheBatchIncludingRepeats)
{
    // Evicted for every row written, not only the ones reported as newly created: a duplicate id
    // means the row is already there and still pending, and that agent needs to see it too. The
    // API's bulk create makes the same choice.
    for (int index = 1; index <= 3; ++index)
    {
        m_hostOps.agentRows[index] = ubuntuRow();
        m_pendingCache.markEmpty(index < 10 ? "00" + std::to_string(index) : std::to_string(index));
    }
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    // Same request twice: the second finds every id already present.
    ASSERT_EQ(m_orchestrator->process(requestFor({1, 2, 3}), permissive(), m_stop).size(), 3U);
    m_pendingCache.markEmpty("002");
    ASSERT_EQ(m_orchestrator->process(requestFor({1, 2, 3}), permissive(), m_stop).size(), 3U);

    EXPECT_FALSE(m_pendingCache.knownEmpty("001"));
    EXPECT_FALSE(m_pendingCache.knownEmpty("002"));
    EXPECT_FALSE(m_pendingCache.knownEmpty("003"));
}

TEST_F(OrchestratorTest, LeavesTheCacheAloneForAgentsThatGotNoTask)
{
    // An agent that failed a gate has no row, so evicting it would throw away a correct cache entry
    // and put its next poll back on the database for nothing.
    m_hostOps.agentRows[1] = ubuntuRow();
    m_hostOps.agentRows[2] = ubuntuRow("v5.0.0"); // Already at the target: refused.
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    m_pendingCache.markEmpty("001");
    m_pendingCache.markEmpty("002");

    const auto outcomes {m_orchestrator->process(requestFor({1, 2}), permissive(), m_stop)};
    ASSERT_EQ(outcomes[0].error, UpgradeError::Success);
    ASSERT_EQ(outcomes[1].error, UpgradeError::NewVersionLessOrEqualThanCurrent);

    EXPECT_FALSE(m_pendingCache.knownEmpty("001"));
    EXPECT_TRUE(m_pendingCache.knownEmpty("002"));
}

TEST_F(OrchestratorTest, WindowsAgentsGetTheBatchInstaller)
{
    m_hostOps.agentRows[7] = windowsRow();
    scriptRepo("windows/", "wazuh_agent_v5.0.0_windows.wpk");

    ASSERT_EQ(m_orchestrator->process(requestFor({7}), permissive(), m_stop).front().error,
              UpgradeError::Success);

    const auto tasks {m_store->takePendingAgentTasks("007", 10)};
    ASSERT_EQ(tasks.size(), 1U);
    EXPECT_EQ(nlohmann::json::parse(tasks[0].payload).at("installer"), "upgrade.bat");
}

TEST_F(OrchestratorTest, TheSameRequestTwiceCreatesTheTaskOnce)
{
    // Idempotency across cluster nodes rests entirely on this: every node broadcasts the same
    // request with the same request_time, so every node derives the same task id.
    m_hostOps.agentRows[5] = ubuntuRow();
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    EXPECT_EQ(m_orchestrator->process(requestFor({5}), permissive(), m_stop).front().error,
              UpgradeError::Success);
    EXPECT_EQ(m_orchestrator->process(requestFor({5}), permissive(), m_stop).front().error,
              UpgradeError::Success);

    EXPECT_EQ(m_store->takePendingAgentTasks("005", 10).size(), 1U);
}

// ---- per-agent verdicts --------------------------------------------------------------------------

TEST_F(OrchestratorTest, OneAgentsFailureDoesNotAffectTheOthers)
{
    m_hostOps.agentRows[1] = ubuntuRow();
    m_hostOps.agentRows[2] = ubuntuRow("v5.0.0"); // Already at the target.
    m_hostOps.agentRows[3] = ubuntuRow();
    m_hostOps.missingInfoFor.insert(4); // Not in the database.
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    const auto outcomes {m_orchestrator->process(requestFor({1, 2, 3, 4}), permissive(), m_stop)};

    ASSERT_EQ(outcomes.size(), 4U);
    EXPECT_EQ(outcomes[0].error, UpgradeError::Success);
    EXPECT_EQ(outcomes[1].error, UpgradeError::NewVersionLessOrEqualThanCurrent);
    EXPECT_EQ(outcomes[2].error, UpgradeError::Success);
    EXPECT_EQ(outcomes[3].error, UpgradeError::GlobalDbFailure);

    // Outcomes come back in the order the agents were requested, which is what lets the Server API
    // line them up against what it sent.
    EXPECT_EQ(outcomes[0].agentId, 1);
    EXPECT_EQ(outcomes[3].agentId, 4);
}

TEST_F(OrchestratorTest, TheDeliveryGateIsAppliedPerAgent)
{
    m_hostOps.agentRows[1] = ubuntuRow("v4.14.0"); // Pre-v5: needs legacy delivery.
    m_hostOps.agentRows[2] = ubuntuRow("v5.0.1");  // Already v5: does not.
    scriptRepo("linux/deb/amd64/", "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");

    const RemotedSettings legacyOff {true, false, RemotedSettings::VERIFY_NONE};
    const auto outcomes {m_orchestrator->process(requestFor({1, 2}), legacyOff, m_stop)};

    EXPECT_EQ(outcomes[0].error, UpgradeError::LegacyDeliveryDisabled);
    // Agent 2 is refused for a different reason entirely -- it is already past the target.
    EXPECT_EQ(outcomes[1].error, UpgradeError::NewVersionLessOrEqualThanCurrent);
}

TEST_F(OrchestratorTest, AnUnreachableRepositoryFailsOnlyTheAgentsThatNeededIt)
{
    m_hostOps.agentRows[1] = ubuntuRow();
    m_hostOps.agentRows[2] = windowsRow();
    // Only the Windows repository answers.
    scriptRepo("windows/", "wazuh_agent_v5.0.0_windows.wpk");

    const auto outcomes {m_orchestrator->process(requestFor({1, 2}), permissive(), m_stop)};

    EXPECT_EQ(outcomes[0].error, UpgradeError::UrlNotFound);
    EXPECT_EQ(outcomes[1].error, UpgradeError::Success);
}

TEST_F(OrchestratorTest, AVersionMissingFromTheRepositoryIsItsOwnError)
{
    m_hostOps.agentRows[1] = ubuntuRow();
    // The repository answers, but does not publish the requested version.
    m_repository.scriptVersions("https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/versions",
                                {true, "v4.14.0 aaaa1111\n", 200, 0});

    const auto outcomes {m_orchestrator->process(requestFor({1}), permissive(), m_stop)};
    EXPECT_EQ(outcomes[0].error, UpgradeError::WpkVersionDoesNotExist);
    EXPECT_EQ(m_repository.totalDownloadCalls(), 0U);
}

TEST_F(OrchestratorTest, StopsAskingWazuhDbAfterConsecutiveFailures)
{
    // A wedged wazuh-db carries a ten-second timeout per call, so without this a 500-agent batch
    // would hold a worker for over an hour discovering the same thing five hundred times.
    std::vector<int> agentIds;
    for (int index = 1; index <= 50; ++index)
    {
        agentIds.push_back(index);
        m_hostOps.missingInfoFor.insert(index);
    }

    const auto outcomes {m_orchestrator->process(requestFor(agentIds), permissive(), m_stop)};

    ASSERT_EQ(outcomes.size(), 50U);
    for (const auto& outcome : outcomes)
    {
        // Every agent still gets the answer it would have got; only the asking stopped.
        EXPECT_EQ(outcome.error, UpgradeError::GlobalDbFailure);
    }
    EXPECT_EQ(m_hostOps.infoCalls.load(), 5);
}

TEST_F(OrchestratorTest, RefusesABatchLargerThanTheCap)
{
    UpgradeOrchestrator::Options options;
    options.managerVersion = "v5.0.0";
    options.upgradeDir = m_dir.path();
    options.maxAgents = 2;
    UpgradeOrchestrator bounded {m_hostOps, *m_store, m_pendingCache, *m_wpkCache, *m_versionsCache, options};

    const auto outcomes {bounded.process(requestFor({1, 2, 3}), permissive(), m_stop)};

    ASSERT_EQ(outcomes.size(), 3U);
    for (const auto& outcome : outcomes)
    {
        EXPECT_EQ(outcome.error, UpgradeError::ParsingRequiredParameter);
    }
    EXPECT_EQ(m_hostOps.infoCalls.load(), 0);
}

// ---- custom WPK containment ----------------------------------------------------------------------

TEST(UpgradeCustomPath, AcceptsAFileDirectlyInsideTheUpgradeDirectory)
{
    const TempDir dir;
    dir.writeFile("wazuh_agent_v5.0.0_linux_x86_64.wpk", CONTENT);

    std::string fileName;
    EXPECT_EQ(resolveCustomWpkPath(dir.path() + "wazuh_agent_v5.0.0_linux_x86_64.wpk", dir.path(), fileName),
              UpgradeError::Success);
    EXPECT_EQ(fileName, "wazuh_agent_v5.0.0_linux_x86_64.wpk");
}

TEST(UpgradeCustomPath, RejectsAnythingOutsideIt)
{
    // NOT new hardening -- a bug fix. The retired code hashed whatever path it was given but put
    // only the BASENAME in the payload, and both delivery paths resolve that under var/upgrade/. So
    // an out-of-tree file_path already produced a task naming a file that is not there, or one that
    // is there but is a different file whose digest will not match. The CLI has always rejected
    // these; only the API did not.
    const TempDir dir;
    const TempDir elsewhere;
    elsewhere.writeFile("agent.wpk", CONTENT);

    std::string fileName;
    EXPECT_EQ(resolveCustomWpkPath(elsewhere.path() + "agent.wpk", dir.path(), fileName),
              UpgradeError::WpkFileDoesNotExist);

    // A traversal that lands outside is the same rejection.
    EXPECT_EQ(resolveCustomWpkPath(dir.path() + "../etc/passwd", dir.path(), fileName),
              UpgradeError::WpkFileDoesNotExist);

    // So is a file that does not exist at all: realpath() requires it.
    EXPECT_EQ(resolveCustomWpkPath(dir.path() + "absent.wpk", dir.path(), fileName),
              UpgradeError::WpkFileDoesNotExist);

    EXPECT_EQ(resolveCustomWpkPath("", dir.path(), fileName), UpgradeError::WpkFileDoesNotExist);
}

TEST(UpgradeCustomPath, ASymlinkOutOfTheDirectoryDoesNotCount)
{
    // The reason the check resolves symlinks first: a link INSIDE var/upgrade/ pointing anywhere
    // else would otherwise pass a plain prefix test while delivering different bytes.
    const TempDir dir;
    const TempDir elsewhere;
    elsewhere.writeFile("real.wpk", CONTENT);

    ASSERT_EQ(::symlink((elsewhere.path() + "real.wpk").c_str(), (dir.path() + "link.wpk").c_str()), 0);

    std::string fileName;
    EXPECT_EQ(resolveCustomWpkPath(dir.path() + "link.wpk", dir.path(), fileName),
              UpgradeError::WpkFileDoesNotExist);
}

TEST(UpgradeCustomPath, ASiblingDirectoryWithASharedPrefixDoesNotCount)
{
    // "/var/upgrade-evil/x.wpk" must not pass as being inside "/var/upgrade/", which a prefix test
    // on the unterminated directory would allow.
    const TempDir parent;
    ASSERT_EQ(::mkdir((parent.path() + "upgrade").c_str(), 0770), 0);
    ASSERT_EQ(::mkdir((parent.path() + "upgrade-evil").c_str(), 0770), 0);
    parent.writeFile("upgrade-evil/agent.wpk", CONTENT);

    std::string fileName;
    EXPECT_EQ(resolveCustomWpkPath(parent.path() + "upgrade-evil/agent.wpk", parent.path() + "upgrade", fileName),
              UpgradeError::WpkFileDoesNotExist);
}

TEST_F(OrchestratorTest, ACustomBatchVerifiesTheFileOnceAndDownloadsNothing)
{
    m_dir.writeFile("wazuh_agent_v5.0.0_linux_x86_64.wpk", CONTENT);
    for (int index = 1; index <= 20; ++index)
    {
        m_hostOps.agentRows[index] = ubuntuRow();
    }

    UpgradeCustomRequest request;
    request.requestTime = REQUEST_TIME;
    request.filePath = m_dir.path() + "wazuh_agent_v5.0.0_linux_x86_64.wpk";
    for (int index = 1; index <= 20; ++index)
    {
        request.agentIds.push_back(index);
    }

    const auto outcomes {m_orchestrator->process(request, permissive(), m_stop)};

    ASSERT_EQ(outcomes.size(), 20U);
    for (const auto& outcome : outcomes)
    {
        EXPECT_EQ(outcome.error, UpgradeError::Success);
    }
    EXPECT_EQ(m_repository.totalDownloadCalls(), 0U);
    EXPECT_EQ(m_repository.totalVersionsCalls(), 0U);

    const auto tasks {m_store->takePendingAgentTasks("001", 10)};
    ASSERT_EQ(tasks.size(), 1U);
    const auto payload = nlohmann::json::parse(tasks[0].payload);
    EXPECT_EQ(payload.at("wpk_file"), "wazuh_agent_v5.0.0_linux_x86_64.wpk");
    EXPECT_EQ(payload.at("wpk_sha1"), SHA1);
}

TEST_F(OrchestratorTest, ACustomWpkIsTreatedAsIfItTargetsFive)
{
    // No 'force' parameter exists on this route, so the https gate has no override.
    m_dir.writeFile("wazuh_agent_v5.0.0_linux_x86_64.wpk", CONTENT);
    m_hostOps.agentRows[1] = ubuntuRow("v5.0.0");

    UpgradeCustomRequest request;
    request.requestTime = REQUEST_TIME;
    request.filePath = m_dir.path() + "wazuh_agent_v5.0.0_linux_x86_64.wpk";
    request.agentIds = {1};

    const RemotedSettings strict {true, true, 2 /* verify full */};
    EXPECT_EQ(m_orchestrator->process(request, strict, m_stop).front().error,
              UpgradeError::HttpsVerificationModeUnsafe);
}

TEST_F(OrchestratorTest, ACustomInstallerOverridesThePlatformDefault)
{
    m_dir.writeFile("wazuh_agent_v5.0.0_linux_x86_64.wpk", CONTENT);
    m_hostOps.agentRows[1] = ubuntuRow();

    UpgradeCustomRequest request;
    request.requestTime = REQUEST_TIME;
    request.filePath = m_dir.path() + "wazuh_agent_v5.0.0_linux_x86_64.wpk";
    request.installer = "my-installer.sh";
    request.agentIds = {1};

    ASSERT_EQ(m_orchestrator->process(request, permissive(), m_stop).front().error, UpgradeError::Success);

    const auto tasks {m_store->takePendingAgentTasks("001", 10)};
    ASSERT_EQ(tasks.size(), 1U);
    EXPECT_EQ(nlohmann::json::parse(tasks[0].payload).at("installer"), "my-installer.sh");
}
