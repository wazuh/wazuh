/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "storage/sqliteTaskStore.hpp"
#include "upgrade/taskLinks.hpp"

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace task_manager;
using namespace task_manager::storage;
using namespace task_manager::upgrade;

namespace fs = std::filesystem;

namespace
{
    constexpr const char* REMOTE_UPGRADE {"remote_upgrade"};

    // Ids must match the shape sweep() recognises as a task file.
    std::string taskId(int n)
    {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%08x-0000-4000-8000-%012x", n, n);
        return buf;
    }

    std::string slurp(const fs::path& path)
    {
        std::ifstream in(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    void writeFile(const fs::path& path, const std::string& content)
    {
        std::ofstream out(path, std::ios::binary);
        out << content;
    }

    ino_t inodeOf(const fs::path& path)
    {
        struct stat st {};
        EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
        return st.st_ino;
    }

    nlink_t linksOf(const fs::path& path)
    {
        struct stat st {};
        EXPECT_EQ(::stat(path.c_str(), &st), 0) << path;
        return st.st_nlink;
    }

    std::set<std::string> namesIn(const fs::path& dir)
    {
        std::set<std::string> names;
        for (const auto& entry : fs::directory_iterator(dir))
        {
            names.insert(entry.path().filename().string());
        }
        return names;
    }

    class TaskLinksTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            std::string pattern {(fs::temp_directory_path() / "tasklinks.XXXXXX").string()};
            ASSERT_NE(::mkdtemp(pattern.data()), nullptr);
            m_root = pattern;
            m_upgradeDir = m_root / "upgrade";
            fs::create_directories(m_upgradeDir);

            SqliteTaskStore::Options options;
            options.dbPath = DB_MEMORY;
            options.groupCommitWindow = std::chrono::milliseconds {0};
            m_store = std::make_unique<SqliteTaskStore>(std::move(options));
        }

        void TearDown() override
        {
            std::error_code ec;
            fs::remove_all(m_root, ec);
        }

        fs::path tasksDir() const
        {
            return m_upgradeDir / "tasks";
        }

        fs::path taskFile(const std::string& id) const
        {
            return tasksDir() / (id + ".wpk");
        }

        fs::path makeWpk(const std::string& name, const std::string& content)
        {
            const auto path {m_upgradeDir / name};
            writeFile(path, content);
            return path;
        }

        void insertRow(const std::string& id, const std::string& agentId = "001")
        {
            AgentTask task;
            task.taskId = id;
            task.agentId = agentId;
            task.taskType = REMOTE_UPGRADE;
            task.payload = "{}";
            task.createTime = 1000;
            ASSERT_TRUE(m_store->createAgentTask(task));
        }

        std::unique_ptr<TaskLinks> makeLinks(TaskLinks::LinkAt linkAt = {})
        {
            return std::make_unique<TaskLinks>(m_upgradeDir.string(), *m_store, std::move(linkAt));
        }

        // Refuses every link whose source is `wpk`, the way a filesystem without hard links would.
        static TaskLinks::LinkAt refuse(const std::string& wpk, int err)
        {
            return [wpk, err](int oldFd, const char* oldPath, int newFd, const char* newPath, int flags)
            {
                if (fs::path(oldPath).filename() == wpk)
                {
                    errno = err;
                    return -1;
                }
                return ::linkat(oldFd, oldPath, newFd, newPath, flags);
            };
        }

        fs::path m_root;
        fs::path m_upgradeDir;
        std::unique_ptr<SqliteTaskStore> m_store;
    };
} // namespace

TEST_F(TaskLinksTest, LinksEachRowBeforeCommit)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}, {taskId(3), "agent.wpk"}};
    auto links {makeLinks()};

    bool committed {false};
    const auto stats {links->linkAndCommit(rows,
                                           [&]
                                           {
                                               committed = true;
                                               for (const auto& row : rows)
                                               {
                                                   EXPECT_TRUE(fs::exists(taskFile(row.taskId))) << row.taskId;
                                                   EXPECT_EQ(inodeOf(taskFile(row.taskId)), inodeOf(wpk));
                                               }
                                           })};

    EXPECT_TRUE(committed);
    EXPECT_EQ(stats.linked, 3U);
    EXPECT_EQ(stats.copied, 0U);
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(linksOf(wpk), 4U);
}

TEST_F(TaskLinksTest, ExistingLinkIsOk)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}};
    auto links {makeLinks()};

    ASSERT_EQ(links->linkAndCommit(rows, [] {}).failed, 0U);
    const auto stats {links->linkAndCommit(rows, [] {})};

    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(inodeOf(taskFile(taskId(1))), inodeOf(wpk));
}

TEST_F(TaskLinksTest, CopiesOnceWhenLinkIsRefused)
{
    makeWpk("agent.wpk", "WPK-A");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}, {taskId(3), "agent.wpk"}};
    auto links {makeLinks(refuse("agent.wpk", EPERM))};

    const auto stats {links->linkAndCommit(rows, [] {})};

    EXPECT_EQ(stats.copied, 1U);
    EXPECT_EQ(stats.failed, 0U);
    const auto ino {inodeOf(taskFile(taskId(1)))};
    for (const auto& row : rows)
    {
        EXPECT_EQ(inodeOf(taskFile(row.taskId)), ino);
        EXPECT_EQ(slurp(taskFile(row.taskId)), "WPK-A");
    }
    EXPECT_NE(ino, inodeOf(m_upgradeDir / "agent.wpk"));
    for (const auto& name : namesIn(tasksDir()))
    {
        EXPECT_EQ(fs::path(name).extension(), ".wpk") << name;
    }
}

TEST_F(TaskLinksTest, CopiesAgainWhenTheCopyReachesTheLinkLimit)
{
    makeWpk("agent.wpk", "WPK-A");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}, {taskId(3), "agent.wpk"}};
    // The origin refuses every link and the first copy refuses them as if it had hit EMLINK.
    const auto full {taskId(1) + ".wpk"};
    auto links {makeLinks(
        [full](int oldFd, const char* oldPath, int newFd, const char* newPath, int flags)
        {
            const auto name {fs::path(oldPath).filename().string()};
            if (name == "agent.wpk" || name == full)
            {
                errno = EMLINK;
                return -1;
            }
            return ::linkat(oldFd, oldPath, newFd, newPath, flags);
        })};

    const auto stats {links->linkAndCommit(rows, [] {})};

    EXPECT_EQ(stats.copied, 2U);
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_NE(inodeOf(taskFile(taskId(1))), inodeOf(taskFile(taskId(2))));
    EXPECT_EQ(inodeOf(taskFile(taskId(2))), inodeOf(taskFile(taskId(3))));
    for (const auto& row : rows)
    {
        EXPECT_EQ(slurp(taskFile(row.taskId)), "WPK-A");
    }
}

TEST_F(TaskLinksTest, RejectsIdsThatAreNotTaskIds)
{
    makeWpk("agent.wpk", "WPK-A");
    const std::vector<TaskLink> rows {{"../escape", "agent.wpk"}, {"NOT-A-TASK-ID", "agent.wpk"}};
    auto links {makeLinks()};

    const auto stats {links->linkAndCommit(rows, [] {})};

    EXPECT_EQ(stats.failed, 2U);
    EXPECT_EQ(stats.lastErrno, EINVAL);
    EXPECT_FALSE(fs::exists(m_upgradeDir / "escape.wpk"));
    EXPECT_TRUE(namesIn(tasksDir()).empty());
}

TEST_F(TaskLinksTest, EachTaskKeepsItsOwnWpkUnderEmlink)
{
    makeWpk("a.wpk", "CONTENT-A");
    const auto wpkB {makeWpk("b.wpk", "CONTENT-B")};
    const std::vector<TaskLink> rows {
        {taskId(1), "a.wpk"}, {taskId(2), "a.wpk"}, {taskId(3), "b.wpk"}, {taskId(4), "a.wpk"}};
    auto links {makeLinks(refuse("a.wpk", EMLINK))};

    const auto stats {links->linkAndCommit(rows, [] {})};

    EXPECT_EQ(stats.failed, 0U);
    const auto inoA {inodeOf(taskFile(taskId(1)))};
    EXPECT_EQ(inodeOf(taskFile(taskId(2))), inoA);
    EXPECT_EQ(inodeOf(taskFile(taskId(4))), inoA);
    EXPECT_EQ(slurp(taskFile(taskId(1))), "CONTENT-A");
    EXPECT_EQ(slurp(taskFile(taskId(2))), "CONTENT-A");
    EXPECT_EQ(slurp(taskFile(taskId(4))), "CONTENT-A");
    EXPECT_EQ(inodeOf(taskFile(taskId(3))), inodeOf(wpkB));
    EXPECT_NE(inoA, inodeOf(wpkB));
    EXPECT_EQ(slurp(taskFile(taskId(3))), "CONTENT-B");
}

TEST_F(TaskLinksTest, StaleTmpDoesNotBlockTheCopy)
{
    makeWpk("agent.wpk", "WPK-A");
    fs::create_directories(tasksDir());
    const auto id {taskId(1)};
    writeFile(tasksDir() / ("." + id + ".tmp"), "STALE");
    auto links {makeLinks(refuse("agent.wpk", EPERM))};

    const auto stats {links->linkAndCommit({{id, "agent.wpk"}}, [] {})};

    EXPECT_EQ(stats.copied, 1U);
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(slurp(taskFile(id)), "WPK-A");
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {id + ".wpk"});
}

TEST_F(TaskLinksTest, TotalFailureStillCommits)
{
    // The WPK does not exist, so the link is refused and the copy has no source either.
    const std::vector<TaskLink> rows {{taskId(1), "missing.wpk"}, {taskId(2), "missing.wpk"}};
    auto links {makeLinks(refuse("missing.wpk", EPERM))};

    bool committed {false};
    const auto stats {links->linkAndCommit(rows, [&] { committed = true; })};

    EXPECT_TRUE(committed);
    EXPECT_EQ(stats.failed, rows.size());
    EXPECT_NE(stats.lastErrno, 0);
    EXPECT_TRUE(!fs::exists(tasksDir()) || namesIn(tasksDir()).empty());
}

TEST_F(TaskLinksTest, CreatesTasksDirOnDemand)
{
    makeWpk("agent.wpk", "WPK-A");
    ASSERT_FALSE(fs::exists(tasksDir()));
    auto links {makeLinks()};

    const auto old {::umask(0)};
    const auto stats {links->linkAndCommit({{taskId(1), "agent.wpk"}}, [] {})};
    ::umask(old);

    EXPECT_EQ(stats.failed, 0U);
    struct stat st {};
    ASSERT_EQ(::stat(tasksDir().c_str(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));
    EXPECT_EQ(st.st_mode & 07777, 0770U);
}

TEST_F(TaskLinksTest, RefusesASymlinkedTasksDir)
{
    makeWpk("agent.wpk", "WPK-A");
    const auto outside {m_root / "outside"};
    fs::create_directories(outside);
    fs::create_directory_symlink(outside, tasksDir());
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}};
    auto links {makeLinks()};

    bool committed {false};
    const auto stats {links->linkAndCommit(rows, [&] { committed = true; })};

    EXPECT_TRUE(committed);
    EXPECT_EQ(stats.failed, rows.size());
    EXPECT_TRUE(namesIn(outside).empty());
}

TEST_F(TaskLinksTest, SweepWaitsForAnInFlightCommit)
{
    makeWpk("agent.wpk", "WPK-A");
    const auto id {taskId(1)};
    auto links {makeLinks()};

    std::atomic<bool> inCommit {false};
    std::atomic<bool> release {false};
    std::atomic<bool> sweepStarted {false};
    std::atomic<bool> sweepDone {false};

    std::thread committer(
        [&]
        {
            links->linkAndCommit({{id, "agent.wpk"}},
                                 [&]
                                 {
                                     inCommit = true;
                                     while (!release)
                                     {
                                         std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                     }
                                 });
        });

    for (int i = 0; i < 5000 && !inCommit; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(inCommit);

    std::thread sweeper(
        [&]
        {
            sweepStarted = true;
            links->sweep();
            sweepDone = true;
        });

    for (int i = 0; i < 5000 && !sweepStarted; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(sweepStarted);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(sweepDone) << "sweep ran while a commit was in flight";

    insertRow(id);
    release = true;
    committer.join();
    sweeper.join();

    EXPECT_TRUE(sweepDone);
    EXPECT_TRUE(fs::exists(taskFile(id)));
}

TEST_F(TaskLinksTest, SweepRemovesOnlyOrphans)
{
    makeWpk("agent.wpk", "WPK-A");
    makeWpk("keep.wpk", "OTHER");
    auto links {makeLinks()};
    ASSERT_EQ(links->linkAndCommit({{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}}, [] {}).failed, 0U);
    insertRow(taskId(1));
    writeFile(tasksDir() / ".x.tmp", "TMP");
    writeFile(tasksDir() / "notes.txt", "NOTES");

    EXPECT_EQ(links->sweep(), 2U);

    EXPECT_TRUE(fs::exists(taskFile(taskId(1))));
    EXPECT_FALSE(fs::exists(taskFile(taskId(2))));
    EXPECT_FALSE(fs::exists(tasksDir() / ".x.tmp"));
    EXPECT_TRUE(fs::exists(tasksDir() / "notes.txt"));
    EXPECT_TRUE(fs::exists(m_upgradeDir / "agent.wpk"));
    EXPECT_TRUE(fs::exists(m_upgradeDir / "keep.wpk"));
}

TEST_F(TaskLinksTest, RetentionThenSweep)
{
    makeWpk("agent.wpk", "WPK-A");
    auto links {makeLinks()};
    ASSERT_EQ(links->linkAndCommit({{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}}, [] {}).failed, 0U);
    insertRow(taskId(1), "001");
    insertRow(taskId(2), "002");

    // Row 1 becomes delivered, the only state deleteOldAgentTasks removes besides expired.
    ASSERT_EQ(m_store->takePendingAgentTasks("001", 10).size(), 1U);
    ASSERT_EQ(m_store->deleteOldAgentTasks(std::numeric_limits<std::int64_t>::max()), 1);

    EXPECT_EQ(links->sweep(), 1U);

    EXPECT_FALSE(fs::exists(taskFile(taskId(1))));
    EXPECT_TRUE(fs::exists(taskFile(taskId(2))));
}
