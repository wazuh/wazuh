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
#include "upgrade/fileHash.hpp"
#include "upgrade/taskLinks.hpp"

#include <json.hpp>

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

    const TaskLinks::Commit noCommit {[](const std::vector<std::size_t>&) {}};

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

        std::unique_ptr<TaskLinks> makeLinks(TaskLinks::LinkAt linkAt = {}, TaskLinks::Fsync fsync = {})
        {
            return std::make_unique<TaskLinks>(m_upgradeDir.string(), *m_store, std::move(linkAt), std::move(fsync));
        }

        static TaskLinks::Fsync failingFsync()
        {
            return [](int)
            {
                errno = EIO;
                return -1;
            };
        }

        void addPending(const std::string& id, const nlohmann::json& payload, const std::string& agentId = "001")
        {
            addPendingRaw(id, payload.dump(), agentId);
        }

        void addPendingRaw(const std::string& id, const std::string& payload, const std::string& agentId = "001")
        {
            AgentTask task;
            task.taskId = id;
            task.agentId = agentId;
            task.taskType = REMOTE_UPGRADE;
            task.payload = payload;
            task.createTime = 1000;
            ASSERT_EQ(m_store->createAgentTasks({task}), std::vector<bool> {true});
        }

        void addPendingWpk(const std::string& id,
                           const std::string& wpkFile,
                           const std::string& sha1,
                           const std::string& agentId = "001")
        {
            addPending(id, nlohmann::json {{"wpk_file", wpkFile}, {"wpk_sha1", sha1}}, agentId);
        }

        std::set<std::string> pendingIds()
        {
            std::set<std::string> ids;
            for (const auto& task : m_store->pendingAgentTasksByType(REMOTE_UPGRADE))
            {
                ids.insert(task.taskId);
            }
            return ids;
        }

        static std::string sha1Of(const fs::path& path)
        {
            return sha1OfFile(path.string()).value_or("");
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
                                           [&](const std::vector<std::size_t>& staged)
                                           {
                                               committed = true;
                                               EXPECT_EQ(staged, (std::vector<std::size_t> {0, 1, 2}));
                                               for (const auto& row : rows)
                                               {
                                                   EXPECT_TRUE(fs::exists(taskFile(row.taskId))) << row.taskId;
                                                   EXPECT_EQ(inodeOf(taskFile(row.taskId)), inodeOf(wpk));
                                               }
                                           })};

    EXPECT_TRUE(committed);
    EXPECT_EQ(stats.linked, 3U);
    EXPECT_EQ(stats.staged, (std::vector<bool> {true, true, true}));
    EXPECT_EQ(stats.copied, 0U);
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(linksOf(wpk), 4U);
}

TEST_F(TaskLinksTest, ExistingLinkIsOk)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}};
    auto links {makeLinks()};

    ASSERT_EQ(links->linkAndCommit(rows, noCommit).failed, 0U);
    const auto stats {links->linkAndCommit(rows, noCommit)};

    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(inodeOf(taskFile(taskId(1))), inodeOf(wpk));
}

TEST_F(TaskLinksTest, CopiesOnceWhenLinkIsRefused)
{
    makeWpk("agent.wpk", "WPK-A");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}, {taskId(3), "agent.wpk"}};
    auto links {makeLinks(refuse("agent.wpk", EPERM))};

    const auto stats {links->linkAndCommit(rows, noCommit)};

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

    const auto stats {links->linkAndCommit(rows, noCommit)};

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

    const auto stats {links->linkAndCommit(rows, noCommit)};

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

    const auto stats {links->linkAndCommit(rows, noCommit)};

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

    const auto stats {links->linkAndCommit({{id, "agent.wpk"}}, noCommit)};

    EXPECT_EQ(stats.copied, 1U);
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(slurp(taskFile(id)), "WPK-A");
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {id + ".wpk"});
}

TEST_F(TaskLinksTest, TotalFailureCommitsNothing)
{
    // The WPK does not exist: the origin check fails before any link or copy is attempted.
    const std::vector<TaskLink> rows {{taskId(1), "missing.wpk"}, {taskId(2), "missing.wpk"}};
    auto links {makeLinks(refuse("missing.wpk", EPERM))};

    bool committed {false};
    std::vector<std::size_t> staged {99};
    const auto stats {links->linkAndCommit(rows,
                                           [&](const std::vector<std::size_t>& indices)
                                           {
                                               committed = true;
                                               staged = indices;
                                           })};

    EXPECT_TRUE(committed);
    EXPECT_TRUE(staged.empty());
    EXPECT_EQ(stats.staged, (std::vector<bool> {false, false}));
    EXPECT_EQ(stats.failed, rows.size());
    EXPECT_EQ(stats.lastErrno, ENOENT);
    EXPECT_TRUE(!fs::exists(tasksDir()) || namesIn(tasksDir()).empty());
}

TEST_F(TaskLinksTest, CreatesTasksDirOnDemand)
{
    makeWpk("agent.wpk", "WPK-A");
    ASSERT_FALSE(fs::exists(tasksDir()));
    auto links {makeLinks()};

    const auto old {::umask(0)};
    const auto stats {links->linkAndCommit({{taskId(1), "agent.wpk"}}, noCommit)};
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
    const auto stats {
        links->linkAndCommit(rows, [&](const std::vector<std::size_t>& staged) { committed = staged.empty(); })};

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
                                 [&](const std::vector<std::size_t>&)
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
    ASSERT_EQ(links->linkAndCommit({{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}}, noCommit).failed, 0U);
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
    ASSERT_EQ(links->linkAndCommit({{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}}, noCommit).failed, 0U);
    insertRow(taskId(1), "001");
    insertRow(taskId(2), "002");

    // Row 1 becomes delivered, the only state deleteOldAgentTasks removes besides expired.
    ASSERT_EQ(m_store->takePendingAgentTasks("001", 10).size(), 1U);
    ASSERT_EQ(m_store->deleteOldAgentTasks(std::numeric_limits<std::int64_t>::max()), 1);

    EXPECT_EQ(links->sweep(), 1U);

    EXPECT_FALSE(fs::exists(taskFile(taskId(1))));
    EXPECT_TRUE(fs::exists(taskFile(taskId(2))));
}

// ---- rows without a file, and the directory sync ---------------------------------------------

TEST_F(TaskLinksTest, ARowWithoutAFileIsNotCommitted)
{
    makeWpk("agent.wpk", "WPK-A");
    // A directory as origin is refused by the origin check (EISDIR), whatever the user or the
    // permissions.
    fs::create_directory(m_upgradeDir / "dir.wpk");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "dir.wpk"}, {taskId(3), "agent.wpk"}};
    auto links {makeLinks(refuse("dir.wpk", EPERM))};

    std::vector<std::size_t> committed;
    const auto stats {links->linkAndCommit(rows, [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0, 2}));
    EXPECT_EQ(stats.staged, (std::vector<bool> {true, false, true}));
    EXPECT_EQ(stats.failed, 1U);
    EXPECT_EQ(stats.lastErrno, EISDIR);
    EXPECT_EQ(namesIn(tasksDir()), (std::set<std::string> {taskId(1) + ".wpk", taskId(3) + ".wpk"}));
}

TEST_F(TaskLinksTest, ACopyIsMode0660AndRefusesASymlinkedSource)
{
    makeWpk("agent.wpk", "WPK-A");
    const auto target {m_root / "target.wpk"};
    writeFile(target, "OUTSIDE");
    fs::create_symlink(target, m_upgradeDir / "link.wpk");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "link.wpk"}};
    auto links {makeLinks(
        [](int, const char*, int, const char*, int)
        {
            errno = EPERM;
            return -1;
        })};

    std::vector<std::size_t> committed;
    const auto old {::umask(0)};
    const auto stats {links->linkAndCommit(rows, [&](const std::vector<std::size_t>& staged) { committed = staged; })};
    ::umask(old);

    EXPECT_EQ(committed, (std::vector<std::size_t> {0}));
    EXPECT_EQ(stats.staged, (std::vector<bool> {true, false}));
    EXPECT_EQ(stats.failed, 1U);
    EXPECT_EQ(slurp(taskFile(taskId(1))), "WPK-A");
    struct stat st {};
    ASSERT_EQ(::stat(taskFile(taskId(1)).c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, 0660U);
    EXPECT_FALSE(fs::exists(taskFile(taskId(2))));
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {taskId(1) + ".wpk"});
}

TEST_F(TaskLinksTest, ASymlinkedWpkIsNotLinked)
{
    const auto target {m_root / "target.wpk"};
    writeFile(target, "OUTSIDE");
    fs::create_symlink(target, m_upgradeDir / "link.wpk");
    auto links {makeLinks()};

    std::vector<std::size_t> committed {99};
    const auto stats {links->linkAndCommit({{taskId(1), "link.wpk"}},
                                           [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_TRUE(committed.empty());
    EXPECT_EQ(stats.staged, (std::vector<bool> {false}));
    EXPECT_EQ(stats.failed, 1U);
    EXPECT_EQ(stats.lastErrno, ELOOP);
    EXPECT_FALSE(fs::exists(taskFile(taskId(1))));
    EXPECT_TRUE(!fs::exists(tasksDir()) || namesIn(tasksDir()).empty());
}

TEST_F(TaskLinksTest, AFailedDirectoryFsyncStagesNothing)
{
    makeWpk("agent.wpk", "WPK-A");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}};

    std::vector<std::size_t> committed {99};
    const auto stats {makeLinks({}, failingFsync())
                          ->linkAndCommit(rows, [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_TRUE(committed.empty());
    EXPECT_EQ(stats.staged, (std::vector<bool> {false, false}));
    EXPECT_EQ(stats.failed, rows.size());
    EXPECT_EQ(stats.lastErrno, EIO);

    // The files stay behind; the same batch finds them and confirms every row.
    committed.clear();
    const auto again {
        makeLinks()->linkAndCommit(rows, [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0, 1}));
    EXPECT_EQ(again.staged, (std::vector<bool> {true, true}));
    EXPECT_EQ(again.failed, 0U);
}

// ---- task files that already exist -----------------------------------------------------------

TEST_F(TaskLinksTest, ExistingLinkToTheBatchCopyIsOk)
{
    makeWpk("agent.wpk", "WPK-A");
    const std::vector<TaskLink> rows {{taskId(1), "agent.wpk"}, {taskId(2), "agent.wpk"}};
    const auto id2 {taskId(2) + ".wpk"};
    int temporaries {0};
    // The origin is refused, so row 1 is a copy; the link of row 2 to that copy lands and then reports
    // EEXIST, as if another creator had won the race.
    auto links {makeLinks(
        [&](int oldFd, const char* oldPath, int newFd, const char* newPath, int flags)
        {
            const std::string name {fs::path(newPath).filename().string()};
            if (name.front() == '.')
            {
                ++temporaries;
            }
            if (fs::path(oldPath).filename() == "agent.wpk")
            {
                errno = EPERM;
                return -1;
            }
            const auto linked {::linkat(oldFd, oldPath, newFd, newPath, flags)};
            return name == id2 ? ::linkat(oldFd, oldPath, newFd, newPath, flags) : linked;
        })};

    std::vector<std::size_t> committed;
    const auto stats {links->linkAndCommit(rows, [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0, 1}));
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(inodeOf(taskFile(taskId(2))), inodeOf(taskFile(taskId(1))));
    EXPECT_EQ(temporaries, 0) << "the existing link to the copy was replaced";
}

TEST_F(TaskLinksTest, AnOrphanFileOfAnotherWpkIsReplaced)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    fs::create_directories(tasksDir());
    const auto id {taskId(1)};
    writeFile(taskFile(id), "OTHER");

    std::vector<std::size_t> committed;
    const auto stats {makeLinks()->linkAndCommit({{id, "agent.wpk"}},
                                                 [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0}));
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(slurp(taskFile(id)), "WPK-A");
    EXPECT_EQ(inodeOf(taskFile(id)), inodeOf(wpk));
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {id + ".wpk"});
}

TEST_F(TaskLinksTest, AnOrphanReplacementSurvivesAStaleTmp)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    fs::create_directories(tasksDir());
    const auto id {taskId(1)};
    writeFile(taskFile(id), "OTHER");
    writeFile(tasksDir() / ("." + id + ".tmp"), "STALE");

    std::vector<std::size_t> committed;
    const auto stats {makeLinks()->linkAndCommit({{id, "agent.wpk"}},
                                                 [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0}));
    EXPECT_EQ(stats.failed, 0U);
    EXPECT_EQ(slurp(taskFile(id)), "WPK-A");
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {id + ".wpk"});
}

TEST_F(TaskLinksTest, AFileThatBelongsToAnExistingRowIsKept)
{
    makeWpk("agent.wpk", "WPK-A");
    fs::create_directories(tasksDir());
    const auto fileId {taskId(1)};
    const auto dirId {taskId(2)};
    insertRow(fileId, "001");
    insertRow(dirId, "002");
    writeFile(taskFile(fileId), "OTHER");
    fs::create_directory(taskFile(dirId));

    std::vector<std::size_t> committed;
    const auto stats {makeLinks()->linkAndCommit({{fileId, "agent.wpk"}, {dirId, "agent.wpk"}},
                                                 [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0}));
    EXPECT_EQ(stats.staged, (std::vector<bool> {true, false}));
    EXPECT_EQ(slurp(taskFile(fileId)), "OTHER");
    EXPECT_TRUE(fs::is_directory(taskFile(dirId)));
}

TEST_F(TaskLinksTest, AnOrphanNonRegularFileIsReplaced)
{
    makeWpk("agent.wpk", "WPK-A");
    fs::create_directories(tasksDir());
    const auto emptyDir {taskId(1)};
    const auto fullDir {taskId(2)};
    const auto symlink {taskId(3)};
    fs::create_directory(taskFile(emptyDir));
    fs::create_directory(taskFile(fullDir));
    writeFile(taskFile(fullDir) / "inner", "INNER");
    writeFile(m_root / "target", "TARGET");
    fs::create_symlink(m_root / "target", taskFile(symlink));

    std::vector<std::size_t> committed;
    const auto stats {
        makeLinks()->linkAndCommit({{emptyDir, "agent.wpk"}, {fullDir, "agent.wpk"}, {symlink, "agent.wpk"}},
                                   [&](const std::vector<std::size_t>& staged) { committed = staged; })};

    EXPECT_EQ(committed, (std::vector<std::size_t> {0, 2}));
    EXPECT_EQ(stats.staged, (std::vector<bool> {true, false, true}));
    EXPECT_EQ(stats.failed, 1U);
    EXPECT_TRUE(fs::is_regular_file(taskFile(emptyDir)));
    EXPECT_EQ(slurp(taskFile(emptyDir)), "WPK-A");
    EXPECT_TRUE(fs::is_directory(taskFile(fullDir)));
    EXPECT_TRUE(fs::exists(taskFile(fullDir) / "inner"));
    EXPECT_FALSE(fs::is_symlink(taskFile(symlink)));
    EXPECT_EQ(slurp(taskFile(symlink)), "WPK-A");
    EXPECT_EQ(slurp(m_root / "target"), "TARGET");
}

// ---- backfill --------------------------------------------------------------------------------

TEST_F(TaskLinksTest, BackfillStagesPendingRowsWhoseWpkMatches)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    addPendingWpk(taskId(1), "agent.wpk", sha1Of(wpk));
    addPendingWpk(taskId(2), "agent.wpk", sha1Of(wpk));

    const auto stats {makeLinks()->backfill()};

    EXPECT_EQ(stats.staged, 2U);
    EXPECT_EQ(stats.expired, 0U);
    EXPECT_EQ(pendingIds(), (std::set<std::string> {taskId(1), taskId(2)}));
    for (const auto id : {taskId(1), taskId(2)})
    {
        EXPECT_EQ(slurp(taskFile(id)), "WPK-A") << id;
        EXPECT_EQ(inodeOf(taskFile(id)), inodeOf(wpk)) << id;
    }
}

TEST_F(TaskLinksTest, BackfillStagesACopyWhenTheLinkIsRefused)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    addPendingWpk(taskId(1), "agent.wpk", sha1Of(wpk));

    const auto stats {makeLinks(refuse("agent.wpk", EPERM))->backfill()};

    EXPECT_EQ(stats.staged, 1U);
    EXPECT_EQ(slurp(taskFile(taskId(1))), "WPK-A");
    EXPECT_NE(inodeOf(taskFile(taskId(1))), inodeOf(wpk));
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {taskId(1) + ".wpk"});
}

TEST_F(TaskLinksTest, BackfillExpiresRowsWhoseWpkIsMissingOrChanged)
{
    const auto good {makeWpk("good.wpk", "WPK-A")};
    const auto goodSha1 {sha1Of(good)};
    makeWpk("changed.wpk", "WPK-CHANGED");
    fs::create_symlink(good, m_upgradeDir / "link.wpk");
    fs::create_directory(m_upgradeDir / "dir.wpk");
    writeFile(m_root / "x", "WPK-A");
    writeFile(m_root / "abs.wpk", "WPK-A");
    writeFile(m_upgradeDir / ".x", "WPK-A");
    writeFile(m_upgradeDir / "a", "WPK-A");
    fs::create_directories(tasksDir());
    writeFile(tasksDir() / "x", "WPK-A");

    const std::string withNul {"a\0b", 3};
    const std::vector<std::pair<std::string, std::string>> cases {{taskId(1), "absent.wpk"},
                                                                  {taskId(2), "changed.wpk"},
                                                                  {taskId(3), "link.wpk"},
                                                                  {taskId(4), "dir.wpk"},
                                                                  {taskId(5), "../x"},
                                                                  {taskId(6), "tasks/x"},
                                                                  {taskId(7), (m_root / "abs.wpk").string()},
                                                                  {taskId(8), ".x"},
                                                                  {taskId(9), withNul},
                                                                  {"not-a-task-id", "good.wpk"}};
    std::set<std::string> ids;
    for (const auto& [id, wpkFile] : cases)
    {
        addPendingWpk(id, wpkFile, goodSha1);
        ids.insert(id);
    }
    addPending(taskId(10), nlohmann::json {{"wpk_file", "good.wpk"}});
    ids.insert(taskId(10));

    const auto rootBefore {namesIn(m_root)};
    const auto upgradeBefore {namesIn(m_upgradeDir)};

    const auto stats {makeLinks()->backfill()};

    EXPECT_EQ(stats.staged, 0U);
    EXPECT_EQ(stats.expired, ids.size());
    EXPECT_TRUE(pendingIds().empty());
    EXPECT_EQ(m_store->agentTaskIds(REMOTE_UPGRADE).size(), ids.size());
    EXPECT_EQ(namesIn(m_root), rootBefore);
    EXPECT_EQ(namesIn(m_upgradeDir), upgradeBefore);
    EXPECT_EQ(namesIn(tasksDir()), std::set<std::string> {"x"});
}

TEST_F(TaskLinksTest, BackfillExpiresARowWhoseTaskFileIsNotRegular)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    fs::create_directories(tasksDir());
    addPendingWpk(taskId(1), "agent.wpk", sha1Of(wpk));
    fs::create_directory(taskFile(taskId(1)));

    const auto stats {makeLinks()->backfill()};

    EXPECT_EQ(stats.staged, 0U);
    EXPECT_EQ(stats.expired, 1U);
    EXPECT_TRUE(pendingIds().empty());
    EXPECT_TRUE(fs::is_directory(taskFile(taskId(1))));
}

TEST_F(TaskLinksTest, BackfillExpiresRowsWithUnusablePayloads)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    addPendingRaw(taskId(1), "not json");
    addPending(taskId(2), nlohmann::json {{"wpk_file", 5}, {"wpk_sha1", sha1Of(wpk)}});
    addPending(taskId(3), nlohmann::json {{"wpk_file", "agent.wpk"}, {"wpk_sha1", 5}});

    BackfillStats stats {};
    EXPECT_NO_THROW(stats = makeLinks()->backfill());

    EXPECT_EQ(stats.staged, 0U);
    EXPECT_EQ(stats.expired, 3U);
    EXPECT_TRUE(pendingIds().empty());
}

TEST_F(TaskLinksTest, BackfillDoesNotBlockOnAFifo)
{
    ASSERT_EQ(::mkfifo((m_upgradeDir / "agent.fifo").c_str(), 0600), 0);
    addPendingWpk(taskId(1), "agent.fifo", std::string(40, 'a'));

    const auto stats {makeLinks()->backfill()};

    EXPECT_EQ(stats.staged, 0U);
    EXPECT_EQ(stats.expired, 1U);
    EXPECT_TRUE(pendingIds().empty());
}

TEST_F(TaskLinksTest, BackfillExpiresARowWhoseWpkChangesBeforeItsLink)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    addPendingWpk(taskId(1), "agent.wpk", sha1Of(wpk));

    const auto swapThenLink {[this](int oldFd, const char* oldPath, int newFd, const char* newPath, int flags)
                             {
                                 writeFile(m_upgradeDir / "agent.new", "WPK-SWAPPED");
                                 fs::rename(m_upgradeDir / "agent.new", m_upgradeDir / "agent.wpk");
                                 return ::linkat(oldFd, oldPath, newFd, newPath, flags);
                             }};

    const auto stats {makeLinks(swapThenLink)->backfill()};

    EXPECT_EQ(stats.staged, 0U);
    EXPECT_EQ(stats.expired, 1U);
    EXPECT_TRUE(pendingIds().empty());
    EXPECT_FALSE(fs::exists(taskFile(taskId(1))));
}

TEST_F(TaskLinksTest, BackfillWithAFailedFsyncKeepsRowsPending)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    addPendingWpk(taskId(1), "agent.wpk", sha1Of(wpk), "001");
    addPendingWpk(taskId(2), "absent.wpk", sha1Of(wpk));

    const auto stats {makeLinks({}, failingFsync())->backfill()};

    EXPECT_EQ(stats.staged, 1U);
    EXPECT_EQ(stats.expired, 1U);
    EXPECT_EQ(pendingIds(), std::set<std::string> {taskId(1)});
    EXPECT_TRUE(fs::is_regular_file(taskFile(taskId(1))));
}

TEST_F(TaskLinksTest, BackfillLeavesStagedAndNonPendingRowsAlone)
{
    const auto wpk {makeWpk("agent.wpk", "WPK-A")};
    const auto sha1 {sha1Of(wpk)};
    makeLinks()->linkAndCommit({{taskId(1), "agent.wpk"}}, noCommit);
    addPendingWpk(taskId(1), "agent.wpk", sha1, "001");
    addPendingWpk(taskId(2), "agent.wpk", sha1, "002");
    ASSERT_EQ(m_store->takePendingAgentTasks("002", 10).size(), 1U);
    const auto stagedInode {inodeOf(taskFile(taskId(1)))};

    const auto stats {makeLinks()->backfill()};

    EXPECT_EQ(stats.staged, 0U);
    EXPECT_EQ(stats.expired, 0U);
    EXPECT_EQ(pendingIds(), std::set<std::string> {taskId(1)});
    EXPECT_EQ(inodeOf(taskFile(taskId(1))), stagedInode);
    EXPECT_FALSE(fs::exists(taskFile(taskId(2))));
    EXPECT_EQ(m_store->agentTaskIds(REMOTE_UPGRADE).size(), 2U);
}
