/*
 * Wazuh remoted module - CA bundle publication record unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises CaPublicationRecord on its own: load()'s five statuses (issue #39319, C23), the
 * atomic-replace write (temporary, fsync, fchmod, rename, directory fsync -- C22) and its failure
 * paths through the injectable RecordIo seam, since root (this suite's usual runner) ignores the
 * permission tricks that would otherwise be needed to fail a write for real.
 */

#include <gtest/gtest.h>

#include "http_server/caPublicationRecord.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using remoted::http::CaPublicationRecord;
using remoted::http::Entry;
using remoted::http::LoadOutcome;
using remoted::http::RecordIo;

namespace
{
    /// Throwaway directory, removed with everything under it on scope exit -- including the
    /// temporaries and `record.json` this class writes on its own, which is why cleanup is
    /// recursive rather than a list of paths the test tracked itself (the downloadEndpoint_test.cpp
    /// mold, adapted: mkdtemp for per-instance/per-process uniqueness, std::filesystem for teardown).
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = "/tmp/wazuh-ca-record-test-XXXXXX";
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');

            const char* created = ::mkdtemp(buffer.data());
            if (created == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for the publication record test's scratch directory");
            }
            m_path = created;
        }

        ~TempDir()
        {
            std::error_code ignored;
            std::filesystem::remove_all(m_path, ignored);
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::string& path() const
        {
            return m_path;
        }

    private:
        std::string m_path;
    };

    void writeFile(const std::string& path, const std::string& contents)
    {
        std::ofstream out {path, std::ios::binary | std::ios::trunc};
        out << contents;
    }

    std::string readFile(const std::string& path)
    {
        std::ifstream in {path, std::ios::binary};
        return {std::istreambuf_iterator<char> {in}, std::istreambuf_iterator<char> {}};
    }

    /// Restores the process umask on scope exit, so a test that sets one for a single store() call
    /// cannot leak it into whatever runs after -- even through an early ASSERT return.
    class UmaskGuard
    {
    public:
        explicit UmaskGuard(mode_t mask)
            : m_previous {::umask(mask)}
        {
        }
        ~UmaskGuard()
        {
            ::umask(m_previous);
        }
        UmaskGuard(const UmaskGuard&) = delete;
        UmaskGuard& operator=(const UmaskGuard&) = delete;

    private:
        mode_t m_previous;
    };
} // namespace

TEST(CaPublicationRecord, LoadReturnsAbsentWhenTheFileIsMissing)
{
    TempDir dir;
    CaPublicationRecord record {dir.path() + "/record.json"};

    LoadOutcome outcome;
    EXPECT_NO_THROW(outcome = record.load(dir.path() + "/bundle.pem"));

    EXPECT_EQ(outcome.status, LoadOutcome::Status::absent);
    EXPECT_EQ(outcome.error, 0);
}

TEST(CaPublicationRecord, StoreThenLoadRoundTripsWithMode0640)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/record.json";
    const auto bundlePath = dir.path() + "/bundle.pem";
    CaPublicationRecord record {recordPath};

    const Entry entry {bundlePath, "deadbeefcafe", 1789000000};
    ASSERT_TRUE(record.store(entry));
    EXPECT_EQ(record.lastError(), 0);

    const auto outcome = record.load(bundlePath);
    ASSERT_EQ(outcome.status, LoadOutcome::Status::ok);
    EXPECT_EQ(outcome.entry.bundlePath, bundlePath);
    EXPECT_EQ(outcome.entry.fileSha256, "deadbeefcafe");
    EXPECT_EQ(outcome.entry.publication, 1789000000);

    struct stat info
    {
    };
    ASSERT_EQ(::stat(recordPath.c_str(), &info), 0);
    EXPECT_EQ(info.st_mode & 0777, 0640U);

    // No `.tmp.<pid>.<n>` sibling left behind by a successful store().
    for (const auto& entryInDir : std::filesystem::directory_iterator {dir.path()})
    {
        EXPECT_EQ(entryInDir.path().filename().string().find(".tmp."), std::string::npos) << entryInDir.path();
    }
}

TEST(CaPublicationRecord, LoadRejectsMalformedTypedAndOversizedEntries)
{
    TempDir dir;
    const auto bundlePath = dir.path() + "/bundle.pem";

    // A field with the wrong JSON type: never parsed as a publication of 0 for this bundle.
    {
        const auto recordPath = dir.path() + "/wrong_type.json";
        writeFile(recordPath, R"({"version":1,"bundle_path":123,"file_sha256":"deadbeef","publication":0})");
        CaPublicationRecord record {recordPath};
        EXPECT_EQ(record.load(bundlePath).status, LoadOutcome::Status::malformed);
    }

    // A well-typed document, but a field that is not a real hash/path (kept simple: an empty
    // hash is refused too, see CaPublicationRecord::load()'s emptiness checks).
    {
        const auto recordPath = dir.path() + "/empty_hash.json";
        writeFile(recordPath,
                  R"({"version":1,"bundle_path":"/etc/certs/root-ca.pem","file_sha256":"","publication":0})");
        CaPublicationRecord record {recordPath};
        EXPECT_EQ(record.load(bundlePath).status, LoadOutcome::Status::malformed);
    }

    // Past kMaxBytes: not something this class ever wrote, refused whole rather than parsed.
    {
        const auto recordPath = dir.path() + "/oversized.json";
        writeFile(recordPath, std::string(CaPublicationRecord::kMaxBytes + 1, 'x'));
        CaPublicationRecord record {recordPath};
        EXPECT_EQ(record.load(bundlePath).status, LoadOutcome::Status::malformed);
    }
}

TEST(CaPublicationRecord, RecordPathAliasingBundleIsRejected)
{
    TempDir dir;
    const auto bundlePath = dir.path() + "/bundle.pem";
    writeFile(bundlePath, "not a record -- the CA bundle itself");

    // The exact same path.
    {
        CaPublicationRecord record {bundlePath};
        const auto outcome = record.load(bundlePath);
        EXPECT_EQ(outcome.status, LoadOutcome::Status::foreign_path);
        EXPECT_EQ(outcome.error, EINVAL);

        EXPECT_FALSE(record.store(Entry {bundlePath, "hash", 1}));
        EXPECT_EQ(record.lastError(), EINVAL);
        EXPECT_EQ(readFile(bundlePath), "not a record -- the CA bundle itself"); // untouched
    }

    // A symlink that resolves to the bundle: still an alias, still refused.
    {
        const auto alias = dir.path() + "/alias.json";
        ASSERT_EQ(::symlink(bundlePath.c_str(), alias.c_str()), 0);
        CaPublicationRecord record {alias};
        EXPECT_EQ(record.load(bundlePath).status, LoadOutcome::Status::foreign_path);
        EXPECT_FALSE(record.store(Entry {bundlePath, "hash", 1}));
        EXPECT_EQ(readFile(bundlePath), "not a record -- the CA bundle itself");
    }
}

TEST(CaPublicationRecord, ForeignPathRecordIsIgnored)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/record.json";
    const auto bundlePath = dir.path() + "/bundle.pem";
    const auto otherBundlePath = dir.path() + "/other.pem";

    CaPublicationRecord record {recordPath};
    ASSERT_TRUE(record.store(Entry {otherBundlePath, "deadbeef", 42}));

    // The record is real and readable; it just does not describe THIS bundle.
    const auto outcome = record.load(bundlePath);
    EXPECT_EQ(outcome.status, LoadOutcome::Status::foreign_path);
    EXPECT_EQ(outcome.entry.publication, 0); // default-constructed: nothing lent to this bundle
    EXPECT_TRUE(outcome.entry.bundlePath.empty());
}

TEST(CaPublicationRecord, StoreFailsWhenTheDirectoryDoesNotExistAndExposesErrno)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/missing-subdir/record.json";
    CaPublicationRecord record {recordPath};

    EXPECT_FALSE(record.store(Entry {dir.path() + "/bundle.pem", "hash", 1}));
    EXPECT_EQ(record.lastError(), ENOENT);
}

TEST(CaPublicationRecord, StoreRecoversOnceTheDirectoryExists)
{
    TempDir dir;
    const auto subdir = dir.path() + "/subdir";
    const auto recordPath = subdir + "/record.json";
    const Entry entry {dir.path() + "/bundle.pem", "hash", 1};
    CaPublicationRecord record {recordPath};

    ASSERT_FALSE(record.store(entry));
    ASSERT_EQ(record.lastError(), ENOENT);

    ASSERT_EQ(::mkdir(subdir.c_str(), 0750), 0);

    EXPECT_TRUE(record.store(entry));
    EXPECT_EQ(record.lastError(), 0);
}

TEST(CaPublicationRecord, StoreEnforcesModeUnderRestrictiveAndPermissiveUmask)
{
    TempDir dir;
    const Entry entry {dir.path() + "/bundle.pem", "hash", 1};

    for (const mode_t mask : {mode_t {0077}, mode_t {0000}})
    {
        const auto recordPath = dir.path() + "/record_" + std::to_string(mask) + ".json";
        {
            UmaskGuard guard {mask};
            CaPublicationRecord record {recordPath};
            ASSERT_TRUE(record.store(entry));
        }

        struct stat info
        {
        };
        ASSERT_EQ(::stat(recordPath.c_str(), &info), 0);
        // fchmod(0640) is explicit in the code, never the umask-adjusted mode open(2) would have
        // left on the temporary (objection 14): both a hostile and a wide-open umask land the same.
        EXPECT_EQ(info.st_mode & 0777, 0640U) << "umask " << std::oct << mask;
    }
}

TEST(CaPublicationRecord, WriteFailurePreservesPreviousRecord)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/record.json";
    const auto bundlePath = dir.path() + "/bundle.pem";

    CaPublicationRecord good {recordPath};
    ASSERT_TRUE(good.store(Entry {bundlePath, "first-hash", 1}));

    RecordIo failing;
    failing.write = [](int /*fd*/, const void* /*data*/, std::size_t /*bytes*/) -> ssize_t
    {
        errno = EIO;
        return -1; // the whole entry never lands on the temporary
    };
    CaPublicationRecord broken {recordPath, failing};

    EXPECT_FALSE(broken.store(Entry {bundlePath, "second-hash", 2}));
    EXPECT_EQ(broken.lastError(), EIO);

    // The record a caller reads next is still the one written before the failing attempt.
    const auto outcome = good.load(bundlePath);
    ASSERT_EQ(outcome.status, LoadOutcome::Status::ok);
    EXPECT_EQ(outcome.entry.fileSha256, "first-hash");
    EXPECT_EQ(outcome.entry.publication, 1);

    for (const auto& entryInDir : std::filesystem::directory_iterator {dir.path()})
    {
        EXPECT_EQ(entryInDir.path().filename().string().find(".tmp."), std::string::npos) << entryInDir.path();
    }
}

TEST(CaPublicationRecord, DirectorySyncFailureIsReported)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/record.json";
    const auto bundlePath = dir.path() + "/bundle.pem";

    RecordIo io;
    io.sync = [](int fd, bool directory) -> int
    {
        if (directory)
        {
            errno = EIO;
            return -1; // only the DIRECTORY's flush is refused; the temporary's own fsync is real
        }
        return ::fsync(fd);
    };
    CaPublicationRecord record {recordPath, io};

    // true: the rename already landed. lastError() carries the durability warning separately.
    EXPECT_TRUE(record.store(Entry {bundlePath, "hash", 7}));
    EXPECT_EQ(record.lastError(), EIO);

    CaPublicationRecord plain {recordPath};
    const auto outcome = plain.load(bundlePath);
    ASSERT_EQ(outcome.status, LoadOutcome::Status::ok);
    EXPECT_EQ(outcome.entry.fileSha256, "hash");
    EXPECT_EQ(outcome.entry.publication, 7);
}

TEST(CaPublicationRecord, OrphanTemporaryDoesNotBlockNextStore)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/record.json";
    const auto bundlePath = dir.path() + "/bundle.pem";

    // A temporary a SIGKILLed writer (a different, and by now nonexistent, pid) left behind.
    const auto orphan = recordPath + ".tmp.999999.1";
    writeFile(orphan, "leftover from a killed writer");

    CaPublicationRecord record {recordPath};
    EXPECT_TRUE(record.store(Entry {bundlePath, "hash", 1}));
    EXPECT_EQ(record.lastError(), 0);

    // This feature removes only the temporary IT created; another process's leftover is untouched.
    EXPECT_EQ(readFile(orphan), "leftover from a killed writer");
}

TEST(CaPublicationRecord, ConcurrentStoresUseDistinctTemporaries)
{
    TempDir dir;
    const auto recordPath = dir.path() + "/record.json";
    const auto bundlePath = dir.path() + "/bundle.pem";

    // Same object, same path, same pid: only the per-attempt counter (m_attempt) can keep the two
    // temporaries from sharing a name, which is what O_EXCL would otherwise refuse outright.
    std::atomic<int> started {0};
    RecordIo io;
    io.write = [&started](int fd, const void* data, std::size_t bytes) -> ssize_t
    {
        if (++started == 1)
        {
            // Hold this temporary open until the other call has opened its own: the collision this
            // test is about can only happen while both are on disk at once.
            while (started.load() < 2)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds {1});
            }
        }
        return ::write(fd, data, bytes);
    };
    CaPublicationRecord record {recordPath, io};

    std::atomic<bool> okA {false};
    std::atomic<bool> okB {false};
    std::thread a {[&]
                   {
                       okA = record.store(Entry {bundlePath, "hash-a", 1});
                   }};
    std::thread b {[&]
                   {
                       okB = record.store(Entry {bundlePath, "hash-b", 2});
                   }};
    a.join();
    b.join();

    // Neither refused with EEXIST because of a shared temporary name -- the one thing a race on a
    // single counter would produce.
    EXPECT_TRUE(okA.load());
    EXPECT_TRUE(okB.load());

    // Whichever rename() landed last, the record is a coherent, fully-written one (D22 defers
    // rejecting the loser; this test is only about the temporaries never colliding).
    const auto outcome = record.load(bundlePath);
    ASSERT_EQ(outcome.status, LoadOutcome::Status::ok);
    EXPECT_TRUE(outcome.entry.fileSha256 == "hash-a" || outcome.entry.fileSha256 == "hash-b")
        << outcome.entry.fileSha256;
}
