/*
 * Wazuh manager certs tool - unit tests for the write transaction
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// In-process tests of the three pieces `add` is built from (plan-E7a, `anexos/e7/escritura-atomica.md`):
// BundleWriteLock, atomicWrite() and the prepareWrite()/runAdd()/finishWrite() transaction. Unlike
// the inspect/check suite next door, these DO touch the filesystem -- the whole point of the code
// under test is what it does to a file -- but always inside a throwaway directory of their own,
// never a manager home, and always over PKI built in memory (../testPki.hpp).
//
// Three properties every rejection case here asserts, because they are the contract (RF-8/CA-19):
// the exit code, the message an operator reads, and the bundle's SHA-256 being unchanged.
//
// Everything that writes needs the process to be root: the lock file has to be root-owned (C36f),
// which is true in production (G0 refuses anything else) and in the CI containers, and a developer
// running the binary as themselves gets a skip instead of a failure.

#include "commands/atomicWrite.hpp"
#include "commands/writeLock.hpp"
#include "manager_certs/commands.hpp"
#include "testPki.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using manager_certs::atomicWrite;
using manager_certs::AtomicWriteOutcome;
using manager_certs::BundleWriteLock;
using manager_certs::bytesSha256;
using manager_certs::DestinationImage;
using manager_certs::finishWrite;
using manager_certs::IoPort;
using manager_certs::LockIo;
using manager_certs::prepareWrite;
using manager_certs::runAdd;
using manager_certs::TimeSource;
using manager_certs::WriteContext;
using manager_certs::writeEnvironmentFailure;
using manager_certs::WriteRequest;
using manager_certs::test::makeCertificate;
using manager_certs::test::makeTestKey;

namespace
{
    constexpr long kDay = 24L * 60L * 60L;
    constexpr const char* kBundleName = "root-ca.pem";

/// Every case that opens the transaction needs a root-owned lock file (C36f).
#define SKIP_UNLESS_ROOT()                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::geteuid() != 0)                                                                                          \
        {                                                                                                              \
            GTEST_SKIP() << "the write transaction requires a root-owned lock file (euid 0)";                          \
        }                                                                                                              \
    } while (false)

    /// A temporary directory (mkdtemp), removed recursively when it goes out of scope. Same shape as
    /// managerCerts_test.cpp's: a copy rather than a shared header, because the two suites share no
    /// fixtures beyond ../testPki.hpp and one of them barely touches disk at all.
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = (std::filesystem::temp_directory_path() / "manager_certs_write_XXXXXX").string();
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');
            if (mkdtemp(buffer.data()) == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for manager_certs_utest write fixtures");
            }
            m_path = buffer.data();
        }
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        ~TempDir()
        {
            std::error_code ec;
            std::filesystem::remove_all(m_path, ec);
        }

        const std::filesystem::path& path() const
        {
            return m_path;
        }

    private:
        std::filesystem::path m_path;
    };

    std::string readFile(const std::filesystem::path& path)
    {
        std::ifstream file {path, std::ios::binary};
        std::ostringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    void writeFile(const std::filesystem::path& path, const std::string& content)
    {
        std::ofstream file {path, std::ios::binary};
        file << content;
    }

    std::string sha256Of(const std::filesystem::path& path)
    {
        return bytesSha256(readFile(path));
    }

    /// Temporaries left behind in @p directory for @p name. Anything this tool creates and does not
    /// publish has to be removed; anything it did not create has to survive.
    std::size_t temporaryCount(const std::filesystem::path& directory, const std::string& name)
    {
        std::size_t found {0};
        for (const auto& entry : std::filesystem::directory_iterator {directory})
        {
            const std::string file = entry.path().filename().string();
            if (file.rfind(name + ".tmp.", 0) == 0)
            {
                ++found;
            }
        }
        return found;
    }

    ca_bundle::PublicationBlock blockFor(const std::vector<ca_bundle::X509Ptr>& certificates, std::int64_t publication)
    {
        ca_bundle::PublicationBlock block;
        block.publication = publication;
        block.contentSha256 = ca_bundle::contentSha256(certificates);
        block.updated = "2026-09-19T00:00:00Z";
        block.writtenBy = "manager_certs_utest fixture";
        return block;
    }

    /// The exact shape `wazuh-manager-certs` writes: the block, then the certificates.
    std::string sealedBundleText(const std::vector<ca_bundle::X509Ptr>& certificates, std::int64_t publication)
    {
        return ca_bundle::renderBlock(blockFor(certificates, publication)) +
               ca_bundle::serializeCertificates(certificates);
    }

    /// A programmable clock. `sleeps` is what proves a case went through the wait of C28b (or did
    /// not), and `onSleep` is how a test makes the wall clock jump backwards, stand still, or let
    /// real time pass while the tool is waiting.
    struct TestClock
    {
        std::time_t wall {0};
        std::int64_t monotonic {0};
        int sleeps {0};
        std::function<void(TestClock&)> onSleep {};
    };

    TimeSource sourceFor(TestClock& clock)
    {
        TimeSource source;
        source.now = [&clock]()
        {
            return clock.wall;
        };
        source.monotonicNow = [&clock]()
        {
            return clock.monotonic;
        };
        source.sleepUntilNextSecond = [&clock]()
        {
            ++clock.sleeps;
            ++clock.monotonic;
            if (clock.onSleep)
            {
                clock.onSleep(clock);
            }
            else
            {
                ++clock.wall;
            }
        };
        return source;
    }

    WriteRequest requestFor(const std::filesystem::path& bundlePath, const X509* leaf, TestClock& clock)
    {
        WriteRequest request;
        request.command = "add";
        request.bundlePath = bundlePath;
        request.leaf = leaf;
        request.writtenBy = "manager_certs_utest";
        request.time = sourceFor(clock);
        return request;
    }

    /// One certificate as PEM -- what an operator hands to `add`.
    std::string pemOf(const X509* certificate)
    {
        std::vector<ca_bundle::X509Ptr> one;
        one.push_back(manager_certs::test::retain(certificate));
        return ca_bundle::serializeCertificates(one);
    }

    /// The destination as prepareWrite() would have read it, for the cases that exercise
    /// atomicWrite() on its own (no PKI, no lock, no clock involved).
    DestinationImage imageOf(const std::filesystem::path& path)
    {
        DestinationImage image;
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
        {
            throw std::runtime_error("cannot open the fixture destination");
        }
        struct stat attributes {};
        if (::fstat(fd, &attributes) != 0)
        {
            ::close(fd);
            throw std::runtime_error("cannot stat the fixture destination");
        }
        ::close(fd);
        image.device = attributes.st_dev;
        image.inode = attributes.st_ino;
        image.owner = attributes.st_uid;
        image.group = attributes.st_gid;
        image.mode = attributes.st_mode & 07777;
        image.sha256 = sha256Of(path);
        return image;
    }

    /// Owns a directory descriptor for a case's lifetime.
    class DirFd
    {
    public:
        explicit DirFd(const std::filesystem::path& path)
            : m_fd {::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)}
        {
            if (m_fd < 0)
            {
                throw std::runtime_error("cannot open the fixture directory");
            }
        }
        DirFd(const DirFd&) = delete;
        DirFd& operator=(const DirFd&) = delete;
        ~DirFd()
        {
            ::close(m_fd);
        }
        int get() const
        {
            return m_fd;
        }

    private:
        int m_fd;
    };

    /// Adds a (non-critical, ignored by every verifier) comment extension of @p bytes characters to
    /// @p certificate and re-signs it: the cheapest way to build a certificate big enough to push a
    /// bundle past the serialised byte cap. A long subject would not do it -- OpenSSL silently
    /// refuses an oversized name entry and leaves the certificate small.
    void inflateAndResign(X509* certificate, EVP_PKEY* signerKey, std::size_t bytes)
    {
        const std::string comment(bytes, 'x');
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, certificate, certificate, nullptr, nullptr, 0);
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &ctx, NID_netscape_comment, comment.c_str());
        if (extension == nullptr)
        {
            throw std::runtime_error("could not build the padding extension");
        }
        const int added = X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
        if (added != 1 || X509_sign(certificate, signerKey, EVP_sha256()) == 0)
        {
            throw std::runtime_error("could not inflate a test certificate");
        }
    }

    /// Rewrites @p certificate's notBefore with bytes that are not an ASN.1 time at all, and
    /// re-signs it: a certificate OpenSSL still parses, whose date ca_bundle::describe() can only
    /// report as 0 -- the exact case G3 must not accept as "1970, therefore valid" (C36g).
    void breakNotBeforeAndResign(X509* certificate, EVP_PKEY* signerKey)
    {
        ASN1_TIME* notBefore = X509_getm_notBefore(certificate);
        if (ASN1_STRING_set(notBefore, "not-a-time-at-all", 17) != 1)
        {
            throw std::runtime_error("could not plant a malformed notBefore");
        }
        if (X509_sign(certificate, signerKey, EVP_sha256()) == 0)
        {
            throw std::runtime_error("could not re-sign a certificate with a malformed notBefore");
        }
    }

} // namespace

// ================================================================== BundleWriteLock ==============

TEST(BundleWriteLock, SecondAcquireBlocksUntilFirstReleases)
{
    SKIP_UNLESS_ROOT();
    TempDir dir;
    const DirFd directory {dir.path()};
    const std::string name = std::string {kBundleName} + ".lock";
    const std::string display = (dir.path() / name).string();

    auto first = BundleWriteLock::acquire(directory.get(), name, display);
    ASSERT_TRUE(first.lock.has_value()) << first.message;

    std::atomic<bool> entered {false};
    std::atomic<bool> acquired {false};
    std::thread second(
        [&]()
        {
            entered = true;
            auto attempt = BundleWriteLock::acquire(directory.get(), name, display);
            acquired = attempt.lock.has_value();
        });

    // Long enough for the second acquire to have reached flock() and blocked there.
    while (!entered)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    }
    std::this_thread::sleep_for(std::chrono::milliseconds {200});
    EXPECT_FALSE(acquired) << "the second writer entered while the first still held the lock";

    first.lock.reset();
    second.join();
    EXPECT_TRUE(acquired) << "the second writer never got the lock after it was released";
}

TEST(BundleWriteLock, RejectsSymlinkedOrNonRootLockFile)
{
    TempDir dir;
    const DirFd directory {dir.path()};

    // A symlink where the lock file belongs: O_NOFOLLOW turns it into ELOOP instead of locking
    // whatever it points at (which the certs directory's mode 1770 lets a group member plant).
    const std::string linked = "linked.lock";
    writeFile(dir.path() / "target", "");
    std::filesystem::create_symlink("target", dir.path() / linked);
    auto symlinked = BundleWriteLock::acquire(directory.get(), linked, (dir.path() / linked).string());
    EXPECT_FALSE(symlinked.lock.has_value());
    EXPECT_NE(symlinked.message.find("symlink"), std::string::npos) << symlinked.message;

    // A regular file owned by somebody else.
    const std::string planted = "planted.lock";
    writeFile(dir.path() / planted, "");
    if (::geteuid() == 0)
    {
        ASSERT_EQ(::chown((dir.path() / planted).c_str(), 12345, 12345), 0);
    }
    auto foreign = BundleWriteLock::acquire(directory.get(), planted, (dir.path() / planted).string());
    EXPECT_FALSE(foreign.lock.has_value());
    EXPECT_NE(foreign.message.find("root-owned regular file"), std::string::npos) << foreign.message;
}

TEST(BundleWriteLock, DetectsReplacedLockIdentityAfterBlocking)
{
    SKIP_UNLESS_ROOT();
    TempDir dir;
    const DirFd directory {dir.path()};
    const std::string name = std::string {kBundleName} + ".lock";

    // The seam stands in for "somebody replaced the lock file while this process was blocked in
    // flock()": by the time the lock is held, the path names a different inode, so two writers
    // would be excluding nobody (objection 10 / C36f).
    bool replaced {false};
    LockIo io;
    io.flock = [&](int fd, int operation)
    {
        if (operation == LOCK_EX && !replaced)
        {
            replaced = true;
            ::unlinkat(directory.get(), name.c_str(), 0);
            const int fresh = ::openat(directory.get(), name.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
            if (fresh >= 0)
            {
                ::close(fresh);
            }
        }
        return ::flock(fd, operation);
    };

    auto attempt = BundleWriteLock::acquire(directory.get(), name, (dir.path() / name).string(), io);
    EXPECT_TRUE(replaced);
    EXPECT_FALSE(attempt.lock.has_value());
    EXPECT_NE(attempt.message.find("identity changed"), std::string::npos) << attempt.message;
}

TEST(BundleWriteLock, RetriesOnInterruptedFlockAndReportsARealFailure)
{
    SKIP_UNLESS_ROOT();
    TempDir dir;
    const DirFd directory {dir.path()};
    const std::string name = std::string {kBundleName} + ".lock";
    const std::string display = (dir.path() / name).string();

    int calls {0};
    LockIo interrupted;
    interrupted.flock = [&](int fd, int operation)
    {
        ++calls;
        if (calls == 1)
        {
            errno = EINTR;
            return -1;
        }
        return ::flock(fd, operation);
    };
    auto retried = BundleWriteLock::acquire(directory.get(), name, display, interrupted);
    EXPECT_TRUE(retried.lock.has_value()) << retried.message;
    EXPECT_GE(calls, 2);
    retried.lock.reset();

    LockIo refused;
    refused.flock = [](int, int)
    {
        errno = ENOLCK;
        return -1;
    };
    auto failed = BundleWriteLock::acquire(directory.get(), name, display, refused);
    EXPECT_FALSE(failed.lock.has_value());
    EXPECT_EQ(failed.error, ENOLCK);
    EXPECT_NE(failed.message.find("cannot lock"), std::string::npos) << failed.message;
}

// ====================================================================== atomicWrite ==============

TEST(AtomicWrite, PublishesAndPreservesOwnerAndMode)
{
    TempDir dir;
    const DirFd directory {dir.path()};
    const auto path = dir.path() / kBundleName;
    writeFile(path, "old contents\n");
    ASSERT_EQ(::chmod(path.c_str(), 0640), 0);

    const DestinationImage image = imageOf(path);
    const AtomicWriteOutcome outcome = atomicWrite(directory.get(), kBundleName, "new contents\n", image, IoPort {});

    EXPECT_TRUE(outcome.written) << outcome.message;
    EXPECT_FALSE(outcome.durabilityUnknown);
    EXPECT_EQ(readFile(path), "new contents\n");
    struct stat attributes {};
    ASSERT_EQ(::stat(path.c_str(), &attributes), 0);
    EXPECT_EQ(attributes.st_mode & 07777, 0640u);
    EXPECT_EQ(temporaryCount(dir.path(), kBundleName), 0u);
}

TEST(AtomicWrite, AbortsWhenDestinationChangedSincePrepareRead)
{
    TempDir dir;
    const DirFd directory {dir.path()};
    const auto path = dir.path() / kBundleName;
    writeFile(path, "read under the lock\n");

    const DestinationImage image = imageOf(path);

    // Somebody who did not take the lock (an operator's editor, the installer) replaces the file
    // between the read and the publish. Overwriting it here would throw their change away.
    writeFile(path, "written by somebody else\n");
    const std::string foreign = readFile(path);

    const AtomicWriteOutcome outcome = atomicWrite(directory.get(), kBundleName, "ours\n", image, IoPort {});

    EXPECT_FALSE(outcome.written);
    EXPECT_NE(outcome.message.find("destination changed since it was read"), std::string::npos) << outcome.message;
    EXPECT_EQ(readFile(path), foreign);
    EXPECT_EQ(temporaryCount(dir.path(), kBundleName), 0u);
}

TEST(AtomicWrite, RandomNonceAvoidsPidCounterExhaustion)
{
    TempDir dir;
    const DirFd directory {dir.path()};
    const auto path = dir.path() / kBundleName;
    writeFile(path, "generation 0\n");

    // Exactly what a crashed run of the naming scheme this replaced would leave behind: every
    // `<name>.tmp.<pid>.<0..9>` taken, which O_EXCL would then refuse ten times out of ten.
    for (int index = 0; index < 10; ++index)
    {
        writeFile(dir.path() /
                      (std::string {kBundleName} + ".tmp." + std::to_string(::getpid()) + "." + std::to_string(index)),
                  "leftover\n");
    }

    for (int generation = 1; generation <= 10; ++generation)
    {
        const DestinationImage image = imageOf(path);
        const std::string contents = "generation " + std::to_string(generation) + "\n";
        const AtomicWriteOutcome outcome = atomicWrite(directory.get(), kBundleName, contents, image, IoPort {});
        ASSERT_TRUE(outcome.written) << "generation " << generation << ": " << outcome.message;
        ASSERT_EQ(readFile(path), contents);
    }

    // Ten leftovers still there: a temporary this process did not create is never removed.
    EXPECT_EQ(temporaryCount(dir.path(), kBundleName), 10u);
}

TEST(AtomicWrite, ConcurrentReaderSeesOnlyCompleteOldOrNewFile)
{
    TempDir dir;
    const DirFd directory {dir.path()};
    const auto path = dir.path() / kBundleName;
    const std::string oldContents(64U * 1024U, 'o');
    const std::string newContents(64U * 1024U, 'n');
    writeFile(path, oldContents);

    std::atomic<bool> writing {true};
    std::atomic<int> reads {0};
    std::atomic<bool> sawPartial {false};

    std::thread reader(
        [&]()
        {
            while (writing)
            {
                const std::string seen = readFile(path);
                ++reads;
                if (seen != oldContents && seen != newContents)
                {
                    sawPartial = true;
                }
            }
        });

    // The reader has to be reading BEFORE the first write, or a 64 KiB replacement finishes while
    // the thread is still starting up and this case proves nothing (it asserted zero reads once,
    // under a mutation run). Twenty alternating writes then give it a real window.
    while (reads.load() == 0)
    {
        std::this_thread::yield();
    }

    bool written {true};
    for (int round = 0; round < 20 && written; ++round)
    {
        const DestinationImage image = imageOf(path);
        const std::string& contents = (round % 2 == 0) ? newContents : oldContents;
        const AtomicWriteOutcome outcome = atomicWrite(directory.get(), kBundleName, contents, image, IoPort {});
        written = outcome.written;
        EXPECT_TRUE(outcome.written) << outcome.message;
    }
    writing = false;
    reader.join();

    EXPECT_GT(reads.load(), 0);
    EXPECT_FALSE(sawPartial) << "a reader saw a half-written bundle";
    EXPECT_EQ(readFile(path), oldContents); // the twentieth round wrote this one
}

// The failure matrix of anexos/e7/escritura-atomica.md, one case per phase. Each one asserts the
// same three things: the outcome, the destination byte for byte as it was, and no temporary of ours
// left behind.
namespace
{
    struct WriteFailureCase
    {
        std::string name;
        IoPort io;
        int expectedError;
        std::string expectedMessage;
    };

    void expectRefusedWrite(const WriteFailureCase& testCase)
    {
        TempDir dir;
        const DirFd directory {dir.path()};
        const auto path = dir.path() / kBundleName;
        writeFile(path, "the bundle nobody may lose\n");
        const std::string before = readFile(path);
        const DestinationImage image = imageOf(path);

        const AtomicWriteOutcome outcome =
            atomicWrite(directory.get(), kBundleName, "replacement\n", image, testCase.io);

        EXPECT_FALSE(outcome.written) << testCase.name;
        EXPECT_EQ(outcome.error, testCase.expectedError) << testCase.name;
        EXPECT_NE(outcome.message.find(testCase.expectedMessage), std::string::npos)
            << testCase.name << ": " << outcome.message;
        EXPECT_EQ(readFile(path), before) << testCase.name;
        EXPECT_EQ(temporaryCount(dir.path(), kBundleName), 0u) << testCase.name;
    }
} // namespace

TEST(AtomicWrite, EveryFailureBeforeTheRenameLeavesTheDestinationIntact)
{
    {
        IoPort io;
        io.write = [](int, const void*, std::size_t)
        {
            errno = ENOSPC;
            return static_cast<ssize_t>(-1);
        };
        expectRefusedWrite({"write fails", io, ENOSPC, "cannot write the new bundle"});
    }
    {
        // No progress and no errno: the loop must refuse instead of spinning forever.
        IoPort io;
        io.write = [](int, const void*, std::size_t)
        {
            return static_cast<ssize_t>(0);
        };
        expectRefusedWrite({"write makes no progress", io, EIO, "no progress"});
    }
    {
        IoPort io;
        io.fsync = [](int, bool)
        {
            errno = EIO;
            return -1;
        };
        expectRefusedWrite({"fsync of the temporary fails", io, EIO, "cannot flush the new bundle ("});
    }
    {
        IoPort io;
        io.fchown = [](int, uid_t, gid_t)
        {
            errno = EPERM;
            return -1;
        };
        expectRefusedWrite({"fchown fails", io, EPERM, "cannot set the new bundle's owner"});
    }
    {
        IoPort io;
        io.fchmod = [](int, mode_t)
        {
            errno = EPERM;
            return -1;
        };
        expectRefusedWrite({"fchmod fails", io, EPERM, "cannot set the new bundle's mode"});
    }
    {
        // The SECOND fsync, the one that flushes owner and mode (step 7).
        auto calls = std::make_shared<int>(0);
        IoPort io;
        io.fsync = [calls](int fd, bool directory)
        {
            if (++(*calls) == 2)
            {
                errno = EIO;
                return -1;
            }
            return directory ? ::fsync(fd) : ::fsync(fd);
        };
        expectRefusedWrite({"second fsync fails", io, EIO, "cannot flush the new bundle's metadata"});
    }
    {
        IoPort io;
        io.close = [](int)
        {
            errno = EIO;
            return -1;
        };
        expectRefusedWrite({"checked close fails", io, EIO, "cannot close the new bundle"});
    }
    {
        IoPort io;
        io.renameat = [](int, const char*, int, const char*)
        {
            errno = EXDEV;
            return -1;
        };
        expectRefusedWrite({"renameat fails", io, EXDEV, "cannot publish the new bundle"});
    }
}

TEST(AtomicWrite, DirectoryFsyncFailureIsASuccessWithAWarning)
{
    TempDir dir;
    const DirFd directory {dir.path()};
    const auto path = dir.path() / kBundleName;
    writeFile(path, "old\n");
    const DestinationImage image = imageOf(path);

    // C31: the rename already happened and every reader sees the new file. Reporting failure here
    // would tell an operator to retry a write that did land.
    IoPort io;
    io.fsync = [](int fd, bool directory)
    {
        if (directory)
        {
            errno = EIO;
            return -1;
        }
        return ::fsync(fd);
    };

    const AtomicWriteOutcome outcome = atomicWrite(directory.get(), kBundleName, "new\n", image, io);

    EXPECT_TRUE(outcome.written);
    EXPECT_TRUE(outcome.durabilityUnknown);
    EXPECT_EQ(outcome.error, EIO);
    EXPECT_NE(outcome.message.find("directory could not be flushed"), std::string::npos) << outcome.message;
    EXPECT_EQ(readFile(path), "new\n");
    EXPECT_EQ(temporaryCount(dir.path(), kBundleName), 0u);
}

// ============================================================== environment guards (G0/G7) =======

TEST(ManagerCertsAdd, RejectedOnWorker)
{
    // G7 comes from the effective configuration alone, so it is answered before anything opens,
    // reads or locks the bundle -- there is no path in this call to open (C34c). That the binary
    // really does evaluate it that early (no lock file left behind on a worker) is asserted end to
    // end by tests/cli/manager_certs_cli_test.sh, which is the only thing that runs main.cpp.
    int exitCode {0};
    const std::string worker = writeEnvironmentFailure("add", 0, "worker", exitCode);
    // 2, not 1: exit 1 is reserved for material the operator handed over being rejected, and the
    // node's cluster role says nothing about the material.
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(worker.find("this node is a cluster worker"), std::string::npos) << worker;
    EXPECT_NE(worker.find("--from-master"), std::string::npos) << worker;

    const std::string nonRoot = writeEnvironmentFailure("add", 1000, "master", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(nonRoot.find("must run as root (euid 0)"), std::string::npos) << nonRoot;

    // A root process on a master node passes both, and says nothing.
    EXPECT_TRUE(writeEnvironmentFailure("add", 0, "master", exitCode).empty());
    EXPECT_EQ(exitCode, 0);
}

// ======================================================================= add ====================

namespace
{
    /// A bundle on disk (sealed, mode 0640), the CA it holds, and the leaf that CA signed -- the
    /// starting point of every `add` case below.
    struct AddFixture
    {
        TempDir dir;
        manager_certs::test::EvpPkeyPtr caKey;
        manager_certs::test::EvpPkeyPtr leafKey;
        ca_bundle::X509Ptr ca;
        ca_bundle::X509Ptr leaf;
        std::filesystem::path bundlePath;
        std::time_t base;
        TestClock clock;

        /// @param previousOffset seconds subtracted from now for the bundle's publication: 0 leaves
        ///        the current second EQUAL to it, which is what makes C28b wait; anything positive
        ///        publishes straight away.
        /// @param caNotAfterSeconds how long the bundle's only CA stays valid, from now.
        explicit AddFixture(long previousOffset = 0, long caNotAfterSeconds = 400 * kDay)
            : caKey {makeTestKey()}
            , leafKey {makeTestKey()}
            , ca {makeCertificate("ca-root", -kDay, caNotAfterSeconds, caKey.get(), caKey.get(), nullptr, true, 1)}
            , leaf {makeCertificate("leaf", -kDay, 90 * kDay, leafKey.get(), caKey.get(), ca.get(), false, 2)}
            , bundlePath {dir.path() / kBundleName}
            , base {std::time(nullptr)}
        {
            std::vector<ca_bundle::X509Ptr> certificates;
            certificates.push_back(manager_certs::test::retain(ca.get()));
            writeFile(bundlePath, sealedBundleText(certificates, static_cast<std::int64_t>(base) - previousOffset));
            if (::chmod(bundlePath.c_str(), 0640) != 0)
            {
                throw std::runtime_error("cannot set the fixture bundle's mode");
            }
            clock.wall = base;
        }
    };

    struct AddRun
    {
        int exitCode {0};
        std::string out;
        std::string err;
        std::int64_t publication {0};
    };

    AddRun runAddWith(AddFixture& fixture,
                      const X509* leaf,
                      const std::string& inputPem,
                      const std::filesystem::path& inputPath = "input.pem")
    {
        AddRun run;
        auto prepared = prepareWrite(requestFor(fixture.bundlePath, leaf, fixture.clock));
        if (!prepared.context)
        {
            run.exitCode = prepared.exitCode;
            run.err = prepared.message;
            return run;
        }
        std::ostringstream out;
        std::ostringstream err;
        run.exitCode = runAdd(*prepared.context, inputPem, inputPath, out, err);
        run.out = out.str();
        run.err = err.str();
        const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
        run.publication = written.block ? written.block->publication : 0;
        return run;
    }

    AddRun runAddOn(AddFixture& fixture, const std::string& inputPem)
    {
        return runAddWith(fixture, fixture.leaf.get(), inputPem);
    }

    /// A self-signed CA nobody else in a fixture knows about.
    ca_bundle::X509Ptr makeSpareCa(manager_certs::test::EvpPkeyPtr& key, const char* name, long serial)
    {
        return makeCertificate(name, -kDay, 400 * kDay, key.get(), key.get(), nullptr, true, serial);
    }
} // namespace

TEST(ManagerCertsAdd, InitialPreviousEqualsNowWaitsThenPublishesStrictlyHigher)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture; // the bundle's publication IS the current second
    auto firstKey = makeTestKey();
    auto secondKey = makeTestKey();
    const auto first = makeSpareCa(firstKey, "ca-second", 10);
    const auto second = makeSpareCa(secondKey, "ca-third", 11);

    const AddRun one = runAddOn(fixture, pemOf(first.get()));
    ASSERT_EQ(one.exitCode, 0) << one.err;
    EXPECT_EQ(fixture.clock.sleeps, 1) << "the first add published without waiting for the next second";
    EXPECT_EQ(one.publication, static_cast<std::int64_t>(fixture.base) + 1);

    // Back to back, in what the clock still reports as the same second it just published in: the
    // repro of objection 1 (first revision), where the second add used to be refused as "behind".
    const AddRun two = runAddOn(fixture, pemOf(second.get()));
    ASSERT_EQ(two.exitCode, 0) << two.err;
    EXPECT_EQ(fixture.clock.sleeps, 2);
    EXPECT_EQ(two.publication, static_cast<std::int64_t>(fixture.base) + 2);
    EXPECT_GT(two.publication, one.publication);

    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
    EXPECT_EQ(written.certificates.size(), 3u);
}

TEST(ManagerCertsAdd, PreviousZeroAlsoWaitsOnSameSecondReplacement)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture;
    // The bundle is replaced, in the same second it was published in, by a PLAIN PEM: its
    // publication falls to 0 (C30). Without the wait of C36e the next write would re-publish the
    // very same timestamp and no agent would ever adopt the change.
    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(manager_certs::test::retain(fixture.ca.get()));
    writeFile(fixture.bundlePath, ca_bundle::serializeCertificates(certificates));

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 12);

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    ASSERT_EQ(run.exitCode, 0) << run.err;
    EXPECT_EQ(fixture.clock.sleeps, 1) << "no previous publication is not a reason to skip the wait";
    EXPECT_EQ(run.publication, static_cast<std::int64_t>(fixture.base) + 1);
    EXPECT_NE(run.publication, static_cast<std::int64_t>(fixture.base));
}

TEST(ManagerCertsAdd, ClockBehindIsRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {-100}; // published 100 seconds into this clock's future
    const std::string before = sha256Of(fixture.bundlePath);
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 13);

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("clock is behind the current publication " + std::to_string(fixture.base + 100)),
              std::string::npos)
        << run.err;
    EXPECT_EQ(fixture.clock.sleeps, 0);
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, ClockRollbackDuringWaitIsRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture; // equal to the current second, so the wait happens
    // The wall clock goes backwards WHILE we wait (ntp, a hypervisor, an operator); the monotonic
    // one keeps advancing, which is what the bound is measured with (C36d).
    fixture.clock.onSleep = [](TestClock& clock)
    {
        clock.wall -= 5;
    };
    const std::string before = sha256Of(fixture.bundlePath);
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 14);

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_EQ(fixture.clock.sleeps, 1) << "the rejection has to come from the clock read AFTER the wait";
    EXPECT_NE(run.err.find("clock is behind the current publication"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, FrozenClockDoesNotHangTheCommand)
{
    SKIP_UNLESS_ROOT();
    // A wall clock that never advances (a stopped RTC, a paused VM) would keep a root command in
    // the wait of C28b forever. The monotonic reading is what bounds it, and the refusal says so.
    AddFixture fixture;
    fixture.clock.onSleep = [](TestClock&) {}; // sourceFor() still advances the monotonic clock
    const std::string before = sha256Of(fixture.bundlePath);

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 15);

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("the clock did not advance past " + std::to_string(fixture.base)), std::string::npos)
        << run.err;
    EXPECT_GT(fixture.clock.sleeps, 1) << "the bound has to be measured over several attempts, not one";
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, SeventhCertificateRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};

    // Six certificates in the file, the first of them the one that signs the leaf.
    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(manager_certs::test::retain(fixture.ca.get()));
    std::vector<manager_certs::test::EvpPkeyPtr> keys;
    for (int index = 0; index < 5; ++index)
    {
        keys.push_back(makeTestKey());
        certificates.push_back(makeSpareCa(keys.back(), ("ca-filler-" + std::to_string(index)).c_str(), 20 + index));
    }
    writeFile(fixture.bundlePath, sealedBundleText(certificates, static_cast<std::int64_t>(fixture.base) - 10));
    const std::string before = sha256Of(fixture.bundlePath);

    auto seventhKey = makeTestKey();
    const auto seventh = makeSpareCa(seventhKey, "ca-seventh", 30);
    const AddRun run = runAddOn(fixture, pemOf(seventh.get()));

    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("7 certificates (max 6)"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, EmptyCandidateRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    // Defensive (objection 9): no command should ever hand finishWrite() an empty candidate, and if
    // one does, publishing zero certificates would strand every agent that trusts this file.
    auto prepared = prepareWrite(requestFor(fixture.bundlePath, fixture.leaf.get(), fixture.clock));
    ASSERT_TRUE(prepared.context.has_value()) << prepared.message;
    const manager_certs::WriteOutcome outcome = finishWrite(*prepared.context, {});

    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_EQ(outcome.message, "add: 0 certificates");
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, OversizeRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    // One certificate padded past the serialised cap: the count guard (2 of 6) passes, the leaf
    // still chains to the bundle's own CA, and only the byte cap refuses it.
    auto hugeKey = makeTestKey();
    auto huge = makeSpareCa(hugeKey, "ca-huge", 40);
    inflateAndResign(huge.get(), hugeKey.get(), 8U * 1024U);
    const std::string input = pemOf(huge.get());
    ASSERT_GT(input.size(), ca_bundle::kMaxSerializedBytes) << "fixture too small to exercise the byte cap";

    const AddRun run = runAddOn(fixture, input);
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(" bytes (max " + std::to_string(ca_bundle::kMaxSerializedBytes) + ")"), std::string::npos)
        << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, LeavingLeafUnsignedRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    // The served leaf chains to a CA that is not in the bundle and is not being added either:
    // publishing this would hand agents an anchor none of them could verify the listener with.
    auto foreignCaKey = makeTestKey();
    auto foreignLeafKey = makeTestKey();
    const auto foreignCa = makeSpareCa(foreignCaKey, "foreign-ca", 50);
    const auto foreignLeaf = makeCertificate(
        "foreign-leaf", -kDay, 90 * kDay, foreignLeafKey.get(), foreignCaKey.get(), foreignCa.get(), false, 51);

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 52);

    const AddRun run = runAddWith(fixture, foreignLeaf.get(), pemOf(spare.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("no CA signs the served leaf"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, SignerExpiringDuringWaitRejectedAfterWait)
{
    SKIP_UNLESS_ROOT();
    // The only CA that chains to the leaf is valid for four more seconds of REAL time -- which is
    // the clock OpenSSL verifies chains against, whatever the injected wall clock says. The first
    // G6 pass (before the wait) accepts it; the wait outlives it; the second pass must not (C36d).
    AddFixture fixture {0, 4};
    fixture.clock.onSleep = [](TestClock& clock)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {5000});
        ++clock.wall;
    };
    const std::string before = sha256Of(fixture.bundlePath);

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 60);

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_EQ(fixture.clock.sleeps, 1) << "the first pass of G6 should have accepted the still-valid signer";
    EXPECT_NE(run.err.find("no CA signs the served leaf"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, AddedCertificateExpiringDuringWaitRejectedAfterWait)
{
    SKIP_UNLESS_ROOT();
    // The other half of C36d: G6 covers the CA that signs the leaf, G3 covers the ones this command
    // is adding. Here the wait is long enough (on this clock) to outlive the certificate the
    // operator handed us, while the bundle's own signer -- and therefore the chain -- stays valid,
    // so the ONLY guard that can refuse this is G3 re-evaluated after the wait.
    AddFixture fixture;
    fixture.clock.onSleep = [](TestClock& clock)
    {
        clock.wall += 10;
    };
    const std::string before = sha256Of(fixture.bundlePath);

    auto shortLivedKey = makeTestKey();
    const auto shortLived =
        makeCertificate("ca-short-lived", -kDay, 2, shortLivedKey.get(), shortLivedKey.get(), nullptr, true, 150);
    const std::string identity = ca_bundle::identityOf(shortLived.get());

    const AddRun run = runAddOn(fixture, pemOf(shortLived.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_EQ(fixture.clock.sleeps, 1) << "the first pass of G3 should have accepted a certificate valid then";
    EXPECT_NE(run.err.find(identity + ": expired (notAfter "), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, DuplicateRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);
    const std::string identity = ca_bundle::identityOf(fixture.ca.get());

    const AddRun run = runAddOn(fixture, pemOf(fixture.ca.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(identity + ": duplicate of an existing certificate"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, DuplicateWithinInputRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 70);
    const std::string identity = ca_bundle::identityOf(spare.get());
    const std::string twice = pemOf(spare.get()) + pemOf(spare.get());

    const AddRun run = runAddOn(fixture, twice);
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(identity + ": duplicate within the input file"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, NonCaRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    auto notCaKey = makeTestKey();
    const auto notCa =
        makeCertificate("not-a-ca", -kDay, 400 * kDay, notCaKey.get(), notCaKey.get(), nullptr, false, 80);
    const std::string identity = ca_bundle::identityOf(notCa.get());

    const AddRun run = runAddOn(fixture, pemOf(notCa.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(identity + ": not a CA"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, ExpiredRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    auto expiredKey = makeTestKey();
    const auto expired =
        makeCertificate("ca-expired", -400 * kDay, -kDay, expiredKey.get(), expiredKey.get(), nullptr, true, 90);
    const std::string identity = ca_bundle::identityOf(expired.get());

    const AddRun run = runAddOn(fixture, pemOf(expired.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(identity + ": expired (notAfter "), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, MalformedNotBeforeRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    // notAfter is comfortably in the future; only notBefore is unreadable. describe() would report
    // it as 0, which every window comparison accepts -- so the ASN.1 check has to be its own guard.
    auto brokenKey = makeTestKey();
    auto broken = makeSpareCa(brokenKey, "ca-broken-date", 100);
    breakNotBeforeAndResign(broken.get(), brokenKey.get());
    const std::string identity = ca_bundle::identityOf(broken.get());
    ASSERT_EQ(ca_bundle::describe(broken.get(), nullptr).notBefore, 0) << "fixture did not produce a bogus date";

    const AddRun run = runAddOn(fixture, pemOf(broken.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(identity + ": notBefore/notAfter is not a valid ASN.1 time"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, MalformedExistingBundleRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    writeFile(fixture.bundlePath, "-----BEGIN CERTIFICATE-----\nnot base64 at all !!\n-----END CERTIFICATE-----\n");
    const std::string before = sha256Of(fixture.bundlePath);

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 110);

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    EXPECT_EQ(run.exitCode, 2);
    EXPECT_NE(run.err.find("is malformed; refusing to write"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, MalformedInputRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    const AddRun run =
        runAddOn(fixture, "-----BEGIN CERTIFICATE-----\nnot base64 at all !!\n-----END CERTIFICATE-----\n");
    EXPECT_EQ(run.exitCode, 2);
    EXPECT_NE(run.err.find("is malformed"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, MixedValidAndCorruptInputRejectedAsAWhole)
{
    SKIP_UNLESS_ROOT();
    // Objection 16 / objection 6's repro: an input file whose FIRST block decodes and whose second
    // does not. Reading "up to the first block we could not decode" would add half of what the
    // operator meant to add -- and, worse, hand finishWrite() a candidate built from a partial
    // read. GI refuses the file whole (C34b), and the bundle keeps every certificate it had.
    AddFixture fixture {10};
    auto validKey = makeTestKey();
    const auto valid = makeSpareCa(validKey, "ca-valid-half", 150);
    const std::string mixed =
        pemOf(valid.get()) + "-----BEGIN CERTIFICATE-----\nnot base64 at all !!\n-----END CERTIFICATE-----\n";
    ASSERT_FALSE(ca_bundle::parseBundle(mixed).wellFormed) << "fixture is not the mixed input this case needs";
    const std::string before = sha256Of(fixture.bundlePath);
    const std::string existingIdentity = ca_bundle::identityOf(fixture.ca.get());

    const AddRun run = runAddOn(fixture, mixed);
    EXPECT_EQ(run.exitCode, 2);
    EXPECT_NE(run.err.find("is malformed"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);

    const ca_bundle::ParsedBundle kept = ca_bundle::parseBundle(readFile(fixture.bundlePath));
    ASSERT_EQ(kept.certificates.size(), 1u) << "the candidate must never lose what the bundle already held";
    EXPECT_EQ(ca_bundle::identityOf(kept.certificates[0].get()), existingIdentity);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsAdd, EmptyInputRejected)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    const std::string before = sha256Of(fixture.bundlePath);

    const AddRun run = runAddOn(fixture, "");
    EXPECT_EQ(run.exitCode, 2);
    EXPECT_NE(run.err.find("contains no certificates"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
}

TEST(ManagerCertsAdd, WrittenBundleIsVouchedWithTheNewPublication)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-new-anchor", 120);
    const std::string existingIdentity = ca_bundle::identityOf(fixture.ca.get());
    const std::string addedIdentity = ca_bundle::identityOf(spare.get());

    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    ASSERT_EQ(run.exitCode, 0) << run.err;
    EXPECT_TRUE(run.err.empty()) << run.err;
    EXPECT_EQ(fixture.clock.sleeps, 0) << "a clock already past the publication has nothing to wait for";
    EXPECT_NE(run.out.find("published generation " + std::to_string(fixture.base)), std::string::npos) << run.out;

    // Re-read from disk: what an agent, remoted or `inspect` would see.
    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
    ASSERT_TRUE(written.wellFormed);
    ASSERT_EQ(written.certificates.size(), 2u);
    EXPECT_EQ(ca_bundle::identityOf(written.certificates[0].get()), existingIdentity);
    EXPECT_EQ(ca_bundle::identityOf(written.certificates[1].get()), addedIdentity);

    ASSERT_TRUE(written.block.has_value());
    EXPECT_EQ(written.block->publication, static_cast<std::int64_t>(fixture.base));
    EXPECT_EQ(written.block->contentSha256, ca_bundle::contentSha256(written.certificates));
    EXPECT_FALSE(written.block->contentSha256.empty());
    EXPECT_FALSE(written.block->updated.empty());
    EXPECT_EQ(written.block->writtenBy, "manager_certs_utest");

    // C29's invariant, the reason every guard above exists: after a successful write, vouch() over
    // the RESULT returns exactly the publication just written.
    const ca_bundle::Vouch vouch =
        ca_bundle::vouch(written, fixture.leaf.get(), ca_bundle::serializeCertificates(written.certificates).size());
    EXPECT_EQ(vouch.failure, ca_bundle::GuardFailure::none);
    EXPECT_EQ(vouch.publication, static_cast<std::int64_t>(fixture.base));
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsAdd, WrittenBundlePreservesOwnerAndMode)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    // The installed bundle is root:wazuh-manager 0640 inside a 1770 directory. Group 1 stands in
    // for a group this container is not guaranteed to have: what matters is that the write carries
    // over whatever it found, instead of leaving the temporary's own 0600 root:root.
    ASSERT_EQ(::chown(fixture.bundlePath.c_str(), 0, 1), 0);
    struct stat before {};
    ASSERT_EQ(::stat(fixture.bundlePath.c_str(), &before), 0);
    ASSERT_EQ(before.st_mode & 07777, 0640u);

    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 130);
    const AddRun run = runAddOn(fixture, pemOf(spare.get()));
    ASSERT_EQ(run.exitCode, 0) << run.err;

    struct stat after {};
    ASSERT_EQ(::stat(fixture.bundlePath.c_str(), &after), 0);
    EXPECT_EQ(after.st_mode & 07777, 0640u);
    EXPECT_EQ(after.st_uid, 0u);
    EXPECT_EQ(after.st_gid, 1u);
    EXPECT_EQ(ca_bundle::parseBundle(readFile(fixture.bundlePath)).certificates.size(), 2u);
}

TEST(ManagerCertsAdd, DestinationReplacedDuringTheTransactionIsNotOverwritten)
{
    SKIP_UNLESS_ROOT();
    AddFixture fixture {10};
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-spare", 140);

    auto prepared = prepareWrite(requestFor(fixture.bundlePath, fixture.leaf.get(), fixture.clock));
    ASSERT_TRUE(prepared.context.has_value()) << prepared.message;

    // Somebody writes the bundle without taking the lock, after we read it: the installer, or an
    // operator with an editor (C36f). Their bytes have to survive.
    std::vector<ca_bundle::X509Ptr> theirs;
    theirs.push_back(manager_certs::test::retain(fixture.ca.get()));
    writeFile(fixture.bundlePath, sealedBundleText(theirs, static_cast<std::int64_t>(fixture.base) - 5));
    const std::string foreign = readFile(fixture.bundlePath);

    std::ostringstream out;
    std::ostringstream err;
    const int exitCode = runAdd(*prepared.context, pemOf(spare.get()), "input.pem", out, err);

    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(err.str().find("destination changed since it was read"), std::string::npos) << err.str();
    EXPECT_EQ(readFile(fixture.bundlePath), foreign);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsAdd, MissingBundleIsNotCreated)
{
    SKIP_UNLESS_ROOT();
    TempDir dir;
    TestClock clock;
    clock.wall = std::time(nullptr);
    auto caKey = makeTestKey();
    auto leafKey = makeTestKey();
    const auto ca = makeCertificate("ca-root", -kDay, 400 * kDay, caKey.get(), caKey.get(), nullptr, true, 1);
    const auto leaf = makeCertificate("leaf", -kDay, 90 * kDay, leafKey.get(), caKey.get(), ca.get(), false, 2);

    const auto missing = dir.path() / kBundleName;
    auto prepared = prepareWrite(requestFor(missing, leaf.get(), clock));

    EXPECT_FALSE(prepared.context.has_value());
    EXPECT_EQ(prepared.exitCode, 2);
    EXPECT_NE(prepared.message.find("bundle not found at " + missing.string()), std::string::npos) << prepared.message;
    EXPECT_NE(prepared.message.find("run 'wazuh-manager-certs stamp'"), std::string::npos) << prepared.message;
    EXPECT_FALSE(std::filesystem::exists(missing)) << "add must never create the bundle";
}
