/*
 * Wazuh manager certs tool - unit tests for `remove`, `prune-expired` and `stamp`
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// In-process tests of the three writing commands E7b adds on top of the transaction E7a left in
// place (plan-E7b): they build a candidate and hand it to the same prepareWrite()/finishWrite()
// `add` goes through, so what is exercised here is what is theirs -- which certificates the
// candidate ends up holding, and what each one refuses on its own before the shared guards ever
// run.
//
// Same three assertions on every rejection as the `add` suite next door (RF-8/CA-19): the exit
// code, the message an operator reads, and the bundle's SHA-256 unchanged -- plus, for the two
// paths that must not write at all (`remove` of an absent identity, `prune-expired` with nothing
// expired), the file's mtime as well, since an identical rewrite would keep the hash.
//
// The fixtures below are a deliberate, bounded copy of managerCertsWrite_test.cpp's (TempDir, the
// programmable clock, the sealed-bundle builders): the two files are separate translation units of
// the same binary, both in anonymous namespaces, and the module's precedent for this is
// tests/testPki.hpp's own header comment -- a copy the reader can see whole beats a shared fixture
// header that both suites then have to agree about.

#include "manager_certs/commands.hpp"
#include "testPki.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using manager_certs::finishWrite;
using manager_certs::prepareWrite;
using manager_certs::runPruneExpired;
using manager_certs::runRemove;
using manager_certs::runStamp;
using manager_certs::TimeSource;
using manager_certs::writeEnvironmentFailure;
using manager_certs::WriteRequest;
using manager_certs::test::makeCertificate;
using manager_certs::test::makeTestKey;
using manager_certs::test::retain;

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

    /// A temporary directory (mkdtemp), removed recursively when it goes out of scope.
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = (std::filesystem::temp_directory_path() / "manager_certs_rsp_XXXXXX").string();
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');
            if (mkdtemp(buffer.data()) == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for manager_certs_utest remove/stamp/prune fixtures");
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

    /// Hex SHA-256 of the file's bytes. Deliberately not manager_certs::bytesSha256() (a private
    /// header of the module under test): what a rejection case has to prove is that the FILE did
    /// not change, and an independent digest cannot be broken by the same mistake.
    std::string sha256Of(const std::filesystem::path& path)
    {
        const std::string contents = readFile(path);
        std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
        SHA256(reinterpret_cast<const unsigned char*>(contents.data()), contents.size(), digest.data());
        std::string hex;
        hex.reserve(digest.size() * 2);
        static constexpr char kHex[] = "0123456789abcdef";
        for (const unsigned char byte : digest)
        {
            hex.push_back(kHex[byte >> 4]);
            hex.push_back(kHex[byte & 0x0F]);
        }
        return hex;
    }

    /// The file's modification time to the nanosecond: what tells an identical REWRITE from no
    /// write at all, which the SHA-256 alone cannot (C35's "does not write" is about the file, not
    /// about its contents).
    std::string mtimeOf(const std::filesystem::path& path)
    {
        struct stat attributes {};
        if (::stat(path.c_str(), &attributes) != 0)
        {
            throw std::runtime_error("cannot stat a fixture bundle");
        }
        return std::to_string(attributes.st_mtim.tv_sec) + "." + std::to_string(attributes.st_mtim.tv_nsec);
    }

    /// Temporaries left behind in @p directory for @p name.
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

    /// The exact shape `wazuh-manager-certs` writes: the block, then the certificates. @p hash
    /// overrides the block's `Content-SHA256`, which is how the stale-stamp fixture is built.
    std::string sealedBundleText(const std::vector<ca_bundle::X509Ptr>& certificates,
                                 std::int64_t publication,
                                 const std::string& hash = {})
    {
        ca_bundle::PublicationBlock block;
        block.publication = publication;
        block.contentSha256 = hash.empty() ? ca_bundle::contentSha256(certificates) : hash;
        block.updated = "2026-09-19T00:00:00Z";
        block.writtenBy = "manager_certs_utest fixture";
        return ca_bundle::renderBlock(block) + ca_bundle::serializeCertificates(certificates);
    }

    /// A programmable clock: `sleeps` is what proves a case went through the wait of C28b, or --
    /// for the paths that write nothing -- that it never reached it.
    struct TestClock
    {
        std::time_t wall {0};
        std::int64_t monotonic {0};
        int sleeps {0};
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
            ++clock.wall;
        };
        return source;
    }

    WriteRequest
    requestFor(const std::string& command, const std::filesystem::path& bundlePath, const X509* leaf, TestClock& clock)
    {
        WriteRequest request;
        request.command = command;
        request.bundlePath = bundlePath;
        request.leaf = leaf;
        request.writtenBy = "manager_certs_utest";
        request.time = sourceFor(clock);
        return request;
    }

    /// A self-signed CA nobody else in a fixture knows about.
    ca_bundle::X509Ptr makeSpareCa(manager_certs::test::EvpPkeyPtr& key, const char* name, long serial)
    {
        return makeCertificate(name, -kDay, 400 * kDay, key.get(), key.get(), nullptr, true, serial);
    }

    /// A CA whose `notAfter` is already in the past: what `prune-expired` is for.
    ca_bundle::X509Ptr makeExpiredCa(manager_certs::test::EvpPkeyPtr& key, const char* name, long serial)
    {
        return makeCertificate(name, -400 * kDay, -kDay, key.get(), key.get(), nullptr, true, serial);
    }

    /// Pads @p certificate with a (non-critical, ignored) comment extension and re-signs it: the
    /// cheapest way to build a certificate big enough to push a bundle past the serialised cap.
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

    /// A CA that signs the served leaf, a throwaway directory, and a bundle the case writes itself:
    /// unlike `add`'s fixture, every case here cares about WHICH certificates the file holds.
    struct BundleFixture
    {
        TempDir dir;
        manager_certs::test::EvpPkeyPtr caKey;
        manager_certs::test::EvpPkeyPtr leafKey;
        ca_bundle::X509Ptr ca;
        ca_bundle::X509Ptr leaf;
        std::filesystem::path bundlePath;
        std::time_t base;
        TestClock clock;

        BundleFixture()
            : caKey {makeTestKey()}
            , leafKey {makeTestKey()}
            , ca {makeCertificate("ca-root", -kDay, 400 * kDay, caKey.get(), caKey.get(), nullptr, true, 1)}
            , leaf {makeCertificate("leaf", -kDay, 90 * kDay, leafKey.get(), caKey.get(), ca.get(), false, 2)}
            , bundlePath {dir.path() / kBundleName}
            , base {std::time(nullptr)}
        {
            clock.wall = base;
        }

        /// Writes @p certificates sealed with a publication @p previousOffset seconds in the past
        /// (10 by default: the clock is already past it, so nothing waits), mode 0640 like the
        /// installed bundle. @p hash overrides the block's Content-SHA256.
        void seal(const std::vector<ca_bundle::X509Ptr>& certificates,
                  long previousOffset = 10,
                  const std::string& hash = {})
        {
            writeFile(bundlePath,
                      sealedBundleText(certificates, static_cast<std::int64_t>(base) - previousOffset, hash));
            if (::chmod(bundlePath.c_str(), 0640) != 0)
            {
                throw std::runtime_error("cannot set the fixture bundle's mode");
            }
        }

        /// Writes @p certificates with no publication block at all: a plain PEM, the state every
        /// bundle is in before `stamp` ever touches it.
        void writePlain(const std::vector<ca_bundle::X509Ptr>& certificates)
        {
            writeFile(bundlePath, ca_bundle::serializeCertificates(certificates));
            if (::chmod(bundlePath.c_str(), 0640) != 0)
            {
                throw std::runtime_error("cannot set the fixture bundle's mode");
            }
        }
    };

    struct CommandRun
    {
        int exitCode {0};
        std::string out;
        std::string err;
        std::int64_t publication {0}; ///< Of the file AFTER the run, 0 when it carries no block.
    };

    /// Opens the transaction and runs @p command over it, exactly as main.cpp's runWrite() does.
    CommandRun runOn(BundleFixture& fixture, const std::string& command, const std::string& argument = {})
    {
        CommandRun run;
        auto prepared = prepareWrite(requestFor(command, fixture.bundlePath, fixture.leaf.get(), fixture.clock));
        if (!prepared.context)
        {
            run.exitCode = prepared.exitCode;
            run.err = prepared.message;
            return run;
        }

        std::ostringstream out;
        std::ostringstream err;
        if (command == "remove")
        {
            run.exitCode = runRemove(*prepared.context, argument, out, err);
        }
        else if (command == "prune-expired")
        {
            run.exitCode = runPruneExpired(*prepared.context, out, err);
        }
        else
        {
            run.exitCode = runStamp(*prepared.context, out, err);
        }
        run.out = out.str();
        run.err = err.str();

        const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
        run.publication = written.block ? written.block->publication : 0;
        return run;
    }

    std::vector<ca_bundle::X509Ptr> listOf(std::initializer_list<const X509*> certificates)
    {
        std::vector<ca_bundle::X509Ptr> list;
        for (const X509* certificate : certificates)
        {
            list.push_back(retain(certificate));
        }
        return list;
    }
} // namespace

// ==================================================================== remove =====================

TEST(ManagerCertsRemove, RemovesAllOccurrencesOfDuplicateIdentity)
{
    SKIP_UNLESS_ROOT();
    BundleFixture fixture;
    auto duplicatedKey = makeTestKey();
    const auto duplicated = makeSpareCa(duplicatedKey, "ca-duplicated", 10);

    // {A, A, B}: the same certificate listed twice (two operators adding it through different
    // paths, or a hand-edited file), plus the CA that signs the leaf.
    fixture.seal(listOf({duplicated.get(), duplicated.get(), fixture.ca.get()}));
    const std::string signerIdentity = ca_bundle::identityOf(fixture.ca.get());

    const CommandRun run = runOn(fixture, "remove", ca_bundle::identityOf(duplicated.get()));
    ASSERT_EQ(run.exitCode, 0) << run.err;
    EXPECT_TRUE(run.err.empty()) << run.err;
    EXPECT_NE(run.out.find("removed 2 certificate(s)"), std::string::npos) << run.out;

    // {B}, not {A, B}: removing one of the two copies would leave the anchor published while the
    // operator was told it was gone (objection 7, C34d).
    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
    ASSERT_TRUE(written.wellFormed);
    ASSERT_EQ(written.certificates.size(), 1u);
    EXPECT_EQ(ca_bundle::identityOf(written.certificates[0].get()), signerIdentity);
    EXPECT_EQ(run.publication, static_cast<std::int64_t>(fixture.base));
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsRemove, IdentityNotFoundRejected)
{
    SKIP_UNLESS_ROOT();
    BundleFixture fixture;
    fixture.seal(listOf({fixture.ca.get()}));
    const std::string before = sha256Of(fixture.bundlePath);
    const std::string beforeMtime = mtimeOf(fixture.bundlePath);
    const std::string absent = "x509-sha256:" + std::string(64, '0');

    const CommandRun run = runOn(fixture, "remove", absent);
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("identity " + absent + " not found in bundle"), std::string::npos) << run.err;
    // Nothing published either: a command that changed nothing must not raise the generation the
    // whole fleet compares against.
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(mtimeOf(fixture.bundlePath), beforeMtime);
    EXPECT_EQ(run.publication, static_cast<std::int64_t>(fixture.base) - 10);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);

    // An EMPTY identity is refused before the loop rather than matched against it: identityOf()
    // returns an empty string only for a certificate it could not encode, and silently dropping
    // those is not what an operator who typed nothing asked for.
    const CommandRun empty = runOn(fixture, "remove", "");
    EXPECT_EQ(empty.exitCode, 1);
    EXPECT_NE(empty.err.find("no identity given"), std::string::npos) << empty.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(mtimeOf(fixture.bundlePath), beforeMtime);
}

TEST(ManagerCertsRemove, OnlySignerRejected)
{
    SKIP_UNLESS_ROOT();
    // CA-28: the last CA that the served leaf chains to cannot be removed -- doing so would publish
    // a bundle no agent could use to trust this manager, and `GET /cacerts` would start answering
    // 503 for a file the tool itself wrote.
    BundleFixture fixture;
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-unrelated", 20);
    fixture.seal(listOf({fixture.ca.get(), spare.get()}));
    const std::string before = sha256Of(fixture.bundlePath);

    const CommandRun run = runOn(fixture, "remove", ca_bundle::identityOf(fixture.ca.get()));
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("remove: no CA signs the served leaf"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsRemove, LeavesSevenCertificatesRejected)
{
    SKIP_UNLESS_ROOT();
    // The repro of objection 5 (first revision): the count guard was `add`'s alone, so a `remove`
    // over a bundle of 8 published 7 -- one more than remoted will ever vouch for (C34a).
    BundleFixture fixture;
    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(retain(fixture.ca.get()));
    std::vector<manager_certs::test::EvpPkeyPtr> keys;
    for (int index = 0; index < 7; ++index)
    {
        keys.push_back(makeTestKey());
        certificates.push_back(makeSpareCa(keys.back(), ("ca-filler-" + std::to_string(index)).c_str(), 30 + index));
    }
    const std::string doomed = ca_bundle::identityOf(certificates[1].get());
    fixture.seal(certificates);
    const std::string before = sha256Of(fixture.bundlePath);

    const CommandRun run = runOn(fixture, "remove", doomed);
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("7 certificates (max 6)"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsRemove, RejectedOnWorker)
{
    // CA-30, for `remove`: G7 comes from the effective configuration alone, so it is answered
    // before anything opens, reads or locks the bundle (C34c) -- and it names the command the
    // operator typed.
    int exitCode {0};
    const std::string worker = writeEnvironmentFailure("remove", 0, "worker", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_EQ(worker.rfind("remove: ", 0), 0u) << worker;
    EXPECT_NE(worker.find("this node is a cluster worker"), std::string::npos) << worker;
    EXPECT_NE(worker.find("--from-master"), std::string::npos) << worker;

    const std::string nonRoot = writeEnvironmentFailure("remove", 1000, "master", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(nonRoot.find("must run as root (euid 0)"), std::string::npos) << nonRoot;

    EXPECT_TRUE(writeEnvironmentFailure("remove", 0, "master", exitCode).empty());
    EXPECT_EQ(exitCode, 0);
}

// ============================================================== prune-expired ===================

TEST(ManagerCertsPruneExpired, KeepsSigningCa)
{
    SKIP_UNLESS_ROOT();
    // CA-28: what goes is what expired, never the anchor the served leaf still chains to.
    BundleFixture fixture;
    auto expiredKey = makeTestKey();
    const auto expired = makeExpiredCa(expiredKey, "ca-expired", 40);
    fixture.seal(listOf({expired.get(), fixture.ca.get()}));
    const std::string signerIdentity = ca_bundle::identityOf(fixture.ca.get());

    const CommandRun run = runOn(fixture, "prune-expired");
    ASSERT_EQ(run.exitCode, 0) << run.err;
    EXPECT_TRUE(run.err.empty()) << run.err;
    EXPECT_NE(run.out.find("pruned 1 certificate(s); published generation " + std::to_string(fixture.base)),
              std::string::npos)
        << run.out;

    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
    ASSERT_EQ(written.certificates.size(), 1u);
    EXPECT_EQ(ca_bundle::identityOf(written.certificates[0].get()), signerIdentity);

    const ca_bundle::Vouch vouch =
        ca_bundle::vouch(written, fixture.leaf.get(), ca_bundle::serializeCertificates(written.certificates).size());
    EXPECT_EQ(vouch.failure, ca_bundle::GuardFailure::none);
    EXPECT_EQ(vouch.publication, static_cast<std::int64_t>(fixture.base));
}

TEST(ManagerCertsPruneExpired, OversizeAfterPruneRejected)
{
    SKIP_UNLESS_ROOT();
    // Objection 5 (first revision) for the byte cap: pruning shrinks the bundle, but not
    // necessarily under 8191 bytes -- and what remoted refuses to serve, the tool must refuse to
    // publish (C34a).
    BundleFixture fixture;
    auto hugeKey = makeTestKey();
    auto huge = makeSpareCa(hugeKey, "ca-huge", 50);
    inflateAndResign(huge.get(), hugeKey.get(), 8U * 1024U);
    auto expiredKey = makeTestKey();
    const auto expired = makeExpiredCa(expiredKey, "ca-expired", 51);
    fixture.seal(listOf({fixture.ca.get(), huge.get(), expired.get()}));
    const std::string before = sha256Of(fixture.bundlePath);

    const CommandRun run = runOn(fixture, "prune-expired");
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find(" bytes (max " + std::to_string(ca_bundle::kMaxSerializedBytes) + ")"), std::string::npos)
        << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsPruneExpired, NothingToPruneDoesNotWrite)
{
    SKIP_UNLESS_ROOT();
    // C35, the whole point: with nothing expired the bundle is NOT republished. A new generation
    // over unchanged bytes sends every agent in the fleet back to GET /cacerts for what it already
    // has -- every night, since this is the command that goes in cron.
    BundleFixture fixture;
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-second", 60);
    fixture.seal(listOf({fixture.ca.get(), spare.get()}));
    const std::string before = sha256Of(fixture.bundlePath);
    const std::string beforeMtime = mtimeOf(fixture.bundlePath);

    const CommandRun run = runOn(fixture, "prune-expired");
    EXPECT_EQ(run.exitCode, 0);
    EXPECT_EQ(run.out, "nothing to prune\n");
    // Sealed, current and vouched: the audit of C36i has nothing to warn about.
    EXPECT_TRUE(run.err.empty()) << run.err;

    // Hash AND mtime: an identical rewrite would keep the first and move the second, and it would
    // still be a write nobody asked for.
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(mtimeOf(fixture.bundlePath), beforeMtime);
    EXPECT_EQ(run.publication, static_cast<std::int64_t>(fixture.base) - 10) << "the generation must not move";
    EXPECT_EQ(fixture.clock.sleeps, 0) << "nothing to publish means the wait of C28b is never reached";
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsPruneExpired, NothingToPruneWarnsWhenUnsealedOrHashIsStale)
{
    SKIP_UNLESS_ROOT();
    // C36i: silence on the no-op path would let an operator running this nightly believe the bundle
    // is published when it never was, or when its stamp no longer describes its certificates. It
    // still writes nothing -- it says which command does.
    {
        BundleFixture unsealed;
        unsealed.writePlain(listOf({unsealed.ca.get()}));
        const std::string before = sha256Of(unsealed.bundlePath);
        const std::string beforeMtime = mtimeOf(unsealed.bundlePath);

        const CommandRun run = runOn(unsealed, "prune-expired");
        EXPECT_EQ(run.exitCode, 0);
        EXPECT_EQ(run.out, "nothing to prune\n");
        EXPECT_NE(run.err.find("bundle is not vouched; run 'stamp' to publish it"), std::string::npos) << run.err;
        EXPECT_EQ(sha256Of(unsealed.bundlePath), before);
        EXPECT_EQ(mtimeOf(unsealed.bundlePath), beforeMtime);
        EXPECT_EQ(run.publication, 0);
    }

    {
        BundleFixture stale;
        // Stamped, but with a Content-SHA256 that describes nothing in the file: vouch()'s
        // hash_mismatch, which an operator only ever learns about from `check` -- or from here.
        stale.seal(listOf({stale.ca.get()}), 10, std::string(64, 'a'));
        const std::string before = sha256Of(stale.bundlePath);
        const std::string beforeMtime = mtimeOf(stale.bundlePath);

        const CommandRun run = runOn(stale, "prune-expired");
        EXPECT_EQ(run.exitCode, 0);
        EXPECT_EQ(run.out, "nothing to prune\n");
        EXPECT_NE(run.err.find("bundle is not vouched; run 'stamp' to publish it"), std::string::npos) << run.err;
        EXPECT_EQ(sha256Of(stale.bundlePath), before);
        EXPECT_EQ(mtimeOf(stale.bundlePath), beforeMtime);
        EXPECT_EQ(run.publication, static_cast<std::int64_t>(stale.base) - 10);
    }
}

TEST(ManagerCertsPruneExpired, AllExpiredLeavesEmptyCandidateRejected)
{
    SKIP_UNLESS_ROOT();
    // Objection 16: every certificate expired at once (a CA rotation nobody completed). Publishing
    // the empty result would strand the whole fleet, so G4 refuses it and the file stays as it is
    // -- expired, but still the anchor the agents hold.
    BundleFixture fixture;
    std::vector<ca_bundle::X509Ptr> certificates;
    std::vector<manager_certs::test::EvpPkeyPtr> keys;
    for (int index = 0; index < 6; ++index)
    {
        keys.push_back(makeTestKey());
        certificates.push_back(makeExpiredCa(keys.back(), ("ca-expired-" + std::to_string(index)).c_str(), 70 + index));
    }
    fixture.seal(certificates);
    const std::string before = sha256Of(fixture.bundlePath);
    const std::string beforeMtime = mtimeOf(fixture.bundlePath);

    const CommandRun run = runOn(fixture, "prune-expired");
    EXPECT_EQ(run.exitCode, 1);
    EXPECT_NE(run.err.find("prune-expired: 0 certificates"), std::string::npos) << run.err;
    EXPECT_EQ(sha256Of(fixture.bundlePath), before);
    EXPECT_EQ(mtimeOf(fixture.bundlePath), beforeMtime);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsPruneExpired, RejectedOnWorker)
{
    int exitCode {0};
    const std::string worker = writeEnvironmentFailure("prune-expired", 0, "worker", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_EQ(worker.rfind("prune-expired: ", 0), 0u) << worker;
    EXPECT_NE(worker.find("this node is a cluster worker"), std::string::npos) << worker;

    const std::string nonRoot = writeEnvironmentFailure("prune-expired", 1000, "master", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(nonRoot.find("must run as root (euid 0)"), std::string::npos) << nonRoot;

    EXPECT_TRUE(writeEnvironmentFailure("prune-expired", 0, "master", exitCode).empty());
    EXPECT_EQ(exitCode, 0);
}

// ===================================================================== stamp ====================

TEST(ManagerCertsStamp, PlainPemGetsPublished)
{
    SKIP_UNLESS_ROOT();
    // CA-29: a plain PEM -- no block at all -- is exactly what `stamp` exists for. vouch()'s
    // no_block is not a reason to refuse here; it is the condition being fixed.
    BundleFixture fixture;
    fixture.writePlain(listOf({fixture.ca.get()}));

    const CommandRun run = runOn(fixture, "stamp");
    ASSERT_EQ(run.exitCode, 0) << run.err;
    EXPECT_TRUE(run.err.empty()) << run.err;
    EXPECT_NE(run.out.find("stamped 1 certificate(s); published generation "), std::string::npos) << run.out;
    EXPECT_GT(run.publication, 0);
    // No previous publication means the wait of C36e, so the generation is the NEXT second: an
    // unpublished file may well have been replaced in this very second.
    EXPECT_EQ(fixture.clock.sleeps, 1);
    EXPECT_EQ(run.publication, static_cast<std::int64_t>(fixture.base) + 1);
}

TEST(ManagerCertsStamp, WrittenBundleIsVouchedWithTheNewPublication)
{
    SKIP_UNLESS_ROOT();
    // C29's invariant for `stamp`, without remoted anywhere in sight: the file it wrote is parsed
    // back and vouch() over it returns the publication just written.
    BundleFixture fixture;
    auto spareKey = makeTestKey();
    const auto spare = makeSpareCa(spareKey, "ca-second", 80);
    fixture.writePlain(listOf({fixture.ca.get(), spare.get()}));
    const std::string firstIdentity = ca_bundle::identityOf(fixture.ca.get());
    const std::string secondIdentity = ca_bundle::identityOf(spare.get());

    const CommandRun run = runOn(fixture, "stamp");
    ASSERT_EQ(run.exitCode, 0) << run.err;

    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(fixture.bundlePath));
    ASSERT_TRUE(written.wellFormed);
    ASSERT_EQ(written.certificates.size(), 2u);
    EXPECT_EQ(ca_bundle::identityOf(written.certificates[0].get()), firstIdentity);
    EXPECT_EQ(ca_bundle::identityOf(written.certificates[1].get()), secondIdentity);

    ASSERT_TRUE(written.block.has_value());
    EXPECT_EQ(written.block->publication, static_cast<std::int64_t>(fixture.base) + 1);
    EXPECT_EQ(written.block->contentSha256, ca_bundle::contentSha256(written.certificates));
    EXPECT_FALSE(written.block->updated.empty());
    EXPECT_EQ(written.block->writtenBy, "manager_certs_utest");

    const ca_bundle::Vouch vouch =
        ca_bundle::vouch(written, fixture.leaf.get(), ca_bundle::serializeCertificates(written.certificates).size());
    EXPECT_EQ(vouch.failure, ca_bundle::GuardFailure::none);
    EXPECT_EQ(vouch.publication, run.publication);

    // The mode the file had is the mode it keeps: remoted reads it as the wazuh-manager group.
    struct stat attributes {};
    ASSERT_EQ(::stat(fixture.bundlePath.c_str(), &attributes), 0);
    EXPECT_EQ(attributes.st_mode & 07777, 0640u);
    EXPECT_EQ(temporaryCount(fixture.dir.path(), kBundleName), 0u);
}

TEST(ManagerCertsStamp, RejectedOnWorker)
{
    int exitCode {0};
    const std::string worker = writeEnvironmentFailure("stamp", 0, "worker", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_EQ(worker.rfind("stamp: ", 0), 0u) << worker;
    EXPECT_NE(worker.find("this node is a cluster worker"), std::string::npos) << worker;

    const std::string nonRoot = writeEnvironmentFailure("stamp", 1000, "master", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(nonRoot.find("must run as root (euid 0)"), std::string::npos) << nonRoot;

    EXPECT_TRUE(writeEnvironmentFailure("stamp", 0, "master", exitCode).empty());
    EXPECT_EQ(exitCode, 0);
}
