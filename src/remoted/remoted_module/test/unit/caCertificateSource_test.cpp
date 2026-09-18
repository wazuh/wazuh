/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file caCertificateSource_test.cpp
 * @brief What the CA file turns into: certificates we re-serialise, a verdict from the same read,
 *        and a cache keyed by content so a replacement is seen at once (issue #39078, H01 and H06)
 *        -- plus the publication that verdict now carries, and the generation the notify path
 *        reads through descriptor() (issue #39319).
 *
 * Real certificates throughout (testTlsServer.hpp's throwaway PKI): the point of the class is what
 * OpenSSL makes of the bytes, so parsing them for real is the test. The published bundles are built
 * with ca_bundle::renderBlock(), the only writer of those `##` lines there is, so a test can never
 * pin a block shape the tool would not write.
 */

#include <gtest/gtest.h>

#include "ca_bundle/ca_bundle.hpp"
#include "http_server/caCertificateSource.hpp"
#include "http_server/fileRead.hpp"
#include "testCertificates.hpp"
#include "testTlsServer.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <utime.h>
#include <vector>

using ca_bundle::GuardFailure;
using ca_bundle::parseBundle;
using remoted::http::CaCertificateSource;
using remoted::http::describeReadFailure;
using remoted::http::ReadFailure;
using remoted::http::readFileBounded;
using remoted::http::ReadResult;
using remoted::http::ReadStatus;
using remoted::http::serializeCertificates;
using remoted::http::statusFrom;

namespace
{
    std::string readAll(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        std::ostringstream out;
        out << file.rdbuf();
        return out.str();
    }

    void write(const std::string& path, const std::string& contents)
    {
        std::ofstream file {path, std::ios::binary | std::ios::trunc};
        file << contents;
    }

    /// Replaces @p path atomically (write to a sibling, then rename over it), so a concurrent
    /// reader sees the old content or the new one -- never a truncated or half-written file.
    void replaceAtomically(const std::string& path, const std::string& contents)
    {
        const auto temporary = path + ".tmp";
        write(temporary, contents);
        ASSERT_EQ(std::rename(temporary.c_str(), path.c_str()), 0);
    }

    /// Trailing newlines outside a PEM block change nothing for the reader, so padding is how two
    /// different CAs are made byte-identical in length without touching what they say.
    std::string paddedTo(std::string pem, std::size_t size)
    {
        pem.append(size - pem.size(), '\n');
        return pem;
    }

    /// Overwrite a file keeping its size and modification time: the case a metadata-based cache
    /// would miss, and the reason this one hashes the content.
    void overwritePreservingMetadata(const std::string& path, const std::string& contents)
    {
        struct stat before {};
        ASSERT_EQ(::stat(path.c_str(), &before), 0);
        ASSERT_EQ(static_cast<std::size_t>(before.st_size), contents.size());

        write(path, contents);

        struct utimbuf times {before.st_atime, before.st_mtime};
        ASSERT_EQ(::utime(path.c_str(), &times), 0);

        struct stat after {};
        ASSERT_EQ(::stat(path.c_str(), &after), 0);
        ASSERT_EQ(before.st_size, after.st_size);
        ASSERT_EQ(before.st_mtime, after.st_mtime);
    }

    /**
     * @brief A FileReader with every failure programmable, so the failure paths of
     *        CaCertificateSource are testable without permission tricks that root ignores.
     *
     * The state lives behind a shared_ptr: the copy std::function makes when the reader is
     * installed and the copy the test keeps both point at it, so the test can flip the status
     * an already-constructed CaCertificateSource sees on its next snapshot() call.
     */
    struct FakeReader
    {
        struct State
        {
            std::string contents; ///< Returned verbatim on ReadStatus::Ok.
            ReadStatus status {ReadStatus::Ok};
            int error {0};
            std::optional<std::size_t> declaredSize;    ///< Set to fake a file bigger than maxBytes:
                                                        ///< TooLarge comes back without contents ever
                                                        ///< being materialised, whatever `contents` holds.
            std::vector<std::size_t> requestedMaxBytes; ///< One entry per call, in order.
        };

        std::shared_ptr<State> state {std::make_shared<State>()};

        ReadResult operator()(const std::string& /*path*/, std::size_t maxBytes, std::string& contents) const
        {
            state->requestedMaxBytes.push_back(maxBytes);

            if (state->declaredSize.has_value() && *state->declaredSize > maxBytes)
            {
                contents.clear();
                return {ReadStatus::TooLarge, 0};
            }

            if (state->status != ReadStatus::Ok)
            {
                contents.clear();
                return {state->status, state->error};
            }

            contents = state->contents;
            return {};
        }
    };

    // loadCertificates() is gone (issue #39318): CaCertificateSource is the one reader now. This is
    // the read-only half a plain loadCertificates() call used to give makePki() below -- the
    // bounded/failure-aware half is what CaCertificateSource itself is under test for.
    std::vector<remoted::http::X509Ptr> readPemCertificates(const std::string& path)
    {
        return parseBundle(readAll(path)).certificates;
    }

    struct Pki
    {
        remoted::test::TestCaSignedCertificate files;
        remoted::http::X509Ptr leaf;
    };

    std::optional<Pki> makePki(const std::string& prefix)
    {
        auto generated = remoted::test::generateCaSignedCertificate(prefix);
        if (!generated)
        {
            return std::nullopt;
        }

        auto leaves = readPemCertificates(generated->certPath);
        if (leaves.empty())
        {
            return std::nullopt;
        }

        Pki pki;
        pki.files = *generated;
        pki.leaf = std::move(leaves.front());
        return pki;
    }

    /// Publications the tests stamp with: fixed Unix timestamps, so what the assertions pin is the
    /// number the block carried and not a clock.
    constexpr std::int64_t kPublication {1789000000};
    constexpr std::int64_t kNewerPublication {1789000600};

    /**
     * @brief The document `wazuh-manager-certs` would leave behind: the block it stamps, then the
     *        certificates that block describes.
     *
     * @param contentSha256 Overrides the block's hash, for the one case that matters: a stamp that
     *                      describes another set of certificates (a bundle changed under it).
     */
    std::string sealedDocument(const std::vector<remoted::http::X509Ptr>& certificates,
                               std::int64_t publication,
                               const std::string& contentSha256 = {})
    {
        ca_bundle::PublicationBlock block;
        block.publication = publication;
        block.contentSha256 = contentSha256.empty() ? ca_bundle::contentSha256(certificates) : contentSha256;
        block.updated = "2026-09-18T00:00:00Z";
        block.writtenBy = "caCertificateSource_test";
        return ca_bundle::renderBlock(block) + serializeCertificates(certificates);
    }

    /// A self-signed CA with nothing to do with any leaf, built in memory: filler for the bundles
    /// the count and byte guards are about. @p sanBytes of subjectAltName is how a certificate is
    /// made big without a bigger key -- dNSName entries have no 64-byte name limit to respect.
    remoted::http::X509Ptr fillerCertificate(EVP_PKEY* key, const std::string& commonName, std::size_t sanBytes = 0)
    {
        std::string san;
        while (san.size() < sanBytes)
        {
            san += (san.empty() ? "DNS:" : ",DNS:") + std::string(200, static_cast<char>('a' + san.size() % 26));
        }
        return remoted::test::makeCertificate(commonName.c_str(),
                                              -3600,
                                              3600,
                                              key,
                                              key,
                                              nullptr,
                                              san.empty() ? nullptr : san.c_str(),
                                              /*isCa=*/true);
    }

    /// A FileReader that counts its calls and otherwise reads the file for real: what proves
    /// descriptor() reads once per refresh window instead of once per call.
    struct CountingReader
    {
        std::shared_ptr<std::atomic<int>> calls {std::make_shared<std::atomic<int>>(0)};

        ReadResult operator()(const std::string& path, std::size_t maxBytes, std::string& contents) const
        {
            ++*calls;
            return readFileBounded(path, maxBytes, contents);
        }
    };

    /// A clock the test moves by hand, so the refresh window is exercised without sleeping through
    /// it (and without a real second of test time per case).
    struct TestClock
    {
        std::shared_ptr<std::chrono::steady_clock::time_point> now {
            std::make_shared<std::chrono::steady_clock::time_point>()};

        std::chrono::steady_clock::time_point operator()() const
        {
            return *now;
        }
    };
} // namespace

TEST(CaCertificateSource, PublishesOnlyCertificatesFromACombinedPem)
{
    auto pki = makePki("casource-combined");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // The misprovisioned input the finding is about: the CA certificate and its private key in one
    // file. Before this class, /cacerts answered with the file, key included.
    const auto combined = pki->files.caCertPath + ".combined";
    write(combined, readAll(pki->files.caCertPath) + readAll(pki->files.caKeyPath));
    remoted::test::ScratchFileCleanup cleanupCombined {{combined}};

    CaCertificateSource source {combined, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.certificates, 1U);
    EXPECT_EQ(snapshot.matchesLeaf, true);
    EXPECT_NE(snapshot.pem.find("BEGIN CERTIFICATE"), std::string::npos);
    EXPECT_EQ(snapshot.pem.find("PRIVATE KEY"), std::string::npos);
}

TEST(CaCertificateSource, EmptyTextAndKeyOnlyFilesYieldNothing)
{
    auto pki = makePki("casource-nothing");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto scratch = pki->files.caCertPath + ".scratch";
    remoted::test::ScratchFileCleanup cleanupScratch {{scratch}};

    for (const auto& contents : {std::string {}, std::string {"not a pem at all\n"}, readAll(pki->files.caKeyPath)})
    {
        write(scratch, contents);
        CaCertificateSource source {scratch, pki->leaf.get()};
        const auto snapshot = source.snapshot();
        EXPECT_EQ(snapshot.certificates, 0U);
        EXPECT_TRUE(snapshot.pem.empty());
        EXPECT_FALSE(snapshot.matchesLeaf.has_value());
    }

    // A path that does not exist reads the same way.
    CaCertificateSource missing {scratch + ".nope", pki->leaf.get()};
    EXPECT_EQ(missing.snapshot().certificates, 0U);
}

TEST(CaCertificateSource, RejectsTheWholeFileWhenABlockCannotBeParsed)
{
    auto pki = makePki("casource-corrupt");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // A valid certificate followed by a block OpenSSL cannot decode. Serving the good prefix would
    // mean publishing from a document we do not understand: refuse it whole.
    const auto corrupt = pki->files.caCertPath + ".corrupt";
    write(corrupt,
          readAll(pki->files.caCertPath) + "-----BEGIN CERTIFICATE-----\nnot base64 at all!!\n-----END "
                                           "CERTIFICATE-----\n");
    remoted::test::ScratchFileCleanup cleanupCorrupt {{corrupt}};

    CaCertificateSource source {corrupt, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.certificates, 0U);
    EXPECT_TRUE(snapshot.pem.empty());
}

TEST(CaCertificateSource, ServesABundleAndMatchesOnAnyOfItsCertificates)
{
    auto signer = makePki("casource-bundle");
    auto other = makePki("casource-bundle-other");
    ASSERT_TRUE(signer.has_value());
    ASSERT_TRUE(other.has_value());
    remoted::test::ScratchFileCleanup cleanup {signer->files.files()};
    remoted::test::ScratchFileCleanup cleanupOther {other->files.files()};

    // The signer is the SECOND certificate of the bundle: reading only the first (what the C side
    // still does today) would call this a mismatch.
    const auto bundle = signer->files.caCertPath + ".bundle";
    write(bundle, readAll(other->files.caCertPath) + readAll(signer->files.caCertPath));
    remoted::test::ScratchFileCleanup cleanupBundle {{bundle}};

    CaCertificateSource source {bundle, signer->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.certificates, 2U);
    EXPECT_EQ(snapshot.matchesLeaf, true);
    EXPECT_NE(snapshot.subjects.find(','), std::string::npos);
}

TEST(CaCertificateSource, RevalidatesWhenTheContentChangesEvenWithTheSameSizeAndMtime)
{
    auto pki = makePki("casource-swap");
    auto foreign = makePki("casource-swap-foreign");
    ASSERT_TRUE(pki.has_value());
    ASSERT_TRUE(foreign.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};
    remoted::test::ScratchFileCleanup cleanupForeign {foreign->files.files()};

    // Both CAs padded to the same length, so the swap below changes the content and nothing else.
    const auto ours = readAll(pki->files.caCertPath);
    const auto theirs = readAll(foreign->files.caCertPath);
    const auto size = std::max(ours.size(), theirs.size()) + 8;
    const auto oursPadded = paddedTo(ours, size);
    const auto theirsPadded = paddedTo(theirs, size);

    const auto path = pki->files.caCertPath + ".rotating";
    write(path, oursPadded);
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    EXPECT_EQ(source.snapshot().matchesLeaf, true);
    EXPECT_EQ(source.parses(), 1U);

    // Unchanged file: answered from the cache, no second parse.
    EXPECT_EQ(source.snapshot().matchesLeaf, true);
    EXPECT_EQ(source.parses(), 1U);

    // Replaced by an unrelated CA, keeping size and mtime. The next call already refuses it.
    overwritePreservingMetadata(path, theirsPadded);
    EXPECT_EQ(source.snapshot().matchesLeaf, false);
    EXPECT_EQ(source.parses(), 2U);

    // Repaired: served again in the very next request, no daily tick involved.
    overwritePreservingMetadata(path, oursPadded);
    EXPECT_EQ(source.snapshot().matchesLeaf, true);
    EXPECT_EQ(source.parses(), 3U);
}

TEST(CaCertificateSource, AMissingFileKeepsThePreviousSnapshot)
{
    auto pki = makePki("casource-vanish");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto path = pki->files.caCertPath + ".vanishing";
    const auto contents = readAll(pki->files.caCertPath);
    write(path, contents);

    CaCertificateSource source {path, pki->leaf.get()};
    const auto served = source.snapshot();
    ASSERT_EQ(served.certificates, 1U);
    ASSERT_FALSE(served.lastReadFailure.has_value());

    ::remove(path.c_str());

    // A failed read is a window, not a decision (issue #39318): the last good snapshot keeps
    // being served, with the failure recorded alongside it for the callers that own a logger.
    const auto firstFailure = source.snapshot();
    EXPECT_EQ(firstFailure.certificates, 1U);
    EXPECT_EQ(firstFailure.pem, served.pem);
    ASSERT_TRUE(firstFailure.lastReadFailure.has_value());
    EXPECT_EQ(firstFailure.lastReadFailure->status, ReadStatus::CannotOpen);
    EXPECT_EQ(firstFailure.lastReadFailure->error, ENOENT);
    EXPECT_EQ(firstFailure.lastReadFailure->consecutive, 1U);

    const auto secondFailure = source.snapshot();
    ASSERT_TRUE(secondFailure.lastReadFailure.has_value());
    EXPECT_EQ(secondFailure.lastReadFailure->status, ReadStatus::CannotOpen);
    EXPECT_EQ(secondFailure.lastReadFailure->error, ENOENT);
    EXPECT_EQ(secondFailure.lastReadFailure->consecutive, 2U);

    // Repaired with the exact same bytes: a cache hit, so the failure it recovered from is no
    // longer news, and it costs no reparse.
    write(path, contents);
    const auto restored = source.snapshot();
    EXPECT_EQ(restored.certificates, 1U);
    EXPECT_FALSE(restored.lastReadFailure.has_value());
    EXPECT_EQ(source.parses(), 1U);

    ::remove(path.c_str());
}

TEST(CaCertificateSource, ReadFailureKeepsThePreviousSnapshot)
{
    auto pki = makePki("casource-readfail");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    FakeReader reader;
    reader.state->contents = readAll(pki->files.caCertPath);

    // The path is never actually opened -- the FakeReader stands in for the whole filesystem --
    // so any non-empty path does; the real one is at hand and already cleaned up.
    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get(), reader};
    const auto served = source.snapshot();
    ASSERT_EQ(served.certificates, 1U);
    ASSERT_EQ(source.parses(), 1U);

    reader.state->status = ReadStatus::ReadError;
    reader.state->error = EIO;

    const auto firstFailure = source.snapshot();
    EXPECT_EQ(firstFailure.certificates, 1U);
    EXPECT_EQ(firstFailure.pem, served.pem);
    ASSERT_TRUE(firstFailure.lastReadFailure.has_value());
    EXPECT_EQ(firstFailure.lastReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(firstFailure.lastReadFailure->error, EIO);
    EXPECT_EQ(firstFailure.lastReadFailure->consecutive, 1U);

    const auto secondFailure = source.snapshot();
    ASSERT_TRUE(secondFailure.lastReadFailure.has_value());
    EXPECT_EQ(secondFailure.lastReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(secondFailure.lastReadFailure->error, EIO);
    EXPECT_EQ(secondFailure.lastReadFailure->consecutive, 2U);

    EXPECT_EQ(source.parses(), 1U);
}

TEST(CaCertificateSource, StatusFromCarriesTheReadFailure)
{
    // statusFrom() is the one place a CaCertificateSnapshot becomes a TlsCertificateSnapshot (at
    // start and on every monitor tick): what it copies from a good read, and that a read failure
    // travels through it too, without erasing the last good verdict (issue #39318).
    auto pki = makePki("casource-statusfrom");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    FakeReader reader;
    reader.state->contents = readAll(pki->files.caCertPath);

    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get(), reader};
    const auto status = statusFrom(pki->leaf.get(), source.snapshot());

    EXPECT_EQ(status.caMatchesLeaf, true);
    EXPECT_FALSE(status.caSubjects.empty());
    EXPECT_EQ(status.chainValid, true); // the CLI CA carries CA:TRUE and signed the leaf: it validates too
    EXPECT_TRUE(status.chainError.empty());
    EXPECT_FALSE(status.caReadFailure.has_value());
    EXPECT_EQ(status.evaluations, 0U); // counting is the monitor's job, not statusFrom()'s
    EXPECT_TRUE(status.expiryDays.has_value());

    reader.state->status = ReadStatus::ReadError;
    reader.state->error = EIO;

    const auto failedStatus = statusFrom(pki->leaf.get(), source.snapshot());
    ASSERT_TRUE(failedStatus.caReadFailure.has_value());
    EXPECT_EQ(failedStatus.caReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(failedStatus.caReadFailure->error, EIO);
    EXPECT_EQ(failedStatus.caReadFailure->consecutive, 1U);
    EXPECT_EQ(failedStatus.caMatchesLeaf, true); // the last good verdict, kept through the failure
}

TEST(CaCertificateSource, StatusFromCarriesCertificateAndByteCounts)
{
    // The "too many certificates"/"too many bytes" log lines name what was actually observed
    // alongside the cap (issue found in the E1b review); statusFrom() is where that has to travel
    // from the snapshot to the status the transport logs from.
    auto signer = makePki("casource-statuscounts");
    auto other = makePki("casource-statuscounts-other");
    ASSERT_TRUE(signer.has_value());
    ASSERT_TRUE(other.has_value());
    remoted::test::ScratchFileCleanup cleanup {signer->files.files()};
    remoted::test::ScratchFileCleanup cleanupOther {other->files.files()};

    const auto bundle = signer->files.caCertPath + ".statuscounts";
    write(bundle, readAll(other->files.caCertPath) + readAll(signer->files.caCertPath));
    remoted::test::ScratchFileCleanup cleanupBundle {{bundle}};

    CaCertificateSource source {bundle, signer->leaf.get()};
    const auto snapshot = source.snapshot();
    ASSERT_EQ(snapshot.certificates, 2U);

    const auto status = statusFrom(signer->leaf.get(), snapshot);
    EXPECT_EQ(status.caCertificates, 2U);
    EXPECT_EQ(status.caSerializedBytes, snapshot.pem.size());
}

TEST(CaCertificateSource, ADirectoryAtThePathIsAReadError)
{
    auto pki = makePki("casource-isdir");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto path = pki->files.caCertPath + ".isdir";
    write(path, readAll(pki->files.caCertPath));

    CaCertificateSource source {path, pki->leaf.get()};
    const auto served = source.snapshot();
    ASSERT_EQ(served.certificates, 1U);

    // open(2) succeeds on a directory; it is read(2) that refuses it (EISDIR) -- the case the
    // reader's own doc comment calls out.
    ::remove(path.c_str());
    ASSERT_EQ(::mkdir(path.c_str(), 0755), 0);

    const auto failed = source.snapshot();
    EXPECT_EQ(failed.certificates, 1U);
    EXPECT_EQ(failed.pem, served.pem);
    ASSERT_TRUE(failed.lastReadFailure.has_value());
    EXPECT_EQ(failed.lastReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(failed.lastReadFailure->error, EISDIR);

    ::rmdir(path.c_str());
}

TEST(CaCertificateSource, AFileThatWasNeverReadableYieldsNothing)
{
    auto pki = makePki("casource-neverreadable");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    CaCertificateSource source {pki->files.caCertPath + ".nope", pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.certificates, 0U);
    EXPECT_TRUE(snapshot.pem.empty());
    ASSERT_TRUE(snapshot.lastReadFailure.has_value());
    EXPECT_EQ(snapshot.lastReadFailure->status, ReadStatus::CannotOpen);
    EXPECT_EQ(snapshot.lastReadFailure->error, ENOENT);
    EXPECT_EQ(snapshot.lastReadFailure->consecutive, 1U);
}

TEST(CaCertificateSource, AnEmptiedFileClearsThePreviousSnapshot)
{
    auto pki = makePki("casource-emptied");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto path = pki->files.caCertPath + ".emptied";
    write(path, readAll(pki->files.caCertPath));

    CaCertificateSource source {path, pki->leaf.get()};
    ASSERT_EQ(source.snapshot().certificates, 1U);
    ASSERT_EQ(source.parses(), 1U);

    // Readable but carrying nothing: the operator's way of saying "stop serving", and it takes
    // effect at once -- a read that SUCCEEDS, not one that fails.
    write(path, "");
    const auto emptied = source.snapshot();
    EXPECT_EQ(emptied.certificates, 0U);
    EXPECT_TRUE(emptied.pem.empty());
    EXPECT_FALSE(emptied.lastReadFailure.has_value());
    EXPECT_EQ(source.parses(), 2U);

    ::remove(path.c_str());
}

TEST(CaCertificateSource, TooLargeIsRejectedWithoutReadingItWhole)
{
    auto pki = makePki("casource-toolarge-fake");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    FakeReader reader;
    reader.state->contents = readAll(pki->files.caCertPath);

    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get(), reader};
    const auto served = source.snapshot();
    ASSERT_EQ(served.certificates, 1U);
    ASSERT_EQ(source.parses(), 1U);

    // 100 MiB is never produced by the FakeReader (see its operator()): only declared, which is
    // exactly the point -- CaCertificateSource must refuse on the declared size alone.
    reader.state->declaredSize = 100U * 1024U * 1024U;

    const auto rejected = source.snapshot();
    EXPECT_EQ(rejected.certificates, 1U);
    EXPECT_EQ(rejected.pem, served.pem);
    ASSERT_TRUE(rejected.lastReadFailure.has_value());
    EXPECT_EQ(rejected.lastReadFailure->status, ReadStatus::TooLarge);
    EXPECT_EQ(source.parses(), 1U);

    ASSERT_FALSE(reader.state->requestedMaxBytes.empty());
    EXPECT_EQ(reader.state->requestedMaxBytes.back(), CaCertificateSource::kMaxBytes);
}

TEST(CaCertificateSource, ARealFileOverTheCapKeepsThePreviousSnapshot)
{
    auto pki = makePki("casource-toolarge-real");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto path = pki->files.caCertPath + ".huge";
    write(path, readAll(pki->files.caCertPath));

    CaCertificateSource source {path, pki->leaf.get()};
    const auto served = source.snapshot();
    ASSERT_EQ(served.certificates, 1U);

    // One byte past the cap, whatever it contains: readFileBounded() must refuse it without
    // caring what is inside -- the errno it hands back for this case is an implementation detail.
    write(path, std::string(CaCertificateSource::kMaxBytes + 1, 'x'));

    const auto rejected = source.snapshot();
    EXPECT_EQ(rejected.certificates, 1U);
    EXPECT_EQ(rejected.pem, served.pem);
    ASSERT_TRUE(rejected.lastReadFailure.has_value());
    EXPECT_EQ(rejected.lastReadFailure->status, ReadStatus::TooLarge);

    ::remove(path.c_str());
}

TEST(CaCertificateSource, IdenticalContentAfterAFailureIsACacheHit)
{
    auto pki = makePki("casource-cachehit-afterfail");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    FakeReader reader;
    reader.state->contents = readAll(pki->files.caCertPath);

    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get(), reader};
    ASSERT_EQ(source.snapshot().certificates, 1U);
    ASSERT_EQ(source.parses(), 1U);

    reader.state->status = ReadStatus::ReadError;
    reader.state->error = EIO;
    const auto failed = source.snapshot();
    ASSERT_TRUE(failed.lastReadFailure.has_value());

    // Repaired with the exact same bytes: still the same hash, so it is a cache hit -- no
    // reparse -- and the failure it recovered from is cleared.
    reader.state->status = ReadStatus::Ok;
    const auto recovered = source.snapshot();
    EXPECT_EQ(source.parses(), 1U);
    EXPECT_FALSE(recovered.lastReadFailure.has_value());
    EXPECT_EQ(recovered.certificates, 1U);
}

TEST(CaCertificateSource, ConcurrentReadersPublishTheNewestContent)
{
    auto a = makePki("casource-concurrent-a");
    auto b = makePki("casource-concurrent-b");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    remoted::test::ScratchFileCleanup cleanupA {a->files.files()};
    remoted::test::ScratchFileCleanup cleanupB {b->files.files()};

    const auto rawA = readAll(a->files.caCertPath);
    const auto rawB = readAll(b->files.caCertPath);
    const auto size = std::max(rawA.size(), rawB.size()) + 8;
    const auto paddedA = paddedTo(rawA, size);
    const auto paddedB = paddedTo(rawB, size);

    // The canonical form each content must reserialise to: what proves a snapshot read one of
    // the two whole, never a torn mix of both.
    const auto pemA = serializeCertificates(parseBundle(paddedA).certificates);
    const auto pemB = serializeCertificates(parseBundle(paddedB).certificates);
    ASSERT_FALSE(pemA.empty());
    ASSERT_FALSE(pemB.empty());
    const std::string cnA = "CN=casource-concurrent-a-ca";
    const std::string cnB = "CN=casource-concurrent-b-ca";

    const auto path = a->files.caCertPath + ".rotating";
    write(path, paddedA);
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, a->leaf.get()};
    std::atomic<std::size_t> violations {0};

    std::vector<std::thread> readers;
    for (int i = 0; i < 8; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                for (int call = 0; call < 200; ++call)
                {
                    const auto snapshot = source.snapshot();
                    const bool looksLikeA = snapshot.subjects.find(cnA) != std::string::npos;
                    const bool looksLikeB = snapshot.subjects.find(cnB) != std::string::npos;
                    if (looksLikeA && snapshot.pem != pemA)
                    {
                        ++violations;
                    }
                    if (looksLikeB && snapshot.pem != pemB)
                    {
                        ++violations;
                    }
                }
            });
    }

    // Rotates the file while the readers above are hammering snapshot(): the property under
    // test is that no reader ever sees B's subject paired with A's bytes or the other way
    // around -- not any particular interleaving, so there is nothing here worth a sleep for.
    // Each replacement is atomic (rename over the path): a truncated or half-written file would
    // be a legitimate third content -- empty, or refused whole -- and would count as a parse of
    // its own, which is not what the bound below is about.
    for (int i = 0; i < 20; ++i)
    {
        replaceAtomically(path, (i % 2 == 0) ? paddedA : paddedB);
    }

    for (auto& reader : readers)
    {
        reader.join();
    }

    EXPECT_EQ(violations.load(), 0U);

    // i = 19 (odd) wrote B last.
    const auto final = source.snapshot();
    EXPECT_EQ(final.pem, pemB);
    EXPECT_NE(final.subjects.find(cnB), std::string::npos);
    EXPECT_LE(source.parses(), 21U);
}

TEST(CaCertificateSource, ReadsNeverOverlapUnderTheMutex)
{
    // The direct proof of "the whole call, read included, runs under the mutex": a reader that
    // counts how many calls are inside it at once. With the read outside the lock, eight threads
    // hammering snapshot() would overlap inside the reader almost immediately; under the lock the
    // count can never exceed one. (ConcurrentReadersPublishTheNewestContent above checks
    // coherence, which the lock also guarantees but which a lock-free implementation could fake.)
    auto pki = makePki("casource-nooverlap");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    struct Counters
    {
        std::atomic<int> inFlight {0};
        std::atomic<int> maxInFlight {0};
        std::string contents;
    };
    auto counters = std::make_shared<Counters>();
    counters->contents = readAll(pki->files.caCertPath);

    remoted::http::FileReader reader =
        [counters](const std::string& /*path*/, std::size_t /*maxBytes*/, std::string& out)
    {
        const int now = ++counters->inFlight;
        int seen = counters->maxInFlight.load();
        while (seen < now && !counters->maxInFlight.compare_exchange_weak(seen, now))
        {
        }
        // Hold the "file" open for a while, so that a reader running outside the lock would be
        // caught overlapping for certain rather than by luck.
        const auto until = std::chrono::steady_clock::now() + std::chrono::microseconds {200};
        while (std::chrono::steady_clock::now() < until)
        {
            std::this_thread::yield();
        }
        out = counters->contents;
        --counters->inFlight;
        return remoted::http::ReadResult {};
    };

    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get(), reader};
    std::vector<std::thread> readers;
    for (int i = 0; i < 8; ++i)
    {
        readers.emplace_back(
            [&source]
            {
                for (int call = 0; call < 100; ++call)
                {
                    (void)source.snapshot();
                }
            });
    }
    for (auto& readerThread : readers)
    {
        readerThread.join();
    }

    EXPECT_EQ(counters->maxInFlight.load(), 1);
    EXPECT_EQ(counters->inFlight.load(), 0);
    EXPECT_EQ(source.parses(), 1U); // same bytes every time: one parse, 799 cache hits
}

TEST(CaCertificateSource, WithoutALeafTheVerdictIsUnknownRatherThanMismatch)
{
    auto pki = makePki("casource-noleaf");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    CaCertificateSource source {pki->files.caCertPath, nullptr};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.certificates, 1U);
    EXPECT_FALSE(snapshot.matchesLeaf.has_value()); // unknown serves; false would refuse
}

TEST(CaCertificateSource, SnapshotCarriesChainValid)
{
    auto pki = makePki("casource-chainvalid");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // generateCaSignedCertificate()'s CA is `openssl req -x509`, which OpenSSL 3 stamps
    // `basicConstraints = critical, CA:TRUE` on by default (testTlsServer.hpp), so the leaf it
    // signed VALIDATES against it as a trust anchor -- not just matches its signature.
    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.matchesLeaf, true);
    ASSERT_TRUE(snapshot.chainValid.has_value());
    EXPECT_TRUE(*snapshot.chainValid) << snapshot.chainError;
    EXPECT_TRUE(snapshot.chainError.empty()) << snapshot.chainError;

    // Without a leaf there is nothing to validate against: buildLocked() never calls
    // chainValidates() in that case, so chainValid stays nullopt (tlsCertificateStatus.cpp).
    CaCertificateSource noLeaf {pki->files.caCertPath, nullptr};
    EXPECT_FALSE(noLeaf.snapshot().chainValid.has_value());
}

TEST(CaCertificateSource, UnpublishedBundleVouchesAsZeroWithNoBlockFailure)
{
    auto pki = makePki("casource-unpublished");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // The state every bundle is in before the tool ever stamps it -- and the state every existing
    // installation is in: an ordinary CA file. It is served exactly as before; what it is not is
    // published, and `no_block` is how that is told apart from a broken stamp.
    CaCertificateSource source {pki->files.caCertPath, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.publication, 0);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::no_block);
    EXPECT_FALSE(snapshot.block.has_value());
    EXPECT_FALSE(snapshot.pem.empty());
    EXPECT_EQ(snapshot.matchesLeaf, true);
    EXPECT_EQ(snapshot.serializedBytes, snapshot.pem.size());
    EXPECT_EQ(snapshot.fileSha256.size(), 64U); // the FILE's hash, hex: what the record compares
}

TEST(CaCertificateSource, VouchesAPublishedBundleAndAnnouncesItsPublication)
{
    auto pki = makePki("casource-published");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto certificates = readPemCertificates(pki->files.caCertPath);
    ASSERT_EQ(certificates.size(), 1U);
    const auto path = pki->files.caCertPath + ".published";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.publication, kPublication);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::none);
    ASSERT_TRUE(snapshot.block.has_value());
    EXPECT_EQ(snapshot.block->publication, kPublication);
    EXPECT_EQ(snapshot.block->contentSha256, ca_bundle::contentSha256(certificates));
    EXPECT_EQ(snapshot.block->updated, "2026-09-18T00:00:00Z");
    EXPECT_EQ(snapshot.block->writtenBy, "caCertificateSource_test");

    // The `##` lines are the tool's; what is served is still the certificates alone.
    EXPECT_EQ(snapshot.pem, serializeCertificates(certificates));
    EXPECT_EQ(snapshot.pem.find("##"), std::string::npos);

    // And the verdict travels to the status the transport logs and publishes from.
    const auto status = statusFrom(pki->leaf.get(), snapshot);
    EXPECT_EQ(status.caPublication, kPublication);
    EXPECT_EQ(status.caVouchFailure, GuardFailure::none);
}

TEST(CaCertificateSource, RefusesToVouchWhenTheBlockHashDoesNotMatch)
{
    auto pki = makePki("casource-hashmismatch");
    auto other = makePki("casource-hashmismatch-other");
    ASSERT_TRUE(pki.has_value());
    ASSERT_TRUE(other.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};
    remoted::test::ScratchFileCleanup cleanupOther {other->files.files()};

    // A stamp that describes ANOTHER set of certificates: what a bundle edited by hand after the
    // tool stamped it looks like. The stamp is not transferable, and that is the point.
    const auto certificates = readPemCertificates(pki->files.caCertPath);
    const auto foreignHash = ca_bundle::contentSha256(readPemCertificates(other->files.caCertPath));
    const auto path = pki->files.caCertPath + ".mismatched";
    write(path, sealedDocument(certificates, kPublication, foreignHash));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.publication, 0);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::hash_mismatch);
    ASSERT_TRUE(snapshot.block.has_value());
    EXPECT_EQ(snapshot.block->contentSha256, foreignHash);

    // Refusing to vouch is not refusing to serve: the certificates read are handed out as ever,
    // and the agents bootstrapping from them are unaffected.
    EXPECT_EQ(snapshot.certificates, 1U);
    EXPECT_EQ(snapshot.pem, serializeCertificates(certificates));
    EXPECT_EQ(snapshot.matchesLeaf, true);
}

TEST(CaCertificateSource, RefusesToVouchWhenNoCertificateSignsTheLeaf)
{
    auto pki = makePki("casource-foreignca");
    auto foreign = makePki("casource-foreignca-other");
    ASSERT_TRUE(pki.has_value());
    ASSERT_TRUE(foreign.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};
    remoted::test::ScratchFileCleanup cleanupForeign {foreign->files.files()};

    // A perfectly good, properly stamped bundle -- of somebody else's CA. Publishing it would tell
    // agents to trust a generation that cannot verify this listener.
    const auto certificates = readPemCertificates(foreign->files.caCertPath);
    const auto path = pki->files.caCertPath + ".foreign";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.publication, 0);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::no_ca_signs_leaf);
    EXPECT_EQ(snapshot.matchesLeaf, false); // the 503 the endpoint already answered, unchanged
}

TEST(CaCertificateSource, RefusesToVouchWithoutAServedLeaf)
{
    auto pki = makePki("casource-noleaf-vouch");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto certificates = readPemCertificates(pki->files.caCertPath);
    const auto path = pki->files.caCertPath + ".noleaf";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    // With no served certificate to check against, nothing is vouched for: "unknown" still SERVES
    // (matchesLeaf stays nullopt, as it always did), but it never publishes a generation.
    CaCertificateSource source {path, nullptr};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.publication, 0);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::no_ca_signs_leaf);
    EXPECT_FALSE(snapshot.matchesLeaf.has_value());
    EXPECT_FALSE(snapshot.pem.empty());
}

TEST(CaCertificateSource, RefusesToVouchOverSixCertificates)
{
    auto pki = makePki("casource-toomany");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // The signer plus six fillers: seven certificates, one over the cap, and every earlier guard
    // passes (the stamp describes them all and the signer is among them), so the count is what
    // answers -- a bundle that grew past what an agent should be told to trust.
    auto certificates = readPemCertificates(pki->files.caCertPath);
    auto key = remoted::test::makeTestKey();
    for (std::size_t index = 0; index < ca_bundle::kMaxCertificates; ++index)
    {
        certificates.push_back(fillerCertificate(key.get(), "casource-toomany-filler-" + std::to_string(index)));
    }
    ASSERT_EQ(certificates.size(), ca_bundle::kMaxCertificates + 1);

    const auto path = pki->files.caCertPath + ".toomany";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.certificates, ca_bundle::kMaxCertificates + 1);
    EXPECT_EQ(snapshot.publication, 0);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::too_many_certificates);
    EXPECT_EQ(snapshot.matchesLeaf, true); // still servable, just not publishable
}

TEST(CaCertificateSource, RefusesToVouchOverTheByteCap)
{
    auto pki = makePki("casource-toobig");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // Three certificates, two of them fat with subjectAltName entries, so what the source would
    // hand out is over the cap while the count is well under it: the guard measures the document
    // an agent would have to download, not how many certificates produced it.
    auto certificates = readPemCertificates(pki->files.caCertPath);
    auto key = remoted::test::makeTestKey();
    certificates.push_back(fillerCertificate(key.get(), "casource-toobig-filler-0", 5000));
    certificates.push_back(fillerCertificate(key.get(), "casource-toobig-filler-1", 5000));
    ASSERT_LE(certificates.size(), ca_bundle::kMaxCertificates);
    ASSERT_GT(serializeCertificates(certificates).size(), ca_bundle::kMaxSerializedBytes);

    const auto path = pki->files.caCertPath + ".toobig";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    const auto snapshot = source.snapshot();

    EXPECT_EQ(snapshot.publication, 0);
    EXPECT_EQ(snapshot.vouchFailure, GuardFailure::too_many_bytes);
    EXPECT_GT(snapshot.serializedBytes, ca_bundle::kMaxSerializedBytes);
    EXPECT_EQ(snapshot.matchesLeaf, true);
}

TEST(CaCertificateSource, AnEmptyPathNeverReadsAnything)
{
    CaCertificateSource source {"", nullptr};
    EXPECT_EQ(source.snapshot().certificates, 0U);
    EXPECT_EQ(source.parses(), 0U);
}

TEST(CaCertificateSourceDescriptor, DoesNotReadWhenNoPathIsConfigured)
{
    // snapshot() has always had this guard; descriptor() must too -- without it, a source with
    // nothing configured would open "" once per refresh window forever, one CannotOpen at a time.
    const CountingReader reader;
    CaCertificateSource source {"", nullptr, reader};

    for (int call = 0; call < 3; ++call)
    {
        EXPECT_FALSE(source.descriptor().generation.has_value()) << "call " << call;
    }

    EXPECT_EQ(reader.calls->load(), 0);
}

TEST(CaCertificateSourceDescriptor, RevalidatesAtMostOnceWithinTheRefreshWindow)
{
    auto pki = makePki("casource-descriptor-window");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto certificates = readPemCertificates(pki->files.caCertPath);
    const auto path = pki->files.caCertPath + ".descriptor";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    const CountingReader reader;
    const TestClock clock;
    CaCertificateSource source {path, pki->leaf.get(), reader, clock};

    // A notify storm asks this once per notify. Inside the window they cost one read between them:
    // that is the whole budget the feature is allowed on the hot path (C18, CA-15).
    for (int call = 0; call < 100; ++call)
    {
        const auto descriptor = source.descriptor();
        ASSERT_TRUE(descriptor.generation.has_value()) << "call " << call;
        EXPECT_EQ(*descriptor.generation, kPublication) << "call " << call;
    }

    EXPECT_EQ(reader.calls->load(), 1);
    EXPECT_EQ(source.parses(), 1U);
}

TEST(CaCertificateSourceDescriptor, RevalidatesAgainAfterTheWindowElapsesAndShowsTheNewPublication)
{
    auto pki = makePki("casource-descriptor-rotation");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto certificates = readPemCertificates(pki->files.caCertPath);
    const auto path = pki->files.caCertPath + ".rotating-descriptor";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    const CountingReader reader;
    const TestClock clock;
    CaCertificateSource source {path, pki->leaf.get(), reader, clock};

    for (int call = 0; call < 100; ++call)
    {
        (void)source.descriptor();
    }
    ASSERT_EQ(reader.calls->load(), 1);

    // The master re-stamped the bundle. One window later the next caller reads for real and sees
    // the new generation -- no restart, no daily tick.
    replaceAtomically(path, sealedDocument(certificates, kNewerPublication));
    *clock.now += CaCertificateSource::kDescriptorRefresh;

    const auto descriptor = source.descriptor();
    EXPECT_EQ(reader.calls->load(), 2);
    ASSERT_TRUE(descriptor.generation.has_value());
    EXPECT_EQ(*descriptor.generation, kNewerPublication);
    EXPECT_EQ(source.parses(), 2U);
}

TEST(CaCertificateSourceDescriptor, HonoursTheFullRefreshWindow)
{
    // The two tests above only ever check the boundary at exactly kDescriptorRefresh; a window one
    // millisecond short of a second would pass them just the same. This one pins the edges: one
    // millisecond before the window closes the answer must still be the old generation from a
    // single read, and the millisecond that closes it must revalidate for real.
    auto pki = makePki("casource-descriptor-boundary");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto certificates = readPemCertificates(pki->files.caCertPath);
    const auto path = pki->files.caCertPath + ".boundary";
    write(path, sealedDocument(certificates, kPublication));
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    const CountingReader reader;
    const TestClock clock;
    CaCertificateSource source {path, pki->leaf.get(), reader, clock};

    const auto first = source.descriptor();
    ASSERT_EQ(reader.calls->load(), 1);
    ASSERT_TRUE(first.generation.has_value());
    EXPECT_EQ(*first.generation, kPublication);

    // The master re-stamps the bundle right away; still inside the window, so the answer must not
    // move and the file must not be reopened.
    replaceAtomically(path, sealedDocument(certificates, kNewerPublication));
    *clock.now += std::chrono::milliseconds {999};

    const auto stillInsideTheWindow = source.descriptor();
    EXPECT_EQ(reader.calls->load(), 1);
    ASSERT_TRUE(stillInsideTheWindow.generation.has_value());
    EXPECT_EQ(*stillInsideTheWindow.generation, kPublication);

    // The last millisecond of the window: a full second has now passed since the first read, and
    // this call is the one that revalidates and sees the new generation.
    *clock.now += std::chrono::milliseconds {1};

    const auto afterTheWindow = source.descriptor();
    EXPECT_EQ(reader.calls->load(), 2);
    ASSERT_TRUE(afterTheWindow.generation.has_value());
    EXPECT_EQ(*afterTheWindow.generation, kNewerPublication);
}

TEST(CaCertificateSourceDescriptor, IsNulloptWhenNoBundleIsServable)
{
    auto pki = makePki("casource-descriptor-empty");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    // Nothing servable is not "published as 0": the notify path tells the two apart, so an agent
    // can distinguish a manager with no bundle at all from one whose bundle is unstamped.
    const auto path = pki->files.caCertPath + ".emptied";
    write(path, std::string {});
    remoted::test::ScratchFileCleanup cleanupPath {{path}};

    CaCertificateSource source {path, pki->leaf.get()};
    EXPECT_FALSE(source.descriptor().generation.has_value());
}

TEST(ParsedBundle, SerialisationRoundTripsAndDropsEverythingElse)
{
    auto pki = makePki("pem-roundtrip");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto combined = readAll(pki->files.caCertPath) + readAll(pki->files.caKeyPath);
    const auto parsed = parseBundle(combined);
    ASSERT_TRUE(parsed.wellFormed);
    ASSERT_EQ(parsed.certificates.size(), 1U);

    const auto serialised = serializeCertificates(parsed.certificates);
    EXPECT_EQ(serialised.find("PRIVATE KEY"), std::string::npos);

    // What we emit parses back to the same certificate: the published document is usable, not
    // merely stripped.
    const auto reparsed = parseBundle(serialised);
    EXPECT_TRUE(reparsed.wellFormed);
    EXPECT_EQ(reparsed.certificates.size(), 1U);
    EXPECT_EQ(serializeCertificates(reparsed.certificates), serialised);
}

TEST(ReadFileBounded, ReadsUpToTheCapAndFlagsMore)
{
    const auto path = "/tmp/casource-readfilebounded_" + std::to_string(::getpid());
    remoted::test::ScratchFileCleanup cleanup {{path}};

    constexpr std::size_t n = 4096;
    write(path, std::string(n, 'x'));

    std::string contents;
    auto result = readFileBounded(path, n, contents);
    EXPECT_EQ(result.status, ReadStatus::Ok);
    EXPECT_EQ(contents.size(), n);

    // One byte over: TooLarge, not a truncated Ok.
    write(path, std::string(n + 1, 'x'));
    result = readFileBounded(path, n, contents);
    EXPECT_EQ(result.status, ReadStatus::TooLarge);

    result = readFileBounded(path + ".nope", n, contents);
    EXPECT_EQ(result.status, ReadStatus::CannotOpen);
    EXPECT_EQ(result.error, ENOENT);

    const auto dirPath = path + ".dir";
    ASSERT_EQ(::mkdir(dirPath.c_str(), 0755), 0);
    result = readFileBounded(dirPath, n, contents);
    EXPECT_EQ(result.status, ReadStatus::ReadError);
    EXPECT_EQ(result.error, EISDIR);
    ::rmdir(dirPath.c_str());
}

TEST(FileRead, DescribesEachCause)
{
    // The log-line fragment describeReadFailure() completes "the file ...", one per ReadStatus --
    // and, for TooLarge, worded off the actual cap rather than a hardcoded "1 MiB".
    EXPECT_EQ(describeReadFailure(ReadFailure {ReadStatus::CannotOpen, ENOENT, 1}, 1024U * 1024U),
              "cannot be opened (No such file or directory)");
    EXPECT_EQ(describeReadFailure(ReadFailure {ReadStatus::ReadError, EISDIR, 1}, 1024U * 1024U),
              "cannot be read (Is a directory)");
    EXPECT_EQ(describeReadFailure(ReadFailure {ReadStatus::TooLarge, 0, 1}, 1024U * 1024U),
              "is larger than the 1 MiB cap");
    EXPECT_EQ(describeReadFailure(ReadFailure {ReadStatus::TooLarge, 0, 1}, 4096U), "is larger than the 4096-byte cap");
}

TEST(ReadFileBounded, RefusesANonRegularFile)
{
    // A FIFO with no writer: a blocking open() would park the caller -- and, since the source reads
    // under its mutex, every other caller with it. O_NONBLOCK gets the descriptor at once and the
    // fstat() check refuses anything that is not a regular file before the first read.
    const auto fifo = "/tmp/casource-fifo_" + std::to_string(::getpid());
    ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
    remoted::test::ScratchFileCleanup cleanup {{fifo}};

    std::string contents;
    const auto result = readFileBounded(fifo, 4096, contents);
    EXPECT_EQ(result.status, ReadStatus::ReadError);
    EXPECT_EQ(result.error, ENOTSUP);
    EXPECT_TRUE(contents.empty());
}
