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
 *        and a cache keyed by content so a replacement is seen at once (issue #39078, H01 and H06).
 *
 * Real certificates throughout (testTlsServer.hpp's throwaway PKI): the point of the class is what
 * OpenSSL makes of the bytes, so parsing them for real is the test.
 */

#include <gtest/gtest.h>

#include "http_server/caCertificateSource.hpp"
#include "http_server/fileRead.hpp"
#include "testCertificates.hpp"
#include "testTlsServer.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
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

using remoted::http::CaCertificateSource;
using remoted::http::describeReadFailure;
using remoted::http::parseCertificates;
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
        return parseCertificates(readAll(path)).certificates;
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
    const auto pemA = serializeCertificates(parseCertificates(paddedA).certificates);
    const auto pemB = serializeCertificates(parseCertificates(paddedB).certificates);
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

TEST(CaCertificateSource, AnEmptyPathNeverReadsAnything)
{
    CaCertificateSource source {"", nullptr};
    EXPECT_EQ(source.snapshot().certificates, 0U);
    EXPECT_EQ(source.parses(), 0U);
}

TEST(PemCertificates, SerialisationRoundTripsAndDropsEverythingElse)
{
    auto pki = makePki("pem-roundtrip");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto combined = readAll(pki->files.caCertPath) + readAll(pki->files.caKeyPath);
    const auto parsed = parseCertificates(combined);
    ASSERT_TRUE(parsed.wellFormed);
    ASSERT_EQ(parsed.certificates.size(), 1U);

    const auto serialised = serializeCertificates(parsed.certificates);
    EXPECT_EQ(serialised.find("PRIVATE KEY"), std::string::npos);

    // What we emit parses back to the same certificate: the published document is usable, not
    // merely stripped.
    const auto reparsed = parseCertificates(serialised);
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
