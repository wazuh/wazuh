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
#include "testTlsServer.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <utime.h>

using remoted::http::CaCertificateSource;
using remoted::http::loadCertificates;
using remoted::http::parseCertificates;
using remoted::http::serializeCertificates;

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

        auto leaves = loadCertificates(generated->certPath);
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

TEST(CaCertificateSource, MissingFileClearsThePreviousSnapshot)
{
    auto pki = makePki("casource-vanish");
    ASSERT_TRUE(pki.has_value());
    remoted::test::ScratchFileCleanup cleanup {pki->files.files()};

    const auto path = pki->files.caCertPath + ".vanishing";
    write(path, readAll(pki->files.caCertPath));

    CaCertificateSource source {path, pki->leaf.get()};
    EXPECT_EQ(source.snapshot().certificates, 1U);

    ::remove(path.c_str());
    const auto gone = source.snapshot();
    EXPECT_EQ(gone.certificates, 0U);
    EXPECT_TRUE(gone.pem.empty());

    // And it comes back without a restart.
    write(path, readAll(pki->files.caCertPath));
    EXPECT_EQ(source.snapshot().certificates, 1U);
    ::remove(path.c_str());
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
