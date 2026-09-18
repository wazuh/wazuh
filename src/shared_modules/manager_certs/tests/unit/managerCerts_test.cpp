/*
 * Wazuh manager certs tool - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// In-process tests of `inspect`/`check` (manager_certs/commands.hpp): both are pure functions over
// an already-parsed ca_bundle::ParsedBundle and a leaf X509*, so every case here builds its PKI and
// bundle bytes in memory (../testPki.hpp) and calls runInspect()/runCheck() directly -- no
// subprocess, no compiled `wazuh-manager-certs` binary. main.cpp's own environment behaviour
// (config/bundle/leaf resolution, --version/--help with no configuration) is end-to-end territory
// for tests/cli/manager_certs_cli_test.sh instead, which runs outside this GTest binary: the ASAN
// job (5_testunit_managercerts.yml) selects only this binary's `manager_certs_utest` label and
// never builds `wazuh-manager-certs`, so this suite has to stay self-contained.

#include "manager_certs/commands.hpp"
#include "testPki.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

using manager_certs::runCheck;
using manager_certs::runInspect;
using manager_certs::test::makeCertificate;
using manager_certs::test::makeTestKey;

namespace
{
    constexpr long kDay = 24L * 60L * 60L;

    /// A publication block covering @p certificates, ready to prepend to serializeCertificates().
    ca_bundle::PublicationBlock blockFor(const std::vector<ca_bundle::X509Ptr>& certificates, std::int64_t publication)
    {
        ca_bundle::PublicationBlock block;
        block.publication = publication;
        block.contentSha256 = ca_bundle::contentSha256(certificates);
        block.updated = "2026-09-18T00:00:00Z";
        block.writtenBy = "manager_certs_utest";
        return block;
    }

    /// renderBlock() + serializeCertificates(): the exact shape `wazuh-manager-certs` would write.
    std::string sealedBundleText(const std::vector<ca_bundle::X509Ptr>& certificates, std::int64_t publication)
    {
        return ca_bundle::renderBlock(blockFor(certificates, publication)) +
               ca_bundle::serializeCertificates(certificates);
    }

    /// Independent copy of inspect.cpp's own formatUtc(): re-derived here rather than called,
    /// so this test does not exercise the very formatting logic it is trying to pin (a bug that
    /// changed the format would move both the same way and the assertion below would still pass).
    std::string expectedNotAfterLine(std::time_t epochSeconds)
    {
        struct tm parts {};
        gmtime_r(&epochSeconds, &parts);
        char buffer[32];
        const std::size_t written = std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &parts);
        return std::string {buffer, written};
    }

    /// Whether @p output contains a "notAfter: <iso> (<days> days remaining)" line for @p iso, with
    /// the day count within 1 of @p expectedDays -- a tolerance of exactly one day, not an open
    /// range, so the check still fails hard on a wrong offset, a missing days field, or the
    /// "0 days remaining" stub objection #11 named, while absorbing the few milliseconds between
    /// this test's own std::time(nullptr) and runInspect()'s.
    bool hasNotAfterLine(const std::string& output, const std::string& iso, long expectedDays)
    {
        for (long delta = -1; delta <= 1; ++delta)
        {
            const std::string needle =
                "notAfter: " + iso + " (" + std::to_string(expectedDays + delta) + " days remaining)\n";
            if (output.find(needle) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

    /// A temporary directory (mkdtemp), removed recursively when it goes out of scope: only the
    /// file-unchanged case needs an on-disk bundle at all.
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = (std::filesystem::temp_directory_path() / "manager_certs_utest_XXXXXX").string();
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');
            if (mkdtemp(buffer.data()) == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for manager_certs_utest fixtures");
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

} // namespace

// ------------------------------------------------------------------------------------- inspect ---

TEST(ManagerCertsInspect, SealedTwoCaBundleListsBothCertificatesAndVouchedYes)
{
    auto caAKey = makeTestKey();
    auto rootBKey = makeTestKey();
    auto caBKey = makeTestKey();
    auto leafKey = makeTestKey();

    // caA: a root, self-signed like every real trust anchor (issuer == subject for it is correct,
    // not a fixture bug). caB: an INTERMEDIATE, issued by rootB (never itself added to the bundle)
    // -- so caB.issuer != caB.subject, which is what makes the issuer assertion below meaningful:
    // with two self-signed certificates, printing "issuer: <subject>" by mistake would satisfy an
    // `output.find("issuer: " + facts.issuer)` check just as well as the real field would
    // (objection #11).
    auto caA = makeCertificate("ca-a", -kDay, 400 * kDay, caAKey.get(), caAKey.get(), nullptr, true, 1);
    auto rootB = makeCertificate("root-b", -kDay, 400 * kDay, rootBKey.get(), rootBKey.get(), nullptr, true, 10);
    auto caB = makeCertificate("ca-b", -kDay, 400 * kDay, caBKey.get(), rootBKey.get(), rootB.get(), true, 2);
    auto leaf = makeCertificate("leaf", -kDay, 90 * kDay, leafKey.get(), caAKey.get(), caA.get(), false, 3);

    // Facts computed BEFORE the certificates are moved into the bundle vector, against the leaf
    // that is signed by caA: this is what runInspect() must reproduce over the re-parsed bundle.
    const ca_bundle::CertificateFacts caAFacts = ca_bundle::describe(caA.get(), leaf.get());
    const ca_bundle::CertificateFacts caBFacts = ca_bundle::describe(caB.get(), leaf.get());
    ASSERT_TRUE(caAFacts.signsLeaf);
    ASSERT_FALSE(caBFacts.signsLeaf);
    ASSERT_EQ(caAFacts.issuer, caAFacts.subject); // root: genuinely self-signed
    ASSERT_NE(caBFacts.issuer, caBFacts.subject); // intermediate: the fixture this test needs

    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(std::move(caA));
    certificates.push_back(std::move(caB));

    constexpr std::int64_t kPublication = 1758150000;
    const std::time_t beforeInspect = std::time(nullptr);
    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(sealedBundleText(certificates, kPublication));
    ASSERT_TRUE(bundle.wellFormed);
    ASSERT_EQ(bundle.certificates.size(), 2u);
    ASSERT_TRUE(bundle.block.has_value());

    std::ostringstream out;
    EXPECT_EQ(runInspect(bundle, leaf.get(), out), 0);
    const std::string output = out.str();

    EXPECT_NE(output.find("subject: " + caAFacts.subject), std::string::npos) << output;
    EXPECT_NE(output.find("issuer: " + caAFacts.issuer), std::string::npos) << output;
    EXPECT_NE(output.find("identity: " + caAFacts.identity + "\nsignsLeaf: yes\n"), std::string::npos) << output;
    EXPECT_NE(output.find("subject: " + caBFacts.subject), std::string::npos) << output;
    EXPECT_NE(output.find("issuer: " + caBFacts.issuer), std::string::npos) << output;
    // Never "issuer: " + caBFacts.subject: with a distinct issuer this cannot pass by accident.
    EXPECT_EQ(output.find("issuer: " + caBFacts.subject), std::string::npos) << output;
    EXPECT_NE(output.find("identity: " + caBFacts.identity + "\nsignsLeaf: no\n"), std::string::npos) << output;

    // notAfter + days remaining, for BOTH certificates, against an independently-formatted date
    // and a tolerant-but-bounded day count (objection #11: a literal "days remaining)" substring
    // check, as this test used to have, passes even for "0 days remaining)" on a 400-day-out cert).
    const long expectedDaysA = static_cast<long>(caAFacts.notAfter - beforeInspect) / kDay;
    const long expectedDaysB = static_cast<long>(caBFacts.notAfter - beforeInspect) / kDay;
    EXPECT_TRUE(hasNotAfterLine(output, expectedNotAfterLine(caAFacts.notAfter), expectedDaysA)) << output;
    EXPECT_TRUE(hasNotAfterLine(output, expectedNotAfterLine(caBFacts.notAfter), expectedDaysB)) << output;

    EXPECT_NE(output.find("publication: " + std::to_string(kPublication) + "\n"), std::string::npos) << output;
    EXPECT_NE(output.find("vouched: yes\n"), std::string::npos) << output;
}

TEST(ManagerCertsInspect, PlainPemReportsPublicationZeroUnpublished)
{
    auto caKey = makeTestKey();
    auto ca = makeCertificate("ca-plain", -kDay, 400 * kDay, caKey.get(), caKey.get(), nullptr, true, 1);

    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(std::move(ca));
    const std::string plainPem = ca_bundle::serializeCertificates(certificates); // no `##` block at all

    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(plainPem);
    ASSERT_TRUE(bundle.wellFormed);
    ASSERT_FALSE(bundle.block.has_value());

    std::ostringstream out;
    EXPECT_EQ(runInspect(bundle, nullptr, out), 0);
    const std::string output = out.str();

    EXPECT_NE(output.find("publication: 0 (unpublished)\n"), std::string::npos) << output;
    EXPECT_NE(output.find("vouched: no\n"), std::string::npos) << output;
}

// --------------------------------------------------------------------------------------- check ---

TEST(ManagerCertsCheck, ValidBundleExitsZeroAndLeavesFileUnchanged)
{
    auto caKey = makeTestKey();
    auto leafKey = makeTestKey();
    auto ca = makeCertificate("ca-valid", -kDay, 400 * kDay, caKey.get(), caKey.get(), nullptr, true, 1);
    auto leaf = makeCertificate("leaf-valid", -kDay, 90 * kDay, leafKey.get(), caKey.get(), ca.get(), false, 2);

    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(std::move(ca));
    const std::string text = sealedBundleText(certificates, 1758150000);

    TempDir dir;
    const auto bundlePath = dir.path() / "root-ca.pem";
    writeFile(bundlePath, text);
    const std::string before = readFile(bundlePath);

    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(before);
    ASSERT_TRUE(bundle.block.has_value());
    const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();

    std::ostringstream err;
    EXPECT_EQ(runCheck(bundle, leaf.get(), serializedBytes, err), 0);
    EXPECT_TRUE(err.str().empty()) << err.str();

    // check() never opens the bundle at all (it works over what main.cpp already parsed into
    // memory): the file on disk is exactly what it was before the call. That also means this
    // assertion can never catch a regression IN main.cpp itself (the only thing here that ever
    // opens a file) -- tests/cli/manager_certs_cli_test.sh's cli_check_accepts_real_bundle_and_
    // leaves_it_unchanged exercises the compiled binary end to end for that (objection #7).
    EXPECT_EQ(readFile(bundlePath), before);
}

TEST(ManagerCertsCheck, SevenCertificatesExitsNonZeroNamingTheCount)
{
    std::vector<ca_bundle::X509Ptr> certificates;
    ca_bundle::X509Ptr leaf;
    for (int i = 0; i < 7; ++i)
    {
        auto caKey = makeTestKey();
        auto ca = makeCertificate(
            ("ca-" + std::to_string(i)).c_str(), -kDay, 400 * kDay, caKey.get(), caKey.get(), nullptr, true, i + 1);
        if (i == 0)
        {
            // The leaf signs against the FIRST ca, still reachable at ca.get() before the move
            // below: `anyCaSignsLeaf` must pass so the bundle fails on the count, not on the leaf.
            auto leafKey = makeTestKey();
            leaf = makeCertificate("leaf-seven", -kDay, 90 * kDay, leafKey.get(), caKey.get(), ca.get(), false, 100);
        }
        certificates.push_back(std::move(ca));
    }

    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(sealedBundleText(certificates, 1758150000));
    ASSERT_EQ(bundle.certificates.size(), 7u);
    ASSERT_TRUE(bundle.block.has_value());
    const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();

    std::ostringstream err;
    EXPECT_EQ(runCheck(bundle, leaf.get(), serializedBytes, err), 1);
    EXPECT_NE(err.str().find("7 certificates (max 6)"), std::string::npos) << err.str();
}

TEST(ManagerCertsCheck, NoCaSignsLeafExitsNonZeroNamingTheGuard)
{
    auto caKey = makeTestKey();
    auto ca = makeCertificate("ca-orphan", -kDay, 400 * kDay, caKey.get(), caKey.get(), nullptr, true, 1);

    // The leaf is signed by a CA that never goes into the bundle: only `ca` does.
    auto foreignKey = makeTestKey();
    auto foreignLeafKey = makeTestKey();
    auto foreignCa =
        makeCertificate("foreign-ca", -kDay, 400 * kDay, foreignKey.get(), foreignKey.get(), nullptr, true, 2);
    auto leaf = makeCertificate(
        "leaf-orphan", -kDay, 90 * kDay, foreignLeafKey.get(), foreignKey.get(), foreignCa.get(), false, 3);

    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(std::move(ca));
    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(sealedBundleText(certificates, 1758150000));
    ASSERT_TRUE(bundle.block.has_value());
    const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();

    std::ostringstream err;
    EXPECT_EQ(runCheck(bundle, leaf.get(), serializedBytes, err), 1);
    EXPECT_NE(err.str().find("no CA signs the served leaf"), std::string::npos) << err.str();
}

// RF-12 / 02-diseno.md §2.6: ca_bundle::vouch() does not evaluate isCa or the validity window, so
// check() owns both itself, per certificate (commands.hpp). These two cases pin that: vouch()'s own
// six guards all pass (the certificate signs the leaf, the hash matches, the bundle is small), and
// only the per-certificate guard added on top of vouch() is what fails.

TEST(ManagerCertsCheck, ExpiredCertificateExitsNonZeroNamingTheIdentity)
{
    auto caKey = makeTestKey();
    auto leafKey = makeTestKey();
    // Valid window entirely in the past: expired one day ago. anyCaSignsLeaf() is a signature
    // check only (no dates), so vouch() still passes on this certificate.
    auto ca = makeCertificate("ca-expired", -400 * kDay, -1 * kDay, caKey.get(), caKey.get(), nullptr, true, 1);
    auto leaf = makeCertificate("leaf-expired", -kDay, 90 * kDay, leafKey.get(), caKey.get(), ca.get(), false, 2);
    const std::string expectedIdentity = ca_bundle::identityOf(ca.get());

    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(std::move(ca));
    const std::string text = sealedBundleText(certificates, 1758150000);

    TempDir dir;
    const auto bundlePath = dir.path() / "root-ca.pem";
    writeFile(bundlePath, text);
    const std::string before = readFile(bundlePath);

    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(before);
    ASSERT_TRUE(bundle.block.has_value());
    const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();

    std::ostringstream err;
    EXPECT_EQ(runCheck(bundle, leaf.get(), serializedBytes, err), 1);
    EXPECT_NE(err.str().find(expectedIdentity + ": expired"), std::string::npos) << err.str();
    // Same caveat as ManagerCertsCheck.ValidBundleExitsZeroAndLeavesFileUnchanged: runCheck() never
    // touches disk, so this cannot catch main.cpp truncating the file on a REJECTION; the CLI
    // suite's cli_check_rejects_bad_hash_and_leaves_it_unchanged does, against the real binary.
    EXPECT_EQ(readFile(bundlePath), before);
}

TEST(ManagerCertsCheck, NonCaCertificateExitsNonZeroNamingTheIdentity)
{
    auto notCaKey = makeTestKey();
    auto leafKey = makeTestKey();
    // isCa=false (the default): no basicConstraints/keyUsage extensions at all, so describe()
    // reads isCa=false -- the same X509_check_ca() behaviour ca_bundle_test.cpp's own leaf case
    // pins (ca_bundle_test.cpp:728). Signing a leaf does not require the CA extension either
    // (OpenSSL only enforces it at chain-validation time, which ca_bundle deliberately skips), so
    // vouch()'s no_ca_signs_leaf guard still passes.
    auto notCa = makeCertificate("not-a-ca", -kDay, 400 * kDay, notCaKey.get(), notCaKey.get(), nullptr, false, 1);
    auto leaf = makeCertificate("leaf-not-ca", -kDay, 90 * kDay, leafKey.get(), notCaKey.get(), notCa.get(), false, 2);
    const std::string expectedIdentity = ca_bundle::identityOf(notCa.get());

    std::vector<ca_bundle::X509Ptr> certificates;
    certificates.push_back(std::move(notCa));
    const std::string text = sealedBundleText(certificates, 1758150000);

    TempDir dir;
    const auto bundlePath = dir.path() / "root-ca.pem";
    writeFile(bundlePath, text);
    const std::string before = readFile(bundlePath);

    const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(before);
    ASSERT_TRUE(bundle.block.has_value());
    const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();

    std::ostringstream err;
    EXPECT_EQ(runCheck(bundle, leaf.get(), serializedBytes, err), 1);
    EXPECT_NE(err.str().find(expectedIdentity + ": not a CA"), std::string::npos) << err.str();
    // See ValidBundleExitsZeroAndLeavesFileUnchanged above: real disk-safety coverage on rejection
    // is the CLI suite's job, not this in-process call's.
    EXPECT_EQ(readFile(bundlePath), before);
}
