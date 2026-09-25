/*
 * Wazuh manager certs tool - unit tests for `--from-master`
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// In-process tests of the worker's pull (plan-E8, `anexos/e8/tls-transporte.md`): the twelve guards
// of runFromMaster() in their fixed order, the branch finishWrite() grew for a publication that is
// not this node's clock, and -- through the CurlPort seam -- the options the real transport pins on
// the connection before it sends anything.
//
// Two seams, for two different things that cannot be produced any other way:
//
//   MasterTransport  a master that answers with a 302, with no header, with `banana`, with a body
//                    that does not parse, or not at all. Every case below that ends in an exit code
//                    goes through it, so none of them needs a network.
//   CurlPort         what libcurl was ASKED for. A test cannot make CURLOPT_CAINFO_BLOB fail on a
//                    real handle, and it cannot see from outside that CURLOPT_CAPATH was cleared --
//                    and those two are exactly where the connection stops being verified against
//                    the local bundle without anybody noticing (C39a, objections 1 and 2). The
//                    handshake itself, which no seam can fake, is the component test's job
//                    (tests/component/manager_certs_from_master_test.sh).
//
// Like the write suite next door, every rejection asserts three things, because they are the
// contract (RF-8/CA-19): the exit code, the message an operator reads, and the local bundle's
// SHA-256 being unchanged.

#include "commands/atomicWrite.hpp"
#include "commands/masterTransport.hpp"
#include "manager_certs/commands.hpp"
#include "testPki.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <gtest/gtest.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using manager_certs::bytesSha256;
using manager_certs::curlMasterTransport;
using manager_certs::CurlPort;
using manager_certs::finishWrite;
using manager_certs::fromMasterEnvironmentFailure;
using manager_certs::FromMasterRequest;
using manager_certs::MasterFetch;
using manager_certs::MasterFetchFailure;
using manager_certs::MasterFetchResult;
using manager_certs::MasterTransport;
using manager_certs::prepareWrite;
using manager_certs::runFromMaster;
using manager_certs::WriteContext;
using manager_certs::WriteOutcome;
using manager_certs::WriteRequest;
using manager_certs::test::makeCertificate;
using manager_certs::test::makeTestKey;
using manager_certs::test::retain;

namespace
{
    constexpr long kDay = 24L * 60L * 60L;
    constexpr const char* kBundleName = "root-ca.pem";
    constexpr std::int64_t kLocalPublication = 1'700'000'000;

/// Every case that opens the transaction needs a root-owned lock file (C36f), exactly like the
/// write suite: production refuses anything else (G0) and CI runs as root.
#define SKIP_UNLESS_ROOT()                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::geteuid() != 0)                                                                                          \
        {                                                                                                              \
            GTEST_SKIP() << "the write transaction requires a root-owned lock file (euid 0)";                          \
        }                                                                                                              \
    } while (false)

    /// A temporary directory (mkdtemp), removed recursively when it goes out of scope. A copy of
    /// the write suite's, for the same reason it is a copy of the inspect/check suite's: these
    /// suites share ../testPki.hpp and nothing else.
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = (std::filesystem::temp_directory_path() / "manager_certs_pull_XXXXXX").string();
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');
            if (mkdtemp(buffer.data()) == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for manager_certs_utest --from-master fixtures");
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

    /// Adds a comment extension of @p bytes characters to @p certificate and re-signs it: the
    /// cheapest way to push a bundle past the serialised byte cap (the write suite's own copy
    /// documents why a long subject would not do it).
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

    /// The PKI every case shares: a CA that signs the served leaf (what a healthy master would be
    /// publishing), and an unrelated one that does not (what must never be installed here).
    struct Pki
    {
        manager_certs::test::EvpPkeyPtr caKey {nullptr, &EVP_PKEY_free};
        manager_certs::test::EvpPkeyPtr strangerKey {nullptr, &EVP_PKEY_free};
        manager_certs::test::EvpPkeyPtr leafKey {nullptr, &EVP_PKEY_free};
        ca_bundle::X509Ptr ca;
        ca_bundle::X509Ptr stranger;
        ca_bundle::X509Ptr leaf;
    };

    Pki makePki()
    {
        Pki pki;
        pki.caKey = makeTestKey();
        pki.strangerKey = makeTestKey();
        pki.leafKey = makeTestKey();
        pki.ca = makeCertificate("from-master-ca", -kDay, 400 * kDay, pki.caKey.get(), pki.caKey.get(), nullptr, true);
        pki.stranger = makeCertificate(
            "from-master-stranger", -kDay, 400 * kDay, pki.strangerKey.get(), pki.strangerKey.get(), nullptr, true, 7);
        pki.leaf = makeCertificate(
            "from-master-leaf", -kDay, 90 * kDay, pki.leafKey.get(), pki.caKey.get(), pki.ca.get(), false, 2);
        return pki;
    }

    std::vector<ca_bundle::X509Ptr> justOne(const X509* certificate)
    {
        std::vector<ca_bundle::X509Ptr> one;
        one.push_back(retain(certificate));
        return one;
    }

    /// A master that answers whatever the case tells it to, recording what it was asked for.
    struct StubMaster
    {
        MasterFetchResult response;
        std::vector<MasterFetch> asked;
    };

    MasterTransport transportOf(StubMaster& stub)
    {
        MasterTransport transport;
        transport.get = [&stub](const MasterFetch& request)
        {
            stub.asked.push_back(request);
            return stub.response;
        };
        return transport;
    }

    /// A complete 200 carrying @p body and announcing @p generation.
    MasterFetchResult answer(std::string body, const std::string& generation)
    {
        MasterFetchResult result;
        result.httpStatus = 200;
        result.body = std::move(body);
        result.generation = generation;
        return result;
    }

    /// What one run of `--from-master` did, plus the local bundle's hash afterwards.
    struct PullOutcome
    {
        int exitCode {0};
        std::string out;
        std::string err;
        std::string hash;
    };

    /// One `--from-master` over @p bundlePath, with @p stub standing in for the master.
    PullOutcome
    pull(const std::filesystem::path& bundlePath, const X509* leaf, StubMaster& stub, FromMasterRequest fetch = {})
    {
        WriteRequest request;
        request.command = "--from-master";
        request.bundlePath = bundlePath;
        request.leaf = leaf;
        request.writtenBy = "manager_certs_utest";

        if (fetch.host.empty())
        {
            fetch.host = "127.0.0.1";
        }
        if (fetch.port.empty())
        {
            fetch.port = "1517";
        }
        fetch.transport = transportOf(stub);

        std::ostringstream out;
        std::ostringstream err;
        PullOutcome outcome;
        outcome.exitCode = runFromMaster(std::move(request), std::move(fetch), out, err);
        outcome.out = out.str();
        outcome.err = err.str();
        outcome.hash = sha256Of(bundlePath);
        return outcome;
    }

    /// A fixture bundle: the CA that signs the leaf, sealed under kLocalPublication.
    std::filesystem::path seedBundle(const TempDir& directory, const Pki& pki)
    {
        const std::filesystem::path bundlePath = directory.path() / kBundleName;
        writeFile(bundlePath, sealedBundleText(justOne(pki.ca.get()), kLocalPublication));
        return bundlePath;
    }
} // namespace

// ------------------------------------------------------------------ the environment guards ------

TEST(ManagerCertsFromMaster, RejectedOnMaster)
{
    int exitCode = 0;
    // The default node_type is `master`, and an unset one reads as an empty string here: both are
    // "not a worker", and both are exit 2 (C37a, C38c).
    const std::string onMaster = fromMasterEnvironmentFailure("--from-master", 0, "master", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(onMaster.find("not a cluster worker"), std::string::npos) << onMaster;
    EXPECT_NE(onMaster.find("stamp"), std::string::npos) << onMaster;

    exitCode = 0;
    const std::string unset = fromMasterEnvironmentFailure("--from-master", 0, "", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(unset.find("not a cluster worker"), std::string::npos) << unset;

    exitCode = 0;
    const std::string notRoot = fromMasterEnvironmentFailure("--from-master", 1000, "worker", exitCode);
    EXPECT_EQ(exitCode, 2);
    EXPECT_NE(notRoot.find("root"), std::string::npos) << notRoot;

    exitCode = 7;
    EXPECT_TRUE(fromMasterEnvironmentFailure("--from-master", 0, "worker", exitCode).empty());
    EXPECT_EQ(exitCode, 0);
}

// ------------------------------------------------------------------------- the happy paths ------

TEST(ManagerCertsFromMaster, HigherGenerationWritesAndVouches)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::int64_t published = kLocalPublication + 42;

    // What a master really serves: certificates only, no publication block (remoted's
    // CaCertificateSource serialises certificates and nothing else).
    std::vector<ca_bundle::X509Ptr> served;
    served.push_back(retain(pki.ca.get()));
    served.push_back(retain(pki.stranger.get()));

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(served), std::to_string(published));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    ASSERT_EQ(outcome.exitCode, 0) << outcome.err;
    EXPECT_NE(outcome.out.find(std::to_string(published)), std::string::npos) << outcome.out;

    // The file now holds both certificates under the master's own generation, and vouch() -- the
    // verdict remoted will reach over the same bytes -- returns exactly that number (CA-31).
    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(bundlePath));
    ASSERT_TRUE(written.wellFormed);
    EXPECT_EQ(written.certificates.size(), 2U);
    ASSERT_TRUE(written.block.has_value());
    EXPECT_EQ(written.block->publication, published);
    const auto serialized = ca_bundle::serializeCertificates(written.certificates).size();
    EXPECT_EQ(ca_bundle::vouch(written, pki.leaf.get(), serialized).publication, published);

    // The download was asked for with the local bundle as its trust material, and for the URL the
    // components produce -- never a literal (C39g).
    ASSERT_EQ(stub.asked.size(), 1U);
    EXPECT_EQ(stub.asked.front().trustBundle, sealedBundleText(justOne(pki.ca.get()), kLocalPublication));
    EXPECT_EQ(stub.asked.front().url, "https://127.0.0.1:1517/cacerts");
    EXPECT_EQ(stub.asked.front().headerName, "Wazuh-CA-Generation");
}

TEST(ManagerCertsFromMaster, LeafChainedAgainstLocalLeafOnly)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);

    // The response carries a CA that signs THIS node's leaf plus a fabricated one that signs a leaf
    // of the master's own making. Only the local leaf decides (C37c): the bundle is installed
    // because `pki.ca` chains to it, never because anything in the response says so.
    auto fabricatedKey = makeTestKey();
    auto fabricatedCa =
        makeCertificate("fabricated-ca", -kDay, 400 * kDay, fabricatedKey.get(), fabricatedKey.get(), nullptr, true, 9);
    auto fabricatedLeafKey = makeTestKey();
    auto fabricatedLeaf = makeCertificate("fabricated-leaf",
                                          -kDay,
                                          90 * kDay,
                                          fabricatedLeafKey.get(),
                                          fabricatedKey.get(),
                                          fabricatedCa.get(),
                                          false,
                                          10);

    std::vector<ca_bundle::X509Ptr> served;
    served.push_back(retain(fabricatedCa.get()));
    served.push_back(retain(pki.ca.get()));

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(served), std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    ASSERT_EQ(outcome.exitCode, 0) << outcome.err;

    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(bundlePath));
    EXPECT_EQ(written.certificates.size(), 2U);
    EXPECT_TRUE(ca_bundle::leafChainsToAnyCa(pki.leaf.get(), written.certificates));
}

TEST(ManagerCertsFromMaster, EmbeddedBlockMatchingHeaderAccepted)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::int64_t published = kLocalPublication + 5;

    // A master that serves a whole stamped file (an edited bundle, a legacy node) is accepted as
    // long as the block says what the header says (RF-17, C39f).
    StubMaster stub;
    stub.response = answer(sealedBundleText(justOne(pki.ca.get()), published), std::to_string(published));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    ASSERT_EQ(outcome.exitCode, 0) << outcome.err;
    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(bundlePath));
    ASSERT_TRUE(written.block.has_value());
    EXPECT_EQ(written.block->publication, published);
}

// ------------------------------------------------------------------ the generation guards -------

TEST(ManagerCertsFromMaster, EqualGenerationIsNoop)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), std::to_string(kLocalPublication));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 0);
    EXPECT_TRUE(outcome.err.empty()) << outcome.err;
    EXPECT_NE(outcome.out.find("nothing to do"), std::string::npos) << outcome.out;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, EqualGenerationWithDifferentContentIsRepaired)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();

    // The state the number-only shortcut of C37(b) could not see: a healthy publication block,
    // intact, over certificates it does not describe -- somebody edited the worker's bundle (or a
    // restore put an older one back) and left the block alone. This worker announces the master's
    // own generation while serving the wrong anchor, so every pull used to answer "nothing to do"
    // and leave it broken forever.
    const std::filesystem::path bundlePath = directory.path() / kBundleName;
    writeFile(bundlePath,
              ca_bundle::renderBlock(blockFor(justOne(pki.ca.get()), kLocalPublication)) +
                  ca_bundle::serializeCertificates(justOne(pki.stranger.get())));
    const std::string before = sha256Of(bundlePath);

    // The master is at that very generation, with the certificates the file should have carried.
    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), std::to_string(kLocalPublication));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    ASSERT_EQ(outcome.exitCode, 0) << outcome.err;
    EXPECT_TRUE(outcome.err.empty()) << outcome.err;
    EXPECT_EQ(outcome.out.find("nothing to do"), std::string::npos) << outcome.out;
    EXPECT_NE(outcome.out.find("repaired"), std::string::npos) << outcome.out;
    EXPECT_NE(outcome.hash, before);

    // Repaired in place: the master's certificate, under the same generation it already announced
    // (nothing moves backwards for the agents), and a block that describes what the file carries --
    // so `check` vouches for it again (C29).
    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(bundlePath));
    ASSERT_TRUE(written.wellFormed);
    ASSERT_TRUE(written.block.has_value());
    EXPECT_EQ(written.block->publication, kLocalPublication);
    ASSERT_EQ(written.certificates.size(), 1U);
    EXPECT_EQ(ca_bundle::contentSha256(written.certificates), ca_bundle::contentSha256(justOne(pki.ca.get())));
    EXPECT_EQ(written.block->contentSha256, ca_bundle::contentSha256(written.certificates));
}

TEST(ManagerCertsFromMaster, LowerGenerationRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);
    const std::int64_t behind = kLocalPublication - 60;

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), std::to_string(behind));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 1);
    // Both numbers, so the operator can see which node is behind without looking anything up
    // (C37b).
    EXPECT_NE(outcome.err.find(std::to_string(behind)), std::string::npos) << outcome.err;
    EXPECT_NE(outcome.err.find(std::to_string(kLocalPublication)), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, ZeroGenerationRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), "0");

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    // Read fine, breaks a rule: exit 1, not 2 (02-diseno.md §2.7, C38b).
    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_NE(outcome.err.find("not vouched"), std::string::npos) << outcome.err;
    EXPECT_NE(outcome.err.find("stamp"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, MissingHeaderRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), "");
    stub.response.generation.reset();

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    // Could not read it at all: exit 2, with the message that points at the master's version
    // (C38b/C39g, objection 10 -- the draft said 1).
    EXPECT_EQ(outcome.exitCode, 2);
    EXPECT_NE(outcome.err.find("announces no Wazuh-CA-Generation"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, NonNumericHeaderRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    for (const std::string value : {std::string {"banana"},
                                    std::string {"12abc"},
                                    std::string {"1e5"},
                                    std::string {"9223372036854775808"},
                                    std::string {"-"}})
    {
        StubMaster stub;
        stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), value);

        const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
        EXPECT_EQ(outcome.exitCode, 2) << value;
        EXPECT_NE(outcome.err.find("not a generation"), std::string::npos) << outcome.err;
        EXPECT_EQ(outcome.hash, before) << value;
    }
}

// ------------------------------------------------------------------------- the body guards ------

TEST(ManagerCertsFromMaster, MalformedBodyRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    StubMaster stub;
    stub.response = answer("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n",
                           std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    // We could not parse it: exit 2 (P24), same treatment a local file gets.
    EXPECT_EQ(outcome.exitCode, 2);
    EXPECT_NE(outcome.err.find("malformed"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, EmbeddedBlockMismatchRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);
    const std::int64_t announced = kLocalPublication + 10;

    StubMaster stub;
    stub.response = answer(sealedBundleText(justOne(pki.ca.get()), announced + 1), std::to_string(announced));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    // Read fine, says two different things: exit 1, and neither number wins (RF-17, C39f).
    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_NE(outcome.err.find(std::to_string(announced)), std::string::npos) << outcome.err;
    EXPECT_NE(outcome.err.find(std::to_string(announced + 1)), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

// ------------------------------------------------- the guards finishWrite() still runs (C39h) ---
// A bundle the master is perfectly happy with can still be one this node must not install. These
// four are the proof that skipping G8 did not skip anything else: each of them is a candidate the
// master vouches for, refused HERE, under an explicit publication.

TEST(ManagerCertsFromMaster, ExplicitPublicationLeafInvalidChainRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    // Only the stranger CA: a fine bundle on the master, and one no agent of THIS worker could use,
    // because nothing in it signs the leaf this node serves (G6).
    StubMaster stub;
    stub.response =
        answer(ca_bundle::serializeCertificates(justOne(pki.stranger.get())), std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_NE(outcome.err.find("no CA signs the served leaf"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, ExplicitPublicationZeroCertificatesRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    // A well-formed document that carries no certificate at all: parseBundle() is happy, G4 is not.
    StubMaster stub;
    stub.response = answer("# a master that published an empty file\n", std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_NE(outcome.err.find("0 certificates"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, ExplicitPublicationSevenCertificatesRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    std::vector<ca_bundle::X509Ptr> served;
    served.push_back(retain(pki.ca.get()));
    std::vector<manager_certs::test::EvpPkeyPtr> keys;
    for (long index = 0; index < 6; ++index)
    {
        keys.push_back(makeTestKey());
        served.push_back(makeCertificate(
            "spare-ca", -kDay, 400 * kDay, keys.back().get(), keys.back().get(), nullptr, true, 100 + index));
    }
    ASSERT_EQ(served.size(), ca_bundle::kMaxCertificates + 1);

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(served), std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_NE(outcome.err.find("7 certificates"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, ExplicitPublicationOversizeSerializationRejected)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    // The CA that does chain to the leaf, fattened past the byte cap: G6 passes, G5 refuses.
    auto fatKey = makeTestKey();
    auto fatCa = makeCertificate("fat-ca", -kDay, 400 * kDay, fatKey.get(), fatKey.get(), nullptr, true, 11);
    inflateAndResign(fatCa.get(), fatKey.get(), 9000);

    std::vector<ca_bundle::X509Ptr> served;
    served.push_back(retain(pki.ca.get()));
    served.push_back(retain(fatCa.get()));
    ASSERT_GT(ca_bundle::serializeCertificates(served).size(), ca_bundle::kMaxSerializedBytes);

    StubMaster stub;
    stub.response = answer(ca_bundle::serializeCertificates(served), std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 1);
    EXPECT_NE(outcome.err.find("bytes (max "), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, ExplicitPublicationIsWrittenVerbatimAndSkipsNoOtherGuard)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);

    // finishWrite() straight, with no transport in the picture: the generation written is the one
    // handed in -- not a reading of the clock -- and the block it stamps describes the bytes it
    // wrote (GH), which is what remoted will hash when it vouches.
    WriteRequest request;
    request.command = "--from-master";
    request.bundlePath = bundlePath;
    request.leaf = pki.leaf.get();
    request.writtenBy = "manager_certs_utest";
    manager_certs::PrepareOutcome prepared = prepareWrite(std::move(request));
    ASSERT_TRUE(prepared.context) << prepared.message;

    const std::int64_t handed = kLocalPublication + 123;
    const WriteOutcome outcome = finishWrite(*prepared.context, justOne(pki.ca.get()), {}, handed);
    ASSERT_EQ(outcome.exitCode, 0) << outcome.message;
    EXPECT_EQ(outcome.publication, handed);

    const ca_bundle::ParsedBundle written = ca_bundle::parseBundle(readFile(bundlePath));
    ASSERT_TRUE(written.block.has_value());
    EXPECT_EQ(written.block->publication, handed);
    EXPECT_EQ(written.block->contentSha256, ca_bundle::contentSha256(written.certificates));
}

// --------------------------------------------------------------------- the transport's answer ---

TEST(ManagerCertsFromMaster, PreparationFailureIsEnvironmentError)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    StubMaster stub;
    stub.response.failure = MasterFetchFailure::preparation;
    stub.response.message = "cannot pin CURLOPT_CAINFO_BLOB: libcurl refused it (CURLcode 43)";

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 2);
    EXPECT_NE(outcome.err.find("CURLOPT_CAINFO_BLOB"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, TransferFailureSuggestsTheWayOut)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    StubMaster stub;
    stub.response.failure = MasterFetchFailure::transfer;
    stub.response.message = "Couldn't connect to server (CURLcode 7)";

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    EXPECT_EQ(outcome.exitCode, 2);
    EXPECT_NE(outcome.err.find("--port"), std::string::npos) << outcome.err;
    EXPECT_NE(outcome.err.find("scp"), std::string::npos) << outcome.err;
    EXPECT_EQ(outcome.hash, before);
}

TEST(ManagerCertsFromMaster, NonOkStatusRejectedEvenWithAValidBody)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    // A transport that let a 302/206/500 through -- libcurl does not fail on one -- must not have
    // its body installed here either (C39b, objection 4).
    for (const long status : {302L, 206L, 500L})
    {
        StubMaster stub;
        stub.response =
            answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), std::to_string(kLocalPublication + 1));
        stub.response.httpStatus = status;

        const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
        EXPECT_EQ(outcome.exitCode, 2) << status;
        EXPECT_NE(outcome.err.find("HTTP " + std::to_string(status)), std::string::npos) << outcome.err;
        EXPECT_EQ(outcome.hash, before) << status;
    }
}

TEST(ManagerCertsFromMaster, EmptyLocalBundleRefusedBeforeConnecting)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const std::filesystem::path bundlePath = directory.path() / kBundleName;
    writeFile(bundlePath, "");

    StubMaster stub;
    stub.response =
        answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), std::to_string(kLocalPublication + 1));

    const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub);
    // Nothing would verify the master's certificate, and a zero-length blob is what makes libcurl
    // fall back to the system CA store: refused with its own message, and the transport is never
    // asked (C39a, objection 1).
    EXPECT_EQ(outcome.exitCode, 2);
    EXPECT_NE(outcome.err.find("local trust bundle is empty"), std::string::npos) << outcome.err;
    EXPECT_TRUE(stub.asked.empty());
    EXPECT_EQ(readFile(bundlePath), "");
}

// ------------------------------------------------------------------------------- the URL --------

TEST(ManagerCertsFromMaster, UrlIsBuiltFromComponents)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);

    struct Case
    {
        std::string host;
        std::string port;
        std::string prefix;
        std::string expected;
    };

    // The installed default prefix is `/wazuh-manager/`: concatenating it with `/cacerts` would
    // give `//cacerts`, which is a different route (C39g, objection 5).
    const std::vector<Case> cases {
        {"127.0.0.1", "1517", "/wazuh-manager/", "https://127.0.0.1:1517/wazuh-manager/cacerts"},
        {"127.0.0.1", "1517", "", "https://127.0.0.1:1517/cacerts"},
        {"127.0.0.1", "1517", "/", "https://127.0.0.1:1517/cacerts"},
        {"127.0.0.1", "1517", "///", "https://127.0.0.1:1517/cacerts"},
        {"127.0.0.1", "1517", "deep/er/", "https://127.0.0.1:1517/deep/er/cacerts"},
        {"master.example.com", "443", "/wazuh-manager/", "https://master.example.com:443/wazuh-manager/cacerts"},
        {"::1", "1517", "/wazuh-manager/", "https://[::1]:1517/wazuh-manager/cacerts"},
        {"[fe80::1]", "1517", "", "https://[fe80::1]:1517/cacerts"},
    };

    for (const Case& scenario : cases)
    {
        StubMaster stub;
        stub.response = answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), "0"); // Stops at guard 7.

        FromMasterRequest fetch;
        fetch.host = scenario.host;
        fetch.port = scenario.port;
        fetch.globalPrefix = scenario.prefix;

        const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub, std::move(fetch));
        ASSERT_EQ(stub.asked.size(), 1U) << scenario.expected << " (" << outcome.err << ")";
        EXPECT_EQ(stub.asked.front().url, scenario.expected);
    }
}

TEST(ManagerCertsFromMaster, UnusableAddressRefusedWithoutConnecting)
{
    SKIP_UNLESS_ROOT();
    const TempDir directory;
    const Pki pki = makePki();
    const auto bundlePath = seedBundle(directory, pki);
    const std::string before = sha256Of(bundlePath);

    struct Case
    {
        std::string host;
        std::string port;
        std::string expected;
    };
    const std::vector<Case> cases {
        {"", "1517", "no master address configured"},
        {"master/../evil", "1517", "not a host name"},
        {"master host", "1517", "not a host name"},
        {"[fe80::1", "1517", "unbalanced brackets"},
        {"fe80::1]", "1517", "unbalanced brackets"},
        {"127.0.0.1", "0", "1-65535"},
        {"127.0.0.1", "65536", "1-65535"},
        {"127.0.0.1", "17b", "1-65535"},
        {"127.0.0.1", "", "1-65535"},
    };

    for (const Case& scenario : cases)
    {
        StubMaster stub;
        stub.response =
            answer(ca_bundle::serializeCertificates(justOne(pki.ca.get())), std::to_string(kLocalPublication + 1));

        FromMasterRequest fetch;
        fetch.host = scenario.host;
        fetch.port = scenario.port;
        // An empty host or port must survive pull()'s own defaults, which only fill in what the
        // case left untouched; these two are set deliberately.
        if (scenario.host.empty())
        {
            fetch.host = " ";
        }
        if (scenario.port.empty())
        {
            fetch.port = " ";
        }

        const PullOutcome outcome = pull(bundlePath, pki.leaf.get(), stub, std::move(fetch));
        EXPECT_EQ(outcome.exitCode, 2) << scenario.host << ":" << scenario.port;
        EXPECT_TRUE(stub.asked.empty()) << scenario.host << ":" << scenario.port;
        EXPECT_EQ(outcome.hash, before);
    }
}

// ----------------------------------------------------- what the real transport asks libcurl for --
// Through the CurlPort seam: the options themselves, their values, and what happens when one of
// them is refused. The fake drives the callbacks from inside perform(), exactly where libcurl would
// call them, so the body cap and the header collector are exercised while their sinks are alive.
// The handshake these options produce is the component test's job -- no seam can fake that.

namespace
{
    /// One recorded `curl_easy_setopt()`. Pointer options are recorded by their CONTENTS, copied
    /// as they are handed over: libcurl's own arguments (the blob, the two sinks) live on the
    /// transport's stack and are gone by the time a case looks at them.
    struct RecordedOption
    {
        CURLoption option {CURLOPT_URL};
        long number {0};
        std::string text;    ///< A string option's value, or a blob's bytes.
        bool wasNull {true}; ///< Whether the pointer handed over was null.
        curl_write_callback callback {nullptr};
        const void* sink {nullptr}; ///< Only for WRITEDATA/HEADERDATA, used DURING perform().
    };

    /// A libcurl that records what it was asked for and, on perform(), replays a canned response
    /// through the callbacks it was handed.
    struct FakeCurl
    {
        std::vector<RecordedOption> options;
        int performCalls {0};
        int cleanups {0};
        CURLcode performResult {CURLE_OK}; ///< What perform() returns when the replay does not abort.
        long responseCode {200};
        CURLoption failOption {CURLOPT_LASTENTRY}; ///< The one option that is refused.
        CURLcode failWith {CURLE_BAD_FUNCTION_ARGUMENT};
        std::vector<std::string> headerLines; ///< Fed verbatim, one call each, as libcurl does.
        std::vector<std::string> bodyChunks;

        const RecordedOption* find(CURLoption option) const
        {
            for (const RecordedOption& recorded : options)
            {
                if (recorded.option == option)
                {
                    return &recorded;
                }
            }
            return nullptr;
        }

        bool has(CURLoption option) const
        {
            return find(option) != nullptr;
        }

        /// What libcurl does: hand every header line and every body chunk to the registered
        /// callback, and abort the transfer the moment one of them consumes fewer bytes than it was
        /// offered.
        CURLcode replay()
        {
            const RecordedOption* headerFunction = find(CURLOPT_HEADERFUNCTION);
            const RecordedOption* headerData = find(CURLOPT_HEADERDATA);
            for (std::string& line : headerLines)
            {
                if (headerFunction == nullptr || headerFunction->callback == nullptr)
                {
                    break;
                }
                const std::size_t taken = headerFunction->callback(
                    line.data(), 1, line.size(), const_cast<void*>(headerData == nullptr ? nullptr : headerData->sink));
                if (taken != line.size())
                {
                    return CURLE_WRITE_ERROR;
                }
            }

            const RecordedOption* writeFunction = find(CURLOPT_WRITEFUNCTION);
            const RecordedOption* writeData = find(CURLOPT_WRITEDATA);
            for (std::string& chunk : bodyChunks)
            {
                if (writeFunction == nullptr || writeFunction->callback == nullptr)
                {
                    break;
                }
                const std::size_t taken = writeFunction->callback(
                    chunk.data(), 1, chunk.size(), const_cast<void*>(writeData == nullptr ? nullptr : writeData->sink));
                if (taken != chunk.size())
                {
                    return CURLE_WRITE_ERROR;
                }
            }
            return performResult;
        }
    };

    /// A handle that is nothing but a non-null address the fake recognises.
    int g_fakeHandle {0};

    CurlPort portOf(FakeCurl& curl)
    {
        CurlPort port;
        port.init = []() -> CURL*
        {
            return reinterpret_cast<CURL*>(&g_fakeHandle);
        };
        port.setLong = [&curl](CURL*, CURLoption option, long value)
        {
            RecordedOption recorded;
            recorded.option = option;
            recorded.number = value;
            curl.options.push_back(recorded);
            return option == curl.failOption ? curl.failWith : CURLE_OK;
        };
        port.setPointer = [&curl](CURL*, CURLoption option, const void* value)
        {
            RecordedOption recorded;
            recorded.option = option;
            recorded.wasNull = value == nullptr;
            recorded.sink = value;
            if (value != nullptr)
            {
                if (option == CURLOPT_CAINFO_BLOB)
                {
                    const auto* blob = static_cast<const curl_blob*>(value);
                    recorded.text.assign(static_cast<const char*>(blob->data), blob->len);
                }
                else if (option == CURLOPT_URL || option == CURLOPT_PROXY || option == CURLOPT_CAPATH)
                {
                    recorded.text = static_cast<const char*>(value);
                }
            }
            curl.options.push_back(recorded);
            return option == curl.failOption ? curl.failWith : CURLE_OK;
        };
        port.setCallback = [&curl](CURL*, CURLoption option, curl_write_callback value)
        {
            RecordedOption recorded;
            recorded.option = option;
            recorded.callback = value;
            curl.options.push_back(recorded);
            return option == curl.failOption ? curl.failWith : CURLE_OK;
        };
        port.perform = [&curl](CURL*)
        {
            ++curl.performCalls;
            return curl.replay();
        };
        port.getLong = [&curl](CURL*, CURLINFO, long* value)
        {
            *value = curl.responseCode;
            return CURLE_OK;
        };
        port.cleanup = [&curl](CURL*)
        {
            ++curl.cleanups;
        };
        return port;
    }

    const char* const kTrustFixture = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";

    MasterFetch queryFor(const std::string& trust = kTrustFixture)
    {
        MasterFetch query;
        query.url = "https://127.0.0.1:1517/wazuh-manager/cacerts";
        query.trustBundle = trust;
        query.headerName = "Wazuh-CA-Generation";
        return query;
    }

    /// A plain 200 carrying @p body and announcing @p generation.
    void servedBy(FakeCurl& curl, const std::string& body, const std::string& generation)
    {
        curl.headerLines = {"HTTP/1.1 200 OK\r\n",
                            "Content-Type: application/x-pem-file\r\n",
                            "Wazuh-CA-Generation: " + generation + "\r\n",
                            "\r\n"};
        curl.bodyChunks = {body};
    }
} // namespace

TEST(ManagerCertsMasterTransport, PinsEveryOptionThatDecidesWhatItTrusts)
{
    FakeCurl curl;
    servedBy(curl, "pem bytes", "4242");
    const MasterFetchResult result = curlMasterTransport(portOf(curl)).get(queryFor());

    ASSERT_EQ(result.failure, MasterFetchFailure::none) << result.message;
    EXPECT_EQ(curl.performCalls, 1);
    EXPECT_EQ(curl.cleanups, 1);
    EXPECT_EQ(result.body, "pem bytes");
    ASSERT_TRUE(result.generation.has_value());
    EXPECT_EQ(*result.generation, "4242");

    // The trust material is a BLOB, carrying the bundle verbatim: a path would let libcurl open a
    // file this tool never bounded (C38).
    const RecordedOption* blob = curl.find(CURLOPT_CAINFO_BLOB);
    ASSERT_NE(blob, nullptr);
    EXPECT_FALSE(blob->wasNull);
    EXPECT_EQ(blob->text, std::string {kTrustFixture});

    // CAPATH is a trust source of its own that CAINFO_BLOB does NOT replace: it has to be cleared
    // explicitly, or a build whose configure found a system CA directory trusts that too (C39a,
    // objection 2).
    const RecordedOption* caPath = curl.find(CURLOPT_CAPATH);
    ASSERT_NE(caPath, nullptr) << "CURLOPT_CAPATH was never set: an independent trust source is left alone";
    EXPECT_TRUE(caPath->wasNull) << "CURLOPT_CAPATH was set to '" << caPath->text << "', not cleared";

    ASSERT_NE(curl.find(CURLOPT_SSL_VERIFYPEER), nullptr);
    EXPECT_EQ(curl.find(CURLOPT_SSL_VERIFYPEER)->number, 1L);
    ASSERT_NE(curl.find(CURLOPT_SSL_VERIFYHOST), nullptr);
    EXPECT_EQ(curl.find(CURLOPT_SSL_VERIFYHOST)->number, 2L);

    // No inherited https_proxy: a CONNECT answer can carry a generation header of its own (C39a,
    // objection 3).
    const RecordedOption* proxy = curl.find(CURLOPT_PROXY);
    ASSERT_NE(proxy, nullptr);
    EXPECT_FALSE(proxy->wasNull);
    EXPECT_EQ(proxy->text, "");

    ASSERT_NE(curl.find(CURLOPT_FOLLOWLOCATION), nullptr);
    EXPECT_EQ(curl.find(CURLOPT_FOLLOWLOCATION)->number, 0L);
    ASSERT_NE(curl.find(CURLOPT_TIMEOUT), nullptr);
    EXPECT_EQ(curl.find(CURLOPT_TIMEOUT)->number, 10L);
    ASSERT_NE(curl.find(CURLOPT_URL), nullptr);
    EXPECT_EQ(curl.find(CURLOPT_URL)->text, queryFor().url);
    EXPECT_TRUE(curl.has(CURLOPT_WRITEFUNCTION));
    EXPECT_TRUE(curl.has(CURLOPT_WRITEDATA));
    EXPECT_TRUE(curl.has(CURLOPT_HEADERFUNCTION));
    EXPECT_TRUE(curl.has(CURLOPT_HEADERDATA));
}

TEST(ManagerCertsMasterTransport, ARefusedOptionStopsEverythingBeforeSending)
{
    // Every pinned option, one at a time: with its CURLcode ignored, the connection would be made
    // with whatever libcurl defaults to -- for CAINFO_BLOB, this build's compiled-in
    // /etc/pki/tls/certs/ca-bundle.crt (src/external/curl/lib/curl_config.h:7) -- which is the
    // bypass CA-33 forbids (C39a, objection 1).
    const std::vector<CURLoption> pinned {CURLOPT_URL,
                                          CURLOPT_CAINFO_BLOB,
                                          CURLOPT_CAPATH,
                                          CURLOPT_SSL_VERIFYPEER,
                                          CURLOPT_SSL_VERIFYHOST,
                                          CURLOPT_PROXY,
                                          CURLOPT_FOLLOWLOCATION,
                                          CURLOPT_TIMEOUT,
                                          CURLOPT_WRITEFUNCTION,
                                          CURLOPT_WRITEDATA,
                                          CURLOPT_HEADERFUNCTION,
                                          CURLOPT_HEADERDATA};

    for (const CURLoption option : pinned)
    {
        FakeCurl curl;
        servedBy(curl, "pem bytes", "4242");
        curl.failOption = option;
        const MasterFetchResult result = curlMasterTransport(portOf(curl)).get(queryFor());

        EXPECT_EQ(result.failure, MasterFetchFailure::preparation) << option;
        EXPECT_EQ(curl.performCalls, 0) << option << " was refused and the request went out anyway";
        EXPECT_EQ(curl.cleanups, 1) << option;
        EXPECT_FALSE(result.generation.has_value()) << option;
        EXPECT_TRUE(result.body.empty()) << option;
        EXPECT_NE(result.message.find("CURLcode"), std::string::npos) << result.message;
    }
}

TEST(ManagerCertsMasterTransport, AnEmptyTrustBlobIsRefusedByLibcurlItself)
{
    // The real libcurl, not the fake: Curl_setblobopt() refuses a zero-length blob
    // (src/external/curl/lib/setopt.c:110), and with that return ignored the handle would carry on
    // and verify against the system CA store instead. What this asserts is that the run ended in
    // PREPARATION -- nothing was sent -- naming the option that refused.
    const MasterFetchResult result = curlMasterTransport().get(queryFor(""));
    EXPECT_EQ(result.failure, MasterFetchFailure::preparation) << result.message;
    EXPECT_NE(result.message.find("CURLOPT_CAINFO_BLOB"), std::string::npos) << result.message;
    EXPECT_EQ(result.httpStatus, 0);
    EXPECT_TRUE(result.body.empty());
}

TEST(ManagerCertsMasterTransport, OnlyACompleteTwoHundredCounts)
{
    // libcurl reports a 302, a 206 or a 500 as a successful transfer: their body and their headers
    // must never be read as a published bundle (C39b, objection 4).
    for (const long status : {100L, 204L, 206L, 302L, 400L, 500L})
    {
        FakeCurl curl;
        servedBy(curl, "pem bytes", "4242");
        curl.responseCode = status;
        const MasterFetchResult result = curlMasterTransport(portOf(curl)).get(queryFor());
        EXPECT_EQ(result.failure, MasterFetchFailure::transfer) << status;
        EXPECT_NE(result.message.find(std::to_string(status)), std::string::npos) << result.message;
        EXPECT_TRUE(result.body.empty()) << status;
        EXPECT_FALSE(result.generation.has_value()) << status;
    }

    FakeCurl refused;
    servedBy(refused, "pem bytes", "4242");
    refused.performResult = CURLE_PEER_FAILED_VERIFICATION;
    const MasterFetchResult result = curlMasterTransport(portOf(refused)).get(queryFor());
    EXPECT_EQ(result.failure, MasterFetchFailure::transfer);
    EXPECT_EQ(refused.performCalls, 1);
    EXPECT_TRUE(result.body.empty());
    EXPECT_FALSE(result.generation.has_value());
}

TEST(ManagerCertsMasterTransport, TheCapIsCheckedBeforeTheChunkIsAppended)
{
    // Exactly the cap: accepted, because a limit is a limit and not a margin.
    FakeCurl exact;
    servedBy(exact, std::string(64, 'a'), "4242");
    MasterFetch query = queryFor();
    query.maxBodyBytes = 64;
    const MasterFetchResult accepted = curlMasterTransport(portOf(exact)).get(query);
    ASSERT_EQ(accepted.failure, MasterFetchFailure::none) << accepted.message;
    EXPECT_EQ(accepted.body.size(), 64U);

    // One byte over, in a single chunk: refused, and nothing of it kept.
    FakeCurl overBy1;
    servedBy(overBy1, std::string(65, 'a'), "4242");
    const MasterFetchResult refused = curlMasterTransport(portOf(overBy1)).get(query);
    EXPECT_EQ(refused.failure, MasterFetchFailure::transfer);
    EXPECT_NE(refused.message.find("cap"), std::string::npos) << refused.message;
    EXPECT_TRUE(refused.body.empty());

    // Two chunks that only together cross it: the second one is dropped WHOLE, so the cap is never
    // crossed by the part of it that would have fit (C39c, objection 6).
    FakeCurl crossing;
    servedBy(crossing, "", "4242");
    crossing.bodyChunks = {std::string(40, 'a'), std::string(40, 'b')};
    const MasterFetchResult straddled = curlMasterTransport(portOf(crossing)).get(query);
    EXPECT_EQ(straddled.failure, MasterFetchFailure::transfer);
    EXPECT_TRUE(straddled.body.empty());
}

TEST(ManagerCertsMasterTransport, OnlyTheLastResponsesGenerationHeaderSurvives)
{
    FakeCurl curl;
    curl.headerLines = {// A proxy's CONNECT answer, with a generation of its own: taken for the
                        // master's, its size alone would lock this node out of every legitimate
                        // publication afterwards through the monotonicity rule (C39a, objection 3).
                        "HTTP/1.1 200 Connection established\r\n",
                        "wazuh-ca-generation: 99999999999\r\n",
                        "\r\n",
                        // The master's real response.
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: application/x-pem-file\r\n",
                        "WAZUH-CA-GENERATION:   4242  \r\n", // Case-insensitive, OWS trimmed.
                        "\r\n"};
    curl.bodyChunks = {"pem bytes"};

    const MasterFetchResult result = curlMasterTransport(portOf(curl)).get(queryFor());
    ASSERT_EQ(result.failure, MasterFetchFailure::none) << result.message;
    ASSERT_TRUE(result.generation.has_value());
    EXPECT_EQ(*result.generation, "4242");

    // And a response that carries no such header at all leaves nothing behind.
    FakeCurl silent;
    silent.headerLines = {"HTTP/1.1 200 OK\r\n", "Content-Type: application/x-pem-file\r\n", "\r\n"};
    silent.bodyChunks = {"pem bytes"};
    const MasterFetchResult quiet = curlMasterTransport(portOf(silent)).get(queryFor());
    ASSERT_EQ(quiet.failure, MasterFetchFailure::none) << quiet.message;
    EXPECT_FALSE(quiet.generation.has_value());
}
