/*
 * Wazuh CA bundle library - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ca_bundle/ca_bundle.hpp"
#include "testPki.hpp"

#include <gtest/gtest.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

using ca_bundle::contentSha256;
using ca_bundle::describe;
using ca_bundle::GuardFailure;
using ca_bundle::identityOf;
using ca_bundle::leafChainsToAnyCa;
using ca_bundle::parseBundle;
using ca_bundle::ParsedBundle;
using ca_bundle::PublicationBlock;
using ca_bundle::renderBlock;
using ca_bundle::serializeCertificates;
using ca_bundle::vouch;
using ca_bundle::X509Ptr;
using ca_bundle::test::makeCertificate;
using ca_bundle::test::makeTestKey;
using ca_bundle::test::retain;

namespace
{
    constexpr long kDay = 24L * 60L * 60L;
    constexpr const char* kBegin = "-----BEGIN CERTIFICATE-----";

    /// A throwaway PKI: a CA, a leaf it signed, and a CA that signed nothing of ours.
    struct Pki
    {
        ca_bundle::test::EvpPkeyPtr caKey {nullptr, &EVP_PKEY_free};
        ca_bundle::test::EvpPkeyPtr leafKey {nullptr, &EVP_PKEY_free};
        ca_bundle::test::EvpPkeyPtr foreignKey {nullptr, &EVP_PKEY_free};
        X509Ptr ca;
        X509Ptr leaf;
        X509Ptr foreignCa;
    };

    Pki makePki(const std::string& prefix)
    {
        Pki pki;
        pki.caKey = makeTestKey();
        pki.leafKey = makeTestKey();
        pki.foreignKey = makeTestKey();
        pki.ca = makeCertificate(
            (prefix + "-ca").c_str(), -kDay, 30 * kDay, pki.caKey.get(), pki.caKey.get(), nullptr, true);
        pki.leaf = makeCertificate(
            (prefix + "-leaf").c_str(), -kDay, 10 * kDay, pki.leafKey.get(), pki.caKey.get(), pki.ca.get());
        pki.foreignCa = makeCertificate(
            (prefix + "-foreign").c_str(), -kDay, 30 * kDay, pki.foreignKey.get(), pki.foreignKey.get(), nullptr, true);
        return pki;
    }

    /// A bundle sharing the certificates (own references), so one PKI feeds several of them.
    std::vector<X509Ptr> bundleOf(const std::vector<const X509*>& certificates)
    {
        std::vector<X509Ptr> bundle;
        bundle.reserve(certificates.size());
        for (const auto* certificate : certificates)
        {
            bundle.push_back(retain(certificate));
        }
        return bundle;
    }

    /// Six throwaway self-signed CAs, freshly keyed: for guard tests that need one certificate over
    /// kMaxCertificates without caring which certificates they are.
    std::vector<X509Ptr> sixExtraCertificates(const std::string& prefix)
    {
        std::vector<X509Ptr> extra;
        for (int index = 0; index < 6; ++index)
        {
            auto key = makeTestKey();
            extra.push_back(makeCertificate(
                (prefix + "-" + std::to_string(index)).c_str(), -kDay, 30 * kDay, key.get(), key.get(), nullptr, true));
        }
        return extra;
    }

    PublicationBlock stampFor(const std::vector<X509Ptr>& certificates, std::int64_t publication)
    {
        PublicationBlock stamp;
        stamp.publication = publication;
        stamp.contentSha256 = contentSha256(certificates);
        stamp.updated = "2026-09-17T10:11:12Z";
        stamp.writtenBy = "wazuh-manager-certs 5.0.0 (test)";
        return stamp;
    }

    /// What the tool writes: the block, then the certificates it describes.
    std::string sealedDocument(const std::vector<X509Ptr>& certificates, const PublicationBlock& stamp)
    {
        return renderBlock(stamp) + serializeCertificates(certificates);
    }

    /// Hex SHA-256 computed the long way round, to check identityOf() against something else.
    std::string sha256HexOfDer(const X509* certificate)
    {
        unsigned char* der = nullptr;
        const int length = i2d_X509(const_cast<X509*>(certificate), &der);
        if (length <= 0 || der == nullptr)
        {
            return {};
        }

        unsigned char digest[SHA256_DIGEST_LENGTH] {};
        SHA256(der, static_cast<std::size_t>(length), digest);
        OPENSSL_free(der);

        static constexpr char kHex[] = "0123456789abcdef";
        std::string hex;
        for (const auto byte : digest)
        {
            hex.push_back(kHex[byte >> 4]);
            hex.push_back(kHex[byte & 0x0F]);
        }
        return hex;
    }

    /// Hex SHA-256 of raw bytes, computed independently of ca_bundle's own sha256Hex().
    std::string hexSha256(const std::vector<unsigned char>& bytes)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH] {};
        SHA256(bytes.data(), bytes.size(), digest);

        static constexpr char kHex[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(sizeof(digest) * 2);
        for (const auto byte : digest)
        {
            hex.push_back(kHex[byte >> 4]);
            hex.push_back(kHex[byte & 0x0F]);
        }
        return hex;
    }

    /// @p certificate's DER encoding, the long way round (i2d_X509 + a manual copy).
    std::vector<unsigned char> derBytesOf(const X509* certificate)
    {
        unsigned char* raw = nullptr;
        const int length = i2d_X509(const_cast<X509*>(certificate), &raw);
        EXPECT_GT(length, 0);
        std::vector<unsigned char> der {raw, raw + length};
        OPENSSL_free(raw);
        return der;
    }
} // namespace

// --- contentSha256(): the hash names the certificates, not the document (T1, CA-2) --------------

TEST(CaBundleTest, ContentSha256IsOrderAndPemFormatIndependent)
{
    const auto pki = makePki("hash-order");
    const auto forward = bundleOf({pki.ca.get(), pki.foreignCa.get()});
    const auto reversed = bundleOf({pki.foreignCa.get(), pki.ca.get()});

    const auto hash = contentSha256(forward);
    ASSERT_FALSE(hash.empty());
    EXPECT_EQ(contentSha256(reversed), hash);

    // The same pair written down differently: reversed, with an operator's comment before it, a
    // blank line inside it and a stray comment after it.
    const std::string rewrapped = "# the CA of the lab manager\n\n" +
                                  serializeCertificates(bundleOf({pki.foreignCa.get()})) + "\n\n" +
                                  serializeCertificates(bundleOf({pki.ca.get()})) + "# nothing else to see\n";
    const auto reparsed = parseBundle(rewrapped);
    ASSERT_TRUE(reparsed.wellFormed);
    ASSERT_EQ(reparsed.certificates.size(), 2U);
    EXPECT_EQ(contentSha256(reparsed.certificates), hash);
}

TEST(CaBundleTest, ContentSha256ChangesWhenACertificateByteChanges)
{
    const auto pki = makePki("hash-byte");
    const auto original = bundleOf({pki.ca.get(), pki.foreignCa.get()});

    // One byte different, inside the CA's signature: the DER still parses (nothing verifies a
    // signature at load time), so the only thing that changed is the content being hashed.
    unsigned char* der = nullptr;
    const int length = i2d_X509(pki.ca.get(), &der);
    ASSERT_GT(length, 0);
    std::vector<unsigned char> mutated {der, der + length};
    OPENSSL_free(der);
    mutated.back() ^= 0x01U;

    const unsigned char* cursor = mutated.data();
    X509Ptr altered {d2i_X509(nullptr, &cursor, static_cast<long>(mutated.size()))};
    ASSERT_TRUE(altered);

    std::vector<X509Ptr> changed;
    changed.push_back(std::move(altered));
    changed.push_back(retain(pki.foreignCa.get()));

    EXPECT_NE(contentSha256(changed), contentSha256(original));
}

TEST(CaBundleTest, ContentSha256UsesAscendingDerOrder)
{
    const auto pki = makePki("hash-ascending");
    const auto certificates = bundleOf({pki.ca.get(), pki.foreignCa.get()});

    const auto derA = derBytesOf(pki.ca.get());
    const auto derB = derBytesOf(pki.foreignCa.get());

    // The same comparison std::sort over the DER bytes would make, decided here independently of
    // contentSha256()'s own sort.
    const bool aFirst = std::lexicographical_compare(derA.begin(), derA.end(), derB.begin(), derB.end());
    const auto& first = aFirst ? derA : derB;
    const auto& second = aFirst ? derB : derA;

    std::vector<unsigned char> ascending {first};
    ascending.insert(ascending.end(), second.begin(), second.end());
    std::vector<unsigned char> descending {second};
    descending.insert(descending.end(), first.begin(), first.end());

    EXPECT_EQ(contentSha256(certificates), hexSha256(ascending));
    // A descending-order implementation would also produce SOME stable hash; this pins that it has
    // to be the ascending one specifically.
    EXPECT_NE(contentSha256(certificates), hexSha256(descending));
}

// --- parseBundle(): the block is a comment, so it can sit anywhere (T2, CA-1) -------------------

TEST(CaBundleTest, ParseBundleFindsTheFirstBlockWhereverItSits)
{
    const auto pki = makePki("block-position");
    const auto pair = bundleOf({pki.ca.get(), pki.foreignCa.get()});
    const auto stamp = stampFor(pair, 1789000000);
    const auto block = renderBlock(stamp);

    const auto first = serializeCertificates(bundleOf({pki.ca.get()}));
    const auto second = serializeCertificates(bundleOf({pki.foreignCa.get()}));

    const std::vector<std::pair<const char*, std::string>> documents {
        {"block at the top", block + first + second},
        {"block between the certificates", first + block + second},
        {"block after the last certificate", first + second + block}};

    for (const auto& [where, document] : documents)
    {
        SCOPED_TRACE(where);
        const auto parsed = parseBundle(document);
        ASSERT_TRUE(parsed.wellFormed);
        ASSERT_EQ(parsed.certificates.size(), 2U);
        ASSERT_TRUE(parsed.block.has_value());
        EXPECT_EQ(parsed.block->publication, stamp.publication);
        EXPECT_EQ(parsed.block->contentSha256, stamp.contentSha256);
        EXPECT_EQ(parsed.block->updated, stamp.updated);
        EXPECT_EQ(parsed.block->writtenBy, stamp.writtenBy);
        // Both certificates came through untouched, wherever the comment sat.
        EXPECT_EQ(contentSha256(parsed.certificates), stamp.contentSha256);
    }

    // Two blocks: the first complete one wins, so a stamp appended under an older one never
    // silently takes over.
    auto older = stamp;
    older.publication = 1700000000;
    const auto twoBlocks = parseBundle(block + first + renderBlock(older) + second);
    ASSERT_TRUE(twoBlocks.block.has_value());
    EXPECT_EQ(twoBlocks.block->publication, stamp.publication);
}

TEST(CaBundleTest, ParseBundleWithoutABlockLeavesItNullopt)
{
    const auto pki = makePki("no-block");
    const auto document = serializeCertificates(bundleOf({pki.ca.get(), pki.foreignCa.get()}));

    const auto parsed = parseBundle(document);
    EXPECT_TRUE(parsed.wellFormed);
    EXPECT_EQ(parsed.certificates.size(), 2U);
    EXPECT_FALSE(parsed.block.has_value());

    // And an empty document is understood whole: it simply carries nothing.
    const auto empty = parseBundle("");
    EXPECT_TRUE(empty.wellFormed);
    EXPECT_TRUE(empty.certificates.empty());
    EXPECT_FALSE(empty.block.has_value());
}

TEST(CaBundleTest, ParseBundleIgnoresAHashHashLineThatIsNotABlock)
{
    const auto pki = makePki("near-miss");
    const auto certificates = serializeCertificates(bundleOf({pki.ca.get()}));
    const auto stamp = stampFor(bundleOf({pki.ca.get()}), 1789000000);

    // Everything that looks like the stamp without being one. A stamp whose publication cannot be
    // read is in here on purpose: half a block is not a block, and the bundle reads as
    // "never published" rather than as broken.
    const std::string loneFence = "##\n" + certificates;
    const std::string titleWithoutFences = "## Wazuh CA bundle\n" + certificates;
    const std::string sevenLines =
        "##\n## Wazuh CA bundle\n##\n## Publication: 1789000000\n## Content-SHA256: " + stamp.contentSha256 +
        "\n## Updated: 2026-09-17T10:11:12Z\n##\n" + certificates;
    const std::string unreadablePublication =
        "##\n## Wazuh CA bundle\n##\n## Publication: yesterday\n## Content-SHA256: " + stamp.contentSha256 +
        "\n## Updated: 2026-09-17T10:11:12Z\n## Written by: wazuh-manager-certs\n##\n" + certificates;
    const std::string fenceWithoutTitle = "##\n##\n##\n" + certificates + "##\n";

    const std::vector<std::pair<const char*, std::string>> documents {
        {"a lone fence", loneFence},
        {"the title alone", titleWithoutFences},
        {"seven of the eight lines", sevenLines},
        {"an unreadable publication", unreadablePublication},
        {"fences with no title", fenceWithoutTitle}};

    for (const auto& [what, document] : documents)
    {
        SCOPED_TRACE(what);
        const auto parsed = parseBundle(document);
        EXPECT_TRUE(parsed.wellFormed);
        EXPECT_EQ(parsed.certificates.size(), 1U);
        EXPECT_FALSE(parsed.block.has_value());
    }
}

TEST(CaBundleTest, ParseBundleClearsCertificatesWhenNotWellFormed)
{
    const auto pki = makePki("not-well-formed");
    const auto document = serializeCertificates(bundleOf({pki.ca.get(), pki.foreignCa.get()}));
    const auto firstBegin = document.find(kBegin);
    ASSERT_NE(firstBegin, std::string::npos);
    const auto secondBegin = document.find(kBegin, firstBegin + 1);
    ASSERT_NE(secondBegin, std::string::npos);

    // Truncated in the middle of the second block's base64: the document ends without an END line.
    const std::string truncated = document.substr(0, secondBegin + 100);
    // And the same document with a line of non-base64 inside that block.
    std::string corrupted = document;
    corrupted.insert(secondBegin + std::string {kBegin}.size() + 1, "!!!!\n");

    const std::vector<std::pair<const char*, std::string>> documents {{"truncated base64", truncated},
                                                                      {"non-base64 inside a block", corrupted}};

    for (const auto& [what, broken] : documents)
    {
        SCOPED_TRACE(what);
        const auto parsed = parseBundle(broken);
        EXPECT_FALSE(parsed.wellFormed);
        // Parity with the parseCertificates() this came from: a document we do not understand
        // whole is refused whole, never served up to its first bad block.
        EXPECT_TRUE(parsed.certificates.empty());
        EXPECT_FALSE(parsed.block.has_value());
    }
}

TEST(CaBundleTest, ParseBundleRejectsAPublicationWithTrailingGarbage)
{
    const auto pki = makePki("publication-garbage");
    const auto served = bundleOf({pki.ca.get()});
    const auto certificates = serializeCertificates(served);
    const auto hash = contentSha256(served);

    // A full, otherwise-valid block, with only the Publication line varied.
    const auto documentWithPublicationLine = [&](const std::string& publicationLine)
    {
        return "##\n## Wazuh CA bundle\n##\n" + publicationLine + "\n## Content-SHA256: " + hash +
               "\n## Updated: 2026-09-17T10:11:12Z\n## Written by: wazuh-manager-certs 5.0.0 (test)\n##\n" +
               certificates;
    };

    const std::string trailingLetter = documentWithPublicationLine("## Publication: 1789000000x");
    // An embedded NUL followed by more bytes, inside the SAME line: strtoll's C-string reading
    // would stop at the NUL and see a clean end-of-string there, missing the garbage after it.
    const std::string embeddedNul =
        documentWithPublicationLine(std::string {"## Publication: 1789000000"} + '\0' + "basura");
    const std::string negative = documentWithPublicationLine("## Publication: -5");
    const std::string empty = documentWithPublicationLine("## Publication:");

    const std::vector<std::pair<const char*, std::string>> rejected {{"trailing letter", trailingLetter},
                                                                     {"embedded NUL then garbage", embeddedNul},
                                                                     {"negative", negative},
                                                                     {"empty", empty}};
    for (const auto& [what, document] : rejected)
    {
        SCOPED_TRACE(what);
        const auto parsed = parseBundle(document);
        EXPECT_TRUE(parsed.wellFormed);
        EXPECT_FALSE(parsed.block.has_value());
    }

    // A clean value, and the same value with a trailing CR (a CRLF document), both still parse.
    const auto clean = parseBundle(documentWithPublicationLine("## Publication: 1789000000"));
    ASSERT_TRUE(clean.block.has_value());
    EXPECT_EQ(clean.block->publication, 1789000000);

    const std::string withCr =
        "##\n## Wazuh CA bundle\n##\n## Publication: 1789000000\r\n## Content-SHA256: " + hash +
        "\n## Updated: 2026-09-17T10:11:12Z\n## Written by: wazuh-manager-certs 5.0.0 (test)\n##\n" + certificates;
    const auto crParsed = parseBundle(withCr);
    ASSERT_TRUE(crParsed.block.has_value());
    EXPECT_EQ(crParsed.block->publication, 1789000000);
}

// --- vouch(): the guards, in order (T3) --------------------------------------------------------

TEST(CaBundleTest, VouchFailsNoCertificatesWhenBundleIsEmpty)
{
    const auto pki = makePki("vouch-empty");
    const ParsedBundle empty;

    const auto verdict = vouch(empty, pki.leaf.get(), 0);
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::no_certificates);
}

TEST(CaBundleTest, VouchFailsNoBlockWhenBundleIsUnpublished)
{
    const auto pki = makePki("vouch-unpublished");
    const auto document = serializeCertificates(bundleOf({pki.ca.get()}));
    const auto parsed = parseBundle(document);
    ASSERT_FALSE(parsed.block.has_value());

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::no_block);
}

TEST(CaBundleTest, VouchFailsHashMismatchWhenBlockDoesNotDescribeCertificates)
{
    const auto pki = makePki("vouch-mismatch");
    const auto served = bundleOf({pki.ca.get()});

    // A stamp that describes a different set: the one an operator would get by copying the block
    // of another manager's bundle, or by editing the certificates under a stamp.
    auto stamp = stampFor(bundleOf({pki.foreignCa.get()}), 1789000000);
    const auto document = sealedDocument(served, stamp);
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::hash_mismatch);
}

TEST(CaBundleTest, VouchFailsHashMismatchWhenTheComputedHashIsEmpty)
{
    const auto pki = makePki("vouch-empty-hash");

    // A bundle with a certificate i2d_X509 cannot encode -- here, simply absent -- makes
    // contentSha256() come back empty. A block whose OWN Content-SHA256 field is also empty must
    // not slip past the guard by comparing equal to it.
    ParsedBundle bundle;
    bundle.wellFormed = true;
    bundle.certificates.push_back(retain(pki.ca.get()));
    bundle.certificates.push_back(X509Ptr {});

    PublicationBlock block;
    block.publication = 1789000000;
    block.contentSha256 = "";
    block.updated = "2026-09-17T10:11:12Z";
    block.writtenBy = "wazuh-manager-certs 5.0.0 (test)";
    bundle.block = block;

    ASSERT_TRUE(contentSha256(bundle.certificates).empty());

    const auto verdict = vouch(bundle, pki.leaf.get(), 0);
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::hash_mismatch);
}

TEST(CaBundleTest, VouchFailsNoCaSignsLeafWhenLeafIsNull)
{
    const auto pki = makePki("vouch-no-leaf");
    const auto served = bundleOf({pki.ca.get()});
    const auto document = sealedDocument(served, stampFor(served, 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    // No served certificate to check against: nothing is vouched for, on purpose.
    const auto verdict = vouch(parsed, nullptr, document.size());
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::no_ca_signs_leaf);
}

TEST(CaBundleTest, VouchFailsNoCaSignsLeafWhenTheLeafChainsToNothing)
{
    const auto pki = makePki("vouch-foreign");
    const auto served = bundleOf({pki.foreignCa.get()});
    const auto document = sealedDocument(served, stampFor(served, 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::no_ca_signs_leaf);
}

TEST(CaBundleTest, VouchFailsTooManyCertificatesOverSix)
{
    const auto pki = makePki("vouch-too-many");

    // Seven, INCLUDING the CA the leaf chains to: the chain guard is checked first, so this has to
    // get past it to reach the count.
    std::vector<ca_bundle::test::EvpPkeyPtr> keys;
    std::vector<X509Ptr> extra;
    for (int index = 0; index < 6; ++index)
    {
        keys.push_back(makeTestKey());
        extra.push_back(makeCertificate(("vouch-too-many-" + std::to_string(index)).c_str(),
                                        -kDay,
                                        30 * kDay,
                                        keys.back().get(),
                                        keys.back().get(),
                                        nullptr,
                                        true));
    }

    std::vector<const X509*> raw {pki.ca.get()};
    for (const auto& certificate : extra)
    {
        raw.push_back(certificate.get());
    }
    const auto served = bundleOf(raw);
    ASSERT_EQ(served.size(), ca_bundle::kMaxCertificates + 1);

    const auto document = sealedDocument(served, stampFor(served, 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());
    ASSERT_EQ(parsed.certificates.size(), ca_bundle::kMaxCertificates + 1);

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::too_many_certificates);
}

TEST(CaBundleTest, VouchFailsTooManyBytesOverLimit)
{
    const auto pki = makePki("vouch-too-big");
    const auto served = bundleOf({pki.ca.get()});
    const auto document = sealedDocument(served, stampFor(served, 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    // The size the caller would actually hand out. Six EC certificates stay well under the cap, so
    // what the guard protects against is a bundle of large (RSA-4096, long-name) certificates; the
    // parameter is what the caller measured, and here it is one byte over.
    const auto verdict = vouch(parsed, pki.leaf.get(), ca_bundle::kMaxSerializedBytes + 1);
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::too_many_bytes);

    // Exactly at the cap still passes.
    EXPECT_EQ(vouch(parsed, pki.leaf.get(), ca_bundle::kMaxSerializedBytes).failure, GuardFailure::none);
}

TEST(CaBundleTest, VouchSucceedsAndReturnsTheBlockPublication)
{
    const auto pki = makePki("vouch-ok");
    const auto served = bundleOf({pki.ca.get(), pki.foreignCa.get()});
    const auto stamp = stampFor(served, 1789000000);
    const auto document = sealedDocument(served, stamp);
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    const auto pem = serializeCertificates(parsed.certificates);
    const auto verdict = vouch(parsed, pki.leaf.get(), pem.size());
    EXPECT_EQ(verdict.failure, GuardFailure::none);
    EXPECT_EQ(verdict.publication, stamp.publication);
}

// --- vouch(): precedence when more than one guard would fail (review, P2 #6) -------------------

TEST(CaBundleTest, VouchReportsHashMismatchBeforeTheChainGuard)
{
    const auto pki = makePki("vouch-precedence-hash");
    // A CA of somebody else's: the leaf chains to nothing here, so no_ca_signs_leaf would ALSO fail.
    const auto served = bundleOf({pki.foreignCa.get()});
    ASSERT_FALSE(leafChainsToAnyCa(pki.leaf.get(), served));

    // A stamp describing a different set of certificates: hash_mismatch fails too.
    const auto document = sealedDocument(served, stampFor(bundleOf({pki.ca.get()}), 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.failure, GuardFailure::hash_mismatch);
}

TEST(CaBundleTest, VouchReportsNoBlockBeforeTooManyCertificates)
{
    const auto pki = makePki("vouch-precedence-noblock");

    auto extra = sixExtraCertificates("vouch-precedence-noblock");
    std::vector<const X509*> raw {pki.ca.get()};
    for (const auto& certificate : extra)
    {
        raw.push_back(certificate.get());
    }
    const auto served = bundleOf(raw);
    ASSERT_EQ(served.size(), ca_bundle::kMaxCertificates + 1);

    // No stamp at all: unpublished, not merely oversized -- too_many_certificates would ALSO fail.
    const auto document = serializeCertificates(served);
    const auto parsed = parseBundle(document);
    ASSERT_FALSE(parsed.block.has_value());
    ASSERT_EQ(parsed.certificates.size(), ca_bundle::kMaxCertificates + 1);

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.failure, GuardFailure::no_block);
}

TEST(CaBundleTest, VouchReportsTooManyCertificatesBeforeTooManyBytes)
{
    const auto pki = makePki("vouch-precedence-toomany");

    auto extra = sixExtraCertificates("vouch-precedence-toomany");
    std::vector<const X509*> raw {pki.ca.get()};
    for (const auto& certificate : extra)
    {
        raw.push_back(certificate.get());
    }
    const auto served = bundleOf(raw);
    ASSERT_EQ(served.size(), ca_bundle::kMaxCertificates + 1);

    const auto document = sealedDocument(served, stampFor(served, 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());

    // A serialised size the caller measured as over the byte cap too: too_many_bytes would ALSO
    // fail, but the certificate count has to be the one named.
    const auto verdict = vouch(parsed, pki.leaf.get(), ca_bundle::kMaxSerializedBytes + 1);
    EXPECT_EQ(verdict.failure, GuardFailure::too_many_certificates);
}

// --- leafChainsToAnyCa(): a real chain, not a signature (issue #39319, C33) --------------------
//
// The guard this replaced checked only the signature, so a certificate carrying the issuing CA's
// public key under ANOTHER subject passed every check while the leaf named the other one as its
// issuer and no agent could build a chain to it: remoted announced a generation whose anchor was
// unusable. Each case below is decided the way an agent's own OpenSSL decides it -- default flags,
// so a self-signed anchor, and the validity windows and basicConstraints of the path included.
// ---------------------------------------------------------------------------

namespace
{
    /// A self-signed CA:TRUE certificate carrying @p key -- @p pki's own CA key, for the impostor --
    /// under the subject @p commonName. Serial 2 so it never collides with makePki()'s.
    X509Ptr
    selfSignedCaWithKey(const char* commonName, EVP_PKEY* key, long notBefore = -kDay, long notAfter = 30 * kDay)
    {
        return makeCertificate(commonName, notBefore, notAfter, key, key, nullptr, true, 2);
    }
} // namespace

TEST(CaBundleTest, LeafDoesNotChainToACaWithTheSameKeyAndAnotherSubject)
{
    // THE regression test of C33 (Codex, P1). The impostor holds the issuing CA's public key, so it
    // verifies the leaf's signature perfectly, and it is a valid, current CA:TRUE certificate. What
    // it is not is the issuer the leaf NAMES, so nothing chains to it: an agent handed this bundle
    // gets "unable to get local issuer certificate" and cannot verify this manager at all.
    const auto pki = makePki("chain-impostor");
    const auto impostor = selfSignedCaWithKey("chain-impostor-other-subject", pki.caKey.get());

    const auto impostorFacts = describe(impostor.get(), pki.leaf.get());
    ASSERT_TRUE(impostorFacts.signsLeaf) << "the fixture must be the real bug shape: it DOES sign";
    ASSERT_TRUE(impostorFacts.isCa);
    ASSERT_NE(impostorFacts.subject, describe(pki.ca.get(), pki.leaf.get()).subject);

    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({impostor.get()})));

    // With the real issuer next to it the bundle is usable again, whichever order they sit in: one
    // unusable entry is not what decides a bundle.
    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({impostor.get(), pki.ca.get()})));
    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({pki.ca.get(), impostor.get()})));
}

TEST(CaBundleTest, LeafChainsToItsRootCaAloneAndAmongForeignOnes)
{
    const auto pki = makePki("chain-root");

    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({pki.ca.get()})));
    // The root is NOT the first entry: every anchor has to be tried, not only the first.
    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({pki.foreignCa.get(), pki.ca.get()})));
    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({pki.foreignCa.get()})));
}

TEST(CaBundleTest, AnExpiredSignerIsNotAnAnchor)
{
    // The rotation overlap: the same CA re-issued, and the expired copy left in the bundle. It
    // signs the leaf (same key, same subject), and an agent's verifier still refuses it -- so it no
    // longer counts here either, which is the behaviour change C33 documents.
    const auto pki = makePki("chain-expired");
    const auto expired = selfSignedCaWithKey("chain-expired-ca", pki.caKey.get(), -3 * kDay, -kDay);

    ASSERT_TRUE(describe(expired.get(), pki.leaf.get()).signsLeaf);
    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({expired.get()})));
    // The current re-issue of the same CA is the one that carries the bundle.
    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({expired.get(), pki.ca.get()})));
}

TEST(CaBundleTest, ASignerWithoutCaTrueIsNotAnAnchor)
{
    // A certificate holding the CA's key with no basicConstraints at all: its signature IS on the
    // leaf, and `pkg_installer.sh` and every TLS client refuse it as a trust anchor.
    const auto pki = makePki("chain-not-a-ca");
    const auto notACa =
        makeCertificate("chain-not-a-ca-ca", -kDay, 30 * kDay, pki.caKey.get(), pki.caKey.get(), nullptr, false, 3);

    ASSERT_TRUE(describe(notACa.get(), pki.leaf.get()).signsLeaf);
    ASSERT_FALSE(describe(notACa.get(), pki.leaf.get()).isCa);
    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundleOf({notACa.get()})));
}

TEST(CaBundleTest, AnIntermediateAloneIsNotAnAnchorWithDefaultFlags)
{
    // root -> intermediate -> leaf, with only the intermediate published. It signed the leaf, and
    // with X509_V_FLAG_PARTIAL_CHAIN (remoted's chainValidates(), for the operator's logs) it would
    // be an anchor -- but an agent's OpenSSL has no trust settings of its own, so only a SELF-SIGNED
    // certificate of its CA file is trusted and that agent's handshake fails. Default flags here
    // say the same thing: not publishable.
    const auto rootKey = makeTestKey();
    const auto intermediateKey = makeTestKey();
    const auto leafKey = makeTestKey();
    const auto root = makeCertificate("chain-int-root", -kDay, 30 * kDay, rootKey.get(), rootKey.get(), nullptr, true);
    const auto intermediate = makeCertificate(
        "chain-int-intermediate", -kDay, 30 * kDay, intermediateKey.get(), rootKey.get(), root.get(), true);
    const auto leaf =
        makeCertificate("chain-int-leaf", -kDay, 10 * kDay, leafKey.get(), intermediateKey.get(), intermediate.get());

    ASSERT_TRUE(describe(intermediate.get(), leaf.get()).signsLeaf);
    EXPECT_FALSE(leafChainsToAnyCa(leaf.get(), bundleOf({intermediate.get()})));

    // The root alone cannot complete it either (the intermediate is missing from the bundle, and
    // the leaf does not name the root as its issuer); root AND intermediate together can.
    EXPECT_FALSE(leafChainsToAnyCa(leaf.get(), bundleOf({root.get()})));
    EXPECT_TRUE(leafChainsToAnyCa(leaf.get(), bundleOf({root.get(), intermediate.get()})));
}

TEST(CaBundleTest, AnExpiredServedLeafChainsToNothing)
{
    // The other end of the window check, and the one case of C33 that is about the LEAF rather than
    // the anchor: a served certificate past its notAfter validates against nothing, so its bundle
    // is refused too. An agent could not complete a handshake with it either, but the guard is
    // stricter than it was here as well -- worth stating, because the operator's fix is to renew
    // the listener certificate, not the CA.
    const auto pki = makePki("chain-expired-leaf");
    const auto expiredLeaf = makeCertificate(
        "chain-expired-leaf-leaf", -3 * kDay, -kDay, pki.leafKey.get(), pki.caKey.get(), pki.ca.get(), false, 4);

    ASSERT_TRUE(describe(pki.ca.get(), expiredLeaf.get()).signsLeaf);
    EXPECT_FALSE(leafChainsToAnyCa(expiredLeaf.get(), bundleOf({pki.ca.get()})));
}

TEST(CaBundleTest, ASelfSignedLeafIsItsOwnAnchor)
{
    // The quickstart shape: the served certificate itself published as the bundle. It chains at
    // depth 0 -- an agent that pins exactly this certificate does verify the handshake -- so the
    // property the signature check had here is kept.
    const auto key = makeTestKey();
    const auto selfSigned = makeCertificate("chain-self-signed", -kDay, 10 * kDay, key.get(), key.get(), nullptr);

    EXPECT_TRUE(leafChainsToAnyCa(selfSigned.get(), bundleOf({selfSigned.get()})));
}

TEST(CaBundleTest, NothingChainsWithoutALeafOrWithoutAnchors)
{
    const auto pki = makePki("chain-nothing");

    EXPECT_FALSE(leafChainsToAnyCa(nullptr, bundleOf({pki.ca.get()})));
    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), {}));
    // A null entry among the anchors is skipped, not fatal: the real CA next to it still decides.
    std::vector<X509Ptr> withNull;
    withNull.push_back(X509Ptr {});
    withNull.push_back(retain(pki.ca.get()));
    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), withNull));
}

TEST(CaBundleTest, LeafChainsToAnyCaJudgesAtTheInstantGiven)
{
    // A rotation's pre-staged CA: the window opens in ten minutes, and the leaf it signs is valid
    // now. Judged at this instant it anchors nothing; inside its window it does; past its notAfter
    // it does not again. The caller's clock decides, not the file.
    const auto pki = makePki("chain-at");
    const auto futureCa = selfSignedCaWithKey("chain-at-ca", pki.caKey.get(), 600, 7200);
    const auto bundle = bundleOf({futureCa.get()});
    const auto now = std::time(nullptr);

    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundle));
    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundle, now));
    EXPECT_TRUE(leafChainsToAnyCa(pki.leaf.get(), bundle, now + 1200));
    EXPECT_FALSE(leafChainsToAnyCa(pki.leaf.get(), bundle, now + 8000));
}

TEST(CaBundleTest, VouchJudgesTheChainGuardAtTheInstantGiven)
{
    // The same CA, stamped: the only guard with a date term follows the instant it is given, and
    // the publication comes back exactly when the chain does.
    const auto pki = makePki("vouch-at");
    const auto futureCa = selfSignedCaWithKey("vouch-at-ca", pki.caKey.get(), 600, 7200);
    const auto served = bundleOf({futureCa.get()});
    const auto parsed = parseBundle(sealedDocument(served, stampFor(served, 1789000000)));
    ASSERT_TRUE(parsed.block.has_value());
    const auto bytes = serializeCertificates(parsed.certificates).size();
    const auto now = std::time(nullptr);

    EXPECT_EQ(vouch(parsed, pki.leaf.get(), bytes).failure, GuardFailure::no_ca_signs_leaf);
    EXPECT_EQ(vouch(parsed, pki.leaf.get(), bytes, now).failure, GuardFailure::no_ca_signs_leaf);
    const auto inside = vouch(parsed, pki.leaf.get(), bytes, now + 1200);
    EXPECT_EQ(inside.failure, GuardFailure::none);
    EXPECT_EQ(inside.publication, 1789000000);
    EXPECT_EQ(vouch(parsed, pki.leaf.get(), bytes, now + 8000).failure, GuardFailure::no_ca_signs_leaf);
}

TEST(CaBundleTest, VouchRefusesABundleWhoseCaOnlySignsTheLeaf)
{
    // The same impostor, now through the guard that decides what generation is announced: a
    // correctly stamped bundle whose hash matches its certificates, refused because the leaf does
    // not chain to any of them. This is what C33 keeps remoted from publishing.
    const auto pki = makePki("vouch-impostor");
    const auto impostor = selfSignedCaWithKey("vouch-impostor-other-subject", pki.caKey.get());
    const auto served = bundleOf({impostor.get()});
    const auto document = sealedDocument(served, stampFor(served, 1789000000));
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.block.has_value());
    ASSERT_TRUE(describe(parsed.certificates.front().get(), pki.leaf.get()).signsLeaf);

    const auto verdict = vouch(parsed, pki.leaf.get(), document.size());
    EXPECT_EQ(verdict.publication, 0);
    EXPECT_EQ(verdict.failure, GuardFailure::no_ca_signs_leaf);
}

// --- renderBlock(): what the tool writes is what everyone reads (T4) ---------------------------

TEST(CaBundleTest, RenderBlockRoundTripsThroughParseBundle)
{
    const auto pki = makePki("round-trip");
    const auto served = bundleOf({pki.ca.get()});
    const auto stamp = stampFor(served, 1789000000);

    const auto block = renderBlock(stamp);
    // The eight `##` lines of the issue, in order, each one a PEM comment.
    EXPECT_EQ(block,
              "##\n## Wazuh CA bundle\n##\n## Publication: 1789000000\n## Content-SHA256: " + stamp.contentSha256 +
                  "\n## Updated: 2026-09-17T10:11:12Z\n## Written by: wazuh-manager-certs 5.0.0 (test)\n##\n");

    const auto document = sealedDocument(served, stamp);
    const auto parsed = parseBundle(document);
    ASSERT_TRUE(parsed.wellFormed);
    ASSERT_TRUE(parsed.block.has_value());
    EXPECT_EQ(parsed.block->publication, stamp.publication);
    EXPECT_EQ(parsed.block->contentSha256, stamp.contentSha256);
    EXPECT_EQ(parsed.block->updated, stamp.updated);
    EXPECT_EQ(parsed.block->writtenBy, stamp.writtenBy);
    EXPECT_EQ(renderBlock(*parsed.block), block);

    // Hand the very same document to `openssl` and to Python's ssl: anexos/e1a/check-openssl-python.sh
    // runs this case with CA_BUNDLE_SEALED_DIR set and then loads what it wrote.
    if (const char* directory = std::getenv("CA_BUNDLE_SEALED_DIR"); directory != nullptr)
    {
        const std::string bundlePath = std::string {directory} + "/bundle.pem";
        std::ofstream bundle {bundlePath, std::ios::binary};
        ASSERT_TRUE(bundle.good()) << "cannot write " << bundlePath;
        bundle << document;
        bundle.close();

        const std::string leafPath = std::string {directory} + "/leaf.pem";
        std::ofstream leaf {leafPath, std::ios::binary};
        ASSERT_TRUE(leaf.good()) << "cannot write " << leafPath;
        leaf << serializeCertificates(bundleOf({pki.leaf.get()}));
    }
}

// --- identityOf() / describe(): what the tool prints ------------------------------------------

TEST(CaBundleTest, IdentityOfIsX509Sha256OfTheDerEncoding)
{
    const auto pki = makePki("identity");

    const auto expected = sha256HexOfDer(pki.ca.get());
    ASSERT_EQ(expected.size(), 64U);
    EXPECT_EQ(identityOf(pki.ca.get()), "x509-sha256:" + expected);

    // Different certificate, different identity; no certificate, no identity.
    EXPECT_NE(identityOf(pki.foreignCa.get()), identityOf(pki.ca.get()));
    EXPECT_TRUE(identityOf(nullptr).empty());
}

TEST(CaBundleTest, DescribeFillsSubjectIssuerDatesAndSignsLeaf)
{
    const auto pki = makePki("describe");

    const auto facts = describe(pki.ca.get(), pki.leaf.get());
    EXPECT_NE(facts.subject.find("CN=describe-ca"), std::string::npos);
    EXPECT_EQ(facts.issuer, facts.subject); // self-signed
    EXPECT_EQ(facts.identity, identityOf(pki.ca.get()));
    EXPECT_TRUE(facts.isCa);
    EXPECT_TRUE(facts.signsLeaf);
    // For the CA that really issued the leaf the signature fact and the chain verdict agree; the
    // cases where they DO NOT are what the LeafChainsToAnyCa suite below is about.
    EXPECT_EQ(facts.signsLeaf, leafChainsToAnyCa(pki.leaf.get(), bundleOf({pki.ca.get()})));

    const auto now = std::time(nullptr);
    EXPECT_LT(facts.notBefore, now);
    EXPECT_GT(facts.notAfter, now);
    // notBefore a day back, notAfter thirty days out: the window makePki() asked for, give or take
    // the seconds the test itself takes.
    EXPECT_NEAR(static_cast<double>(facts.notAfter - facts.notBefore), static_cast<double>(31 * kDay), 300.0);

    // A CA of the bundle that does NOT hold the listener up, and no certificate at all.
    const auto foreign = describe(pki.foreignCa.get(), pki.leaf.get());
    EXPECT_FALSE(foreign.signsLeaf);
    EXPECT_EQ(foreign.signsLeaf, leafChainsToAnyCa(pki.leaf.get(), bundleOf({pki.foreignCa.get()})));
    EXPECT_TRUE(foreign.isCa);

    const auto leafFacts = describe(pki.leaf.get(), pki.leaf.get());
    EXPECT_FALSE(leafFacts.isCa);

    const auto none = describe(nullptr, pki.leaf.get());
    EXPECT_TRUE(none.subject.empty());
    EXPECT_TRUE(none.identity.empty());
    EXPECT_FALSE(none.signsLeaf);
    EXPECT_EQ(none.notBefore, 0);
    EXPECT_EQ(none.notAfter, 0);
}

TEST(CaBundleTest, DescribeKeepsDatesBefore1970Negative)
{
    auto key = makeTestKey();
    auto certificate = makeCertificate("describe-before-1970", -kDay, 30 * kDay, key.get(), key.get(), nullptr, true);

    // 1960-01-01T00:00:00Z, pinned directly (not as an offset from "now"): -315619200.
    ca_bundle::test::setAbsoluteNotBeforeAndResign(certificate.get(), -315619200, key.get());

    const auto facts = describe(certificate.get(), nullptr);
    EXPECT_EQ(facts.notBefore, -315619200);
    // notAfter is untouched and still comes back as the ordinary, post-1970 date it is.
    EXPECT_GT(facts.notAfter, 0);
}
