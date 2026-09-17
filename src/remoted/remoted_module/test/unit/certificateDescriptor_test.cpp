/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file certificateDescriptor_test.cpp
 * @brief What `GET /tls` says about one certificate (issue #39320): names, validity, the
 *        `x509-sha256:` identity and the bundle hash, all from certificates built in memory.
 */

#include "ca_bundle/ca_bundle.hpp"
#include "http_server/certificateDescriptor.hpp"
#include "http_server/tlsCertificateStatus.hpp"
#include "testCertificates.hpp"

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

using remoted::http::contentSha256;
using remoted::http::describeCertificate;
using remoted::http::fingerprintOf;
using remoted::http::kFingerprintPrefix;
using remoted::http::rfc3339Utc;
using remoted::http::X509Ptr;
using remoted::test::makeCertificate;
using remoted::test::makeTestKey;

namespace
{
    std::int64_t nowSeconds()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    bool isLowercaseHex(const std::string& text)
    {
        return !text.empty() && std::all_of(text.begin(),
                                            text.end(),
                                            [](unsigned char character)
                                            { return std::isxdigit(character) && !std::isupper(character); });
    }

    /// SHA-256 of the SubjectPublicKeyInfo, hex: what a key pin would be, and what the identity must NOT be.
    std::string spkiSha256(const X509* certificate)
    {
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
        unsigned int length = 0;
        if (X509_pubkey_digest(certificate, EVP_sha256(), digest.data(), &length) != 1)
        {
            return {};
        }
        static constexpr char kHex[] = "0123456789abcdef";
        std::string hex;
        for (unsigned int index = 0; index < length; ++index)
        {
            hex.push_back(kHex[digest[index] >> 4]);
            hex.push_back(kHex[digest[index] & 0x0F]);
        }
        return hex;
    }

    X509Ptr duplicate(const X509Ptr& certificate)
    {
        return X509Ptr {X509_dup(certificate.get())};
    }
} // namespace

TEST(CertificateDescriptor, DescribesALeafSignedByACa)
{
    const auto caKey = makeTestKey();
    const auto leafKey = makeTestKey();
    const auto ca = makeCertificate("Test CA", -3600, 86400, caKey.get(), caKey.get(), nullptr, nullptr, true);
    const auto leaf = makeCertificate("manager-01",
                                      -60,
                                      3600,
                                      leafKey.get(),
                                      caKey.get(),
                                      ca.get(),
                                      "DNS:manager-01.example.com,IP:10.0.0.5,IP:2001:db8::1,email:ops@example.com");

    const auto before = nowSeconds();
    const auto described = describeCertificate(leaf.get());
    ASSERT_TRUE(described.has_value());

    EXPECT_EQ(described->subject, "CN=manager-01");
    EXPECT_EQ(described->issuer, "CN=Test CA");
    // Bare names, the two types a TLS client matches a server against, in certificate order; the
    // email entry is neither.
    EXPECT_EQ(described->subjectAltNames,
              (std::vector<std::string> {"manager-01.example.com", "10.0.0.5", "2001:db8::1"}));

    // Epoch seconds, within the slack of the test's own clock reads.
    EXPECT_GE(described->notBefore, before - 60 - 5);
    EXPECT_LE(described->notBefore, before - 60 + 5);
    EXPECT_GE(described->notAfter, before + 3600 - 5);
    EXPECT_LE(described->notAfter, before + 3600 + 5);

    EXPECT_EQ(described->serial, "0x01"); // makeCertificate() sets serial 1; BN_bn2hex pads to a byte
    EXPECT_EQ(described->fingerprint, fingerprintOf(leaf.get()));
}

TEST(CertificateDescriptor, FingerprintIsThePrefixedLowercaseSha256OfTheDer)
{
    const auto key = makeTestKey();
    const auto certificate = makeCertificate("remoted", 0, 3600, key.get(), key.get(), nullptr);

    const auto fingerprint = fingerprintOf(certificate.get());
    ASSERT_EQ(fingerprint.rfind(kFingerprintPrefix, 0), 0U) << fingerprint;
    const auto hex = fingerprint.substr(kFingerprintPrefix.size());
    EXPECT_EQ(hex.size(), 64U);
    EXPECT_TRUE(isLowercaseHex(hex)) << hex;
    EXPECT_EQ(hex.find(':'), std::string::npos);

    // Stable across a PEM round trip: the identity is of the DER, not of the bytes on disk.
    const auto reparsed = ca_bundle::parseBundle(remoted::http::serializeCertificates({} /*none*/));
    EXPECT_TRUE(reparsed.certificates.empty());
    std::vector<X509Ptr> one;
    one.push_back(duplicate(certificate));
    const auto roundTripped = ca_bundle::parseBundle(remoted::http::serializeCertificates(one));
    ASSERT_EQ(roundTripped.certificates.size(), 1U);
    EXPECT_EQ(fingerprintOf(roundTripped.certificates.front().get()), fingerprint);

    // Not the SPKI pin: a reissue with the same key is a different certificate and must read as one.
    EXPECT_NE(hex, spkiSha256(certificate.get()));
    const auto reissued = makeCertificate("remoted", 0, 7200, key.get(), key.get(), nullptr);
    EXPECT_NE(fingerprintOf(reissued.get()), fingerprint);
    EXPECT_EQ(spkiSha256(reissued.get()), spkiSha256(certificate.get()));

    EXPECT_TRUE(fingerprintOf(nullptr).empty());
}

TEST(CertificateDescriptor, ExpiredCertificateReadsNegativeRemainingSeconds)
{
    const auto key = makeTestKey();
    const auto expired = makeCertificate("expired", -172800, -86400, key.get(), key.get(), nullptr);

    const auto described = describeCertificate(expired.get());
    ASSERT_TRUE(described.has_value());
    const auto remaining = described->notAfter - nowSeconds();
    EXPECT_LT(remaining, 0);
    EXPECT_LE(remaining, -86400 + 5);
}

TEST(CertificateDescriptor, NoSubjectAltNameYieldsAnEmptyList)
{
    const auto key = makeTestKey();
    const auto certificate = makeCertificate("plain", 0, 3600, key.get(), key.get(), nullptr);

    const auto described = describeCertificate(certificate.get());
    ASSERT_TRUE(described.has_value());
    EXPECT_TRUE(described->subjectAltNames.empty());
    EXPECT_EQ(described->subject, described->issuer); // self-signed
}

TEST(CertificateDescriptor, NullCertificateIsNotDescribed)
{
    EXPECT_FALSE(describeCertificate(nullptr).has_value());
}

TEST(CertificateDescriptor, ContentSha256IsIndependentOfCertificateOrder)
{
    const auto firstKey = makeTestKey();
    const auto secondKey = makeTestKey();
    const auto first = makeCertificate("CA one", 0, 3600, firstKey.get(), firstKey.get(), nullptr, nullptr, true);
    const auto second = makeCertificate("CA two", 0, 3600, secondKey.get(), secondKey.get(), nullptr, nullptr, true);

    std::vector<X509Ptr> ordered;
    ordered.push_back(duplicate(first));
    ordered.push_back(duplicate(second));
    std::vector<X509Ptr> reversed;
    reversed.push_back(duplicate(second));
    reversed.push_back(duplicate(first));

    const auto hash = ca_bundle::contentSha256(ordered);
    EXPECT_EQ(hash.size(), 64U);
    EXPECT_TRUE(isLowercaseHex(hash)) << hash;
    EXPECT_EQ(ca_bundle::contentSha256(reversed), hash);

    std::vector<X509Ptr> single;
    single.push_back(duplicate(first));
    EXPECT_NE(ca_bundle::contentSha256(single), hash);
}

TEST(CertificateDescriptor, Rfc3339UtcFormatsEpochSeconds)
{
    EXPECT_EQ(rfc3339Utc(0), "1970-01-01T00:00:00Z");
    EXPECT_EQ(rfc3339Utc(1789466400), "2026-09-15T10:00:00Z");
}
