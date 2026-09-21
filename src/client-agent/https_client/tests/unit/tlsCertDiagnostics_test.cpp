/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 15, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tlsCertDiagnostics.hpp"

#include "certFixtures.hpp"

#include <openssl/x509_vfy.h>

#include <gtest/gtest.h>

#include <ostream>

using cert_fixtures::makeSelfSignedEc;

TEST(TlsCertSanNamesTest, ExtractsDnsAndIpEntriesOpenSslFormatted)
{
    auto [certificate, key] = makeSelfSignedEc("leaf", 1, nullptr, "DNS:manager.example.com,IP:10.0.0.1");
    ASSERT_TRUE(certificate);

    const auto names = tlsCertSanNames(certificate.get());

    ASSERT_EQ(2u, names.size());
    EXPECT_EQ("DNS:manager.example.com", names[0]);
    EXPECT_EQ("IP Address:10.0.0.1", names[1]);
}

TEST(TlsCertSanNamesTest, SkipsSanTypesNoHostnameCheckEverMatchesAgainst)
{
    // email + DNS: only the DNS entry is a type a TLS client ever compares an
    // identity against (RFC 6125).
    auto [certificate, key] = makeSelfSignedEc("leaf", 1, nullptr, "email:ops@example.com,DNS:manager.example.com");
    ASSERT_TRUE(certificate);

    const auto names = tlsCertSanNames(certificate.get());

    ASSERT_EQ(1u, names.size());
    EXPECT_EQ("DNS:manager.example.com", names[0]);
}

TEST(TlsCertSanNamesTest, EmptyWhenTheCertificateCarriesNoSanExtension)
{
    auto [certificate, key] = makeSelfSignedEc("leaf", 1);
    ASSERT_TRUE(certificate);

    EXPECT_TRUE(tlsCertSanNames(certificate.get()).empty());
}

TEST(TlsCertSanNamesTest, EmptyForANullCertificate)
{
    EXPECT_TRUE(tlsCertSanNames(nullptr).empty());
}

TEST(TlsCertTimeStringTest, FormatsANonNullAsn1Time)
{
    // notBefore == now (offset 0): the exact rendering depends on the clock at run time, so
    // this only asserts the OpenSSL month abbreviation and " GMT" suffix every notBefore
    // shares, not an exact string.
    auto [certificate, key] = makeSelfSignedEc("leaf", 1);
    ASSERT_TRUE(certificate);

    const auto formatted = tlsCertTimeString(X509_get0_notBefore(certificate.get()));

    EXPECT_FALSE(formatted.empty());
    EXPECT_NE(std::string::npos, formatted.find("GMT"));
}

TEST(TlsCertTimeStringTest, EmptyForANullTime)
{
    EXPECT_TRUE(tlsCertTimeString(nullptr).empty());
}

struct TlsClassifyCase
{
    bool sawDepth0;
    int depth0Error;
    bool peerVerificationFailed;
    TlsFailureKind expected;
};

inline void PrintTo(const TlsClassifyCase& value, std::ostream* stream)
{
    *stream << "sawDepth0=" << value.sawDepth0 << " depth0Error=" << value.depth0Error
            << " peerVerificationFailed=" << value.peerVerificationFailed
            << " expected=" << static_cast<int>(value.expected);
}

class TlsVerifyClassifierTable : public ::testing::TestWithParam<TlsClassifyCase>
{
};

TEST_P(TlsVerifyClassifierTable, ClassifiesAsExpected)
{
    const auto& param = GetParam();
    EXPECT_EQ(param.expected,
              classifyTlsVerifyFailure(param.sawDepth0, param.depth0Error, param.peerVerificationFailed));
}

INSTANTIATE_TEST_SUITE_P(
    TlsFailureTable,
    TlsVerifyClassifierTable,
    ::testing::Values(
        // The leaf was never reached at all (a pure transport failure, or verify_mode=none):
        // depth0Error is meaningless, always None regardless of its value.
        TlsClassifyCase {false, X509_V_OK, true, TlsFailureKind::None},
        TlsClassifyCase {false, X509_V_ERR_CERT_HAS_EXPIRED, true, TlsFailureKind::None},
        // The two date causes, named directly by OpenSSL at depth 0.
        TlsClassifyCase {true, X509_V_ERR_CERT_NOT_YET_VALID, true, TlsFailureKind::CertNotYetValid},
        TlsClassifyCase {true, X509_V_ERR_CERT_HAS_EXPIRED, true, TlsFailureKind::CertExpired},
        // Hostname mismatch named directly by OpenSSL (curl/OpenSSL combinations that route
        // the hostname check through the verify callback).
        TlsClassifyCase {true, X509_V_ERR_HOSTNAME_MISMATCH, true, TlsFailureKind::HostnameMismatch},
        TlsClassifyCase {true, X509_V_ERR_IP_ADDRESS_MISMATCH, true, TlsFailureKind::HostnameMismatch},
        // Hostname mismatch by elimination: the chain and every certificate's validity
        // period verified cleanly, yet libcurl still failed peer verification.
        TlsClassifyCase {true, X509_V_OK, true, TlsFailureKind::HostnameMismatch},
        // The chain verified cleanly AND libcurl's overall result was not
        // CURLE_PEER_FAILED_VERIFICATION: nothing to classify (e.g. the attempt failed for
        // an unrelated reason after a clean handshake -- not reachable in practice since this
        // classifier is only ever called on a TlsFail, but the function must not invent a
        // hostname mismatch out of a clean verification).
        TlsClassifyCase {true, X509_V_OK, false, TlsFailureKind::None},
        // An ordinary chain/CA-trust failure (untrusted root, wrong issuer, ...): not one of
        // the two classified causes, stays generic.
        TlsClassifyCase {true, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, true, TlsFailureKind::None},
        TlsClassifyCase {true, X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, true, TlsFailureKind::None}));
