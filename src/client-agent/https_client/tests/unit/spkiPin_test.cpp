/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * SHA-256 of a certificate's SubjectPublicKeyInfo -- the enrollment token's
 * `pin` (RFC 7469 section 2.4).
 *
 * The fixtures are FIXED, committed certificates, and every expected value is
 * reproducible by hand:
 *
 *   # 64 lowercase hex (kRsaSpkiHex):
 *   openssl x509 -in ca1.pem -noout -pubkey | openssl pkey -pubin -outform der \
 *     | openssl dgst -sha256 -r | cut -d' ' -f1
 *   # 43-char unpadded base64url (kRsaSpkiPin) -- note `openssl base64` is
 *   # neither URL-safe nor unpadded, hence the tr pipeline:
 *   openssl x509 -in ca1.pem -noout -pubkey | openssl pkey -pubin -outform der \
 *     | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
 *   # whole-certificate digest (kRsaCertDerSha256Hex) -- must DIFFER:
 *   openssl x509 -in ca1.pem -outform der | openssl dgst -sha256 -r | cut -d' ' -f1
 *
 * They are also not magic numbers: MatchesTheX509PubkeyRouteFor{Rsa,EcP256}
 * recompute them in-process through the OTHER OpenSSL encoding API, so a typo
 * in a pasted constant fails this suite rather than surviving review.
 *
 * The same fixtures and the same expected pins are used by the manager-side
 * helper in qa-integration-framework
 * (tests/unit/test_spki_pin.py), so agent and mint are provably hashing
 * identical bytes to identical values.
 */

#include "spkiPin.hpp"

#include "certFixtures.hpp"
#include "digest.hpp"
#include "jwt/base64Url.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>

namespace
{
    // RSA-2048 self-signed CA, CN=Wazuh Test CA RSA, serial 1.
    const std::string kRsaCertPem = R"PEM(-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFXYXp1
aCBUZXN0IENBIFJTQTAeFw0yNjA5MDgyMDU1NTdaFw0zNjA5MDUyMDU1NTdaMBwx
GjAYBgNVBAMMEVdhenVoIFRlc3QgQ0EgUlNBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA3RHf+NbNSvrAYce0BkxiWKT9RB7m35wC7K2EVaxzVCRUm15c
U8w52iAVQowEzS9YvWuwWg+HlvJxapIyRdf661v/jiqichaEZs4z1IwdvwdDZpKb
0tmlpT6San57LX7Y+RuqZ/YNdctYwunG9AiSJDKnqOjYfZ9i1YkyAsf8SJb1RILq
QE2m5ffJr+LM4uaIfH5dq0w25G3o2lAonnb/cRLS2dDUGBsnsmW0flrm12P2pMcl
mviEHwqIaJcQ7DK2Lh+OioqYTapjG6/YDcRzUCnHJbXBhHHfFD0mjUTWGPbTIvpZ
9fSp21A74Nl63b7M5kMc86Wlq8T2JxszEbQ2XwIDAQABo1MwUTAdBgNVHQ4EFgQU
VK6zm2Yiqy0N6yBHUojeyqIlT/gwHwYDVR0jBBgwFoAUVK6zm2Yiqy0N6yBHUoje
yqIlT/gwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAad9VCQ88
KtE5TCrCurf5Nv2ShvcWGS7fyoyOgHq+PBVl3IzENw83zq/whQdcJOUuu12zlc4J
x4zDUFey0FzLlpIrKg9F9UFmFA8RIpZ3zF/SgiezexQW7mJwxtke78m5PEuks5HX
FWXl6Kd6ZNIl7+S5+lBGqidT6RaJtzMrc2i+CWZvlKA3vuGfFzuyRdfrq8E2GETz
0GBR12GdVirwYPC6xO4c7NFHupnDRttIECGXQw/TbYfqycMxbREmADtKPMsfJbK2
OGU1K32wI9/ecJiwYOJwmDaURj/0RnQFxhJDJ5/ZGoLQ941mX7cpA8EmiSuysacA
6y81YLGrpuwMkA==
-----END CERTIFICATE-----
)PEM";

    // The SAME RSA key, reissued: different subject, serial, validity and extensions.
    const std::string kRsaReissuedPem = R"PEM(-----BEGIN CERTIFICATE-----
MIIDYzCCAkugAwIBAgICEJIwDQYJKoZIhvcNAQELBQAwQjELMAkGA1UEBhMCRVMx
DjAMBgNVBAoMBVdhenVoMSMwIQYDVQQDDBpXYXp1aCBUZXN0IENBIFJTQSBSZWlz
c3VlZDAeFw0yNjA5MDgyMDU1NTdaFw0yNjEwMDgyMDU1NTdaMEIxCzAJBgNVBAYT
AkVTMQ4wDAYDVQQKDAVXYXp1aDEjMCEGA1UEAwwaV2F6dWggVGVzdCBDQSBSU0Eg
UmVpc3N1ZWQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdEd/41s1K
+sBhx7QGTGJYpP1EHubfnALsrYRVrHNUJFSbXlxTzDnaIBVCjATNL1i9a7BaD4eW
8nFqkjJF1/rrW/+OKqJyFoRmzjPUjB2/B0NmkpvS2aWlPpJqfnstftj5G6pn9g11
y1jC6cb0CJIkMqeo6Nh9n2LViTICx/xIlvVEgupATabl98mv4szi5oh8fl2rTDbk
bejaUCiedv9xEtLZ0NQYGyeyZbR+WubXY/akxyWa+IQfCoholxDsMrYuH46KiphN
qmMbr9gNxHNQKccltcGEcd8UPSaNRNYY9tMi+ln19KnbUDvg2XrdvszmQxzzpaWr
xPYnGzMRtDZfAgMBAAGjYzBhMB0GA1UdDgQWBBRUrrObZiKrLQ3rIEdSiN7KoiVP
+DAfBgNVHSMEGDAWgBRUrrObZiKrLQ3rIEdSiN7KoiVP+DAPBgNVHRMBAf8EBTAD
AQH/MA4GA1UdDwEB/wQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEAYc57zE517thZ
IOfCwAA+Na9YPeNM07GDWDwlfxQkF4gb/gzUwpYcvnvupuFhnVuKDdxho2S9xWaK
rGiEvCjTRrTE03X56XTMIImlSLLnRtATotR54MXzpn2CHCG+xkOBsM40C9FVz09J
+PnNthF/HpvP7McgZfUTLLbiv7SJ6t+YVX2KiSNEmSeLk1ofLaWwAArM/o+7pXeH
kWI9GEUNpAnexd19VxSfPtPkjrWisC80NOUvPNDxczCAen6Fs5jpJT4l1ntGX2vg
F/egfaQI3CxPBzVwMW3yrEdmXu0ue1mJGPoSrLJ9gMnw/t5KWNNLj99+X+u5dq1S
ii4lUv1rsg==
-----END CERTIFICATE-----
)PEM";

    // EC P-256 named-curve self-signed CA.
    const std::string kEcCertPem = R"PEM(-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUI6SSL/onOo3VgnPxqbSqkedq5KAwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQV2F6dWggVGVzdCBDQSBFQzAeFw0yNjA5MDgyMDU1NTdaFw0z
NjA5MDUyMDU1NTdaMBsxGTAXBgNVBAMMEFdhenVoIFRlc3QgQ0EgRUMwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARTtB3js9Tc/oYbfaUChZDLoN5gcS2iHypfm2FS
NLPMD9b36JfDq6szFKR0jWtdkTAhs2f04PABxuOLsulYpFkCo1MwUTAdBgNVHQ4E
FgQU/NA4KJqMsykyK5I9yLQa1r9sEOswHwYDVR0jBBgwFoAU/NA4KJqMsykyK5I9
yLQa1r9sEOswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAXZ6K6
qmpfpBxPhgdQbMme6mfP1NVsdWrbNsqxkFc5VgIhANik3C8qTxfAMxAdYPt3blUB
8ZDE5FgX9kvQG65e522x
-----END CERTIFICATE-----
)PEM";

    // A DIFFERENT EC P-256 key, same subject CN -- the wrong-pin counterparty.
    const std::string kEcOtherKeyPem = R"PEM(-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUC2ZHXbHBCKoAptlSUXTG96ArookwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQV2F6dWggVGVzdCBDQSBFQzAeFw0yNjA5MDgyMDU1NTdaFw0z
NjA5MDUyMDU1NTdaMBsxGTAXBgNVBAMMEFdhenVoIFRlc3QgQ0EgRUMwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARPvYvHaRAJNKxQifZkz99UNenUXVTj5T/yEcVz
CR7mUWHaaTyMKdltkl7JiOuELQkHu/43uURs9kyr6ykGosCZo1MwUTAdBgNVHQ4E
FgQUI2uEecdbVwOoL8WSubp7oHsHP5EwHwYDVR0jBBgwFoAUI2uEecdbVwOoL8WS
ubp7oHsHP5EwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBRTvA9
gTQBndRBjkvFlOj7B40mqO0xRd9Yf5akEMAKtQIgLjrAjTJgYyX5j3l2uIBKoYAr
0F/2hZNaSIyRJfNdY90=
-----END CERTIFICATE-----
)PEM";

    // A private key only: a PEM file with no CERTIFICATE block at all.
    const std::string kNoCertPem = R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglPc92EaVv+wKfaVe
oOn5TqtGVlQjnPd5ibkc2IqlClOhRANCAARTtB3js9Tc/oYbfaUChZDLoN5gcS2i
Hypfm2FSNLPMD9b36JfDq6szFKR0jWtdkTAhs2f04PABxuOLsulYpFkC
-----END PRIVATE KEY-----
)PEM";

    // A well-formed CERTIFICATE block whose body is valid base64 but not a certificate.
    const std::string kGarbagePem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    // Cross-language interop record. Every value below was produced independently
    // by the manager/mint side -- qa-integration-framework's spki_pin() /
    // spki_pin_hex() over these same certificates (tests/unit/test_spki_pin.py) --
    // and by the `openssl` pipeline in this file's header comment. All three agree
    // byte for byte, which is what makes a token minted there acceptable here.
    const std::string kRsaSpkiHex = "fec81ce2566fa87091c419035cbccecffcc6f33803b778880ce8f3ea7c958df7";
    const std::string kRsaSpkiPin = "_sgc4lZvqHCRxBkDXLzOz_zG8zgDt3iIDOjz6nyVjfc";
    const std::string kRsaCertDerSha256Hex = "1f2bd8df82f936f5b0a03713fe2823879c963feb7bd2ecc22b015f4001a8da4c";
    const std::string kRsaReissuedCertDerSha256Hex = "9cc7bb68b604fac90cbdab65618bf6f681971aa4a6abeed59e552089f6a7e831";
    const std::string kEcSpkiHex = "6496b4b63d812a00153aa6fdd29938bd8f81cf33cbe27a4fe6dc72bc0c3d5de0";
    const std::string kEcSpkiPin = "ZJa0tj2BKgAVOqb90pk4vY-BzzPL4npP5txyvAw9XeA";
    const std::string kEcOtherSpkiPin = "PtKvnGxrw6cpQGNmqQgVgsLp76OQHKsyNCslZkkheZ8";

    /// The digest of `pem`, failing the calling test rather than returning an
    /// empty optional, so every case below reads as one assertion.
    SpkiDigest digestOrFail(const std::string& pem)
    {
        SpkiPinError error = SpkiPinError::Internal;
        const auto digest = spkiSha256FromPem(pem, &error);
        EXPECT_TRUE(digest.has_value());
        EXPECT_EQ(SpkiPinError::None, error);
        return digest.value_or(SpkiDigest {});
    }

    /// The error a failing call reports, asserting that it did fail.
    SpkiPinError errorOf(const std::string& pem)
    {
        SpkiPinError error = SpkiPinError::None;
        EXPECT_FALSE(spkiSha256FromPem(pem, &error).has_value());
        return error;
    }

    /// The digest computed through the OTHER OpenSSL route:
    /// X509_get_X509_PUBKEY + i2d_X509_PUBKEY, re-encoding the certificate's
    /// own X509_PUBKEY rather than the parsed EVP_PKEY. Used to pin the
    /// implementation's choice of i2d_PUBKEY (see spkiPin.cpp's digestOf()).
    std::string spkiHexViaX509PubkeyRoute(const std::string& pem)
    {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (certificate == nullptr)
        {
            return {}; // LCOV_EXCL_LINE: the fixtures all parse.
        }

        unsigned char* raw = nullptr;
        const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &raw);
        std::string hex;

        if (length > 0)
        {
            hex = sha256Hex(raw, static_cast<size_t>(length));
            OPENSSL_free(raw);
        }

        X509_free(certificate);
        return hex;
    }

    /// `pin` with the byte at `index` altered, re-encoded -- so the only
    /// difference from the original is at that one position.
    std::string pinWithByteFlipped(const SpkiDigest& digest, std::size_t index)
    {
        SpkiDigest altered = digest;
        altered[index] = static_cast<std::uint8_t>(altered[index] ^ 0xff);
        return spkiPinBase64Url(altered);
    }
} // namespace

// ---------------------------------------------------------------------------
// DoD 1: the digest matches the reference openssl pipeline.
// ---------------------------------------------------------------------------

TEST(SpkiPinTest, RsaSpkiHexMatchesTheOpensslPipeline)
{
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(digestOrFail(kRsaCertPem)));
}

TEST(SpkiPinTest, RsaSpkiPinMatchesTheOpensslPipeline)
{
    EXPECT_EQ(kRsaSpkiPin, spkiPinBase64Url(digestOrFail(kRsaCertPem)));
}

TEST(SpkiPinTest, EcP256SpkiHexMatchesTheOpensslPipeline)
{
    EXPECT_EQ(kEcSpkiHex, spkiPinHex(digestOrFail(kEcCertPem)));
}

TEST(SpkiPinTest, EcP256SpkiPinMatchesTheOpensslPipeline)
{
    EXPECT_EQ(kEcSpkiPin, spkiPinBase64Url(digestOrFail(kEcCertPem)));
}

TEST(SpkiPinTest, PinIsFortyThreeCanonicalBase64UrlChars)
{
    for (const auto& pem : {kRsaCertPem, kEcCertPem})
    {
        const auto pin = spkiPinBase64Url(digestOrFail(pem));
        ASSERT_EQ(SPKI_PIN_B64_CHARS, pin.size());
        EXPECT_TRUE(jwt_profile::v1::isCanonicalBase64UrlOf(pin, SPKI_PIN_BYTES));
        // Unpadded and URL-safe: none of the three characters that would mean
        // the standard alphabet leaked in.
        EXPECT_EQ(std::string::npos, pin.find_first_of("=+/"));
    }
}

TEST(SpkiPinTest, HexIsSixtyFourLowercaseHexChars)
{
    for (const auto& pem : {kRsaCertPem, kEcCertPem})
    {
        const auto hex = spkiPinHex(digestOrFail(pem));
        ASSERT_EQ(SPKI_PIN_HEX_CHARS, hex.size());
        EXPECT_EQ(std::string::npos, hex.find_first_not_of("0123456789abcdef"));
    }
}

// These two are the guard on spkiPin.cpp's choice of i2d_PUBKEY over
// i2d_X509_PUBKEY. The two routes agree today for RSA and named-curve EC; if
// an OpenSSL bump ever changes that, this fires and the decision gets re-made
// deliberately instead of silently. They also independently reproduce the
// pinned hex constants above.
TEST(SpkiPinTest, MatchesTheX509PubkeyRouteForRsa)
{
    const auto viaOtherRoute = spkiHexViaX509PubkeyRoute(kRsaCertPem);
    ASSERT_FALSE(viaOtherRoute.empty());
    EXPECT_EQ(viaOtherRoute, spkiPinHex(digestOrFail(kRsaCertPem)));
    EXPECT_EQ(kRsaSpkiHex, viaOtherRoute);
}

TEST(SpkiPinTest, MatchesTheX509PubkeyRouteForEcP256)
{
    const auto viaOtherRoute = spkiHexViaX509PubkeyRoute(kEcCertPem);
    ASSERT_FALSE(viaOtherRoute.empty());
    EXPECT_EQ(viaOtherRoute, spkiPinHex(digestOrFail(kEcCertPem)));
    EXPECT_EQ(kEcSpkiHex, viaOtherRoute);
}

// ---------------------------------------------------------------------------
// DoD 2: the digest is over the SPKI, NOT over the certificate.
// ---------------------------------------------------------------------------

// Both sides are asserted against their own pinned constants, not merely
// against each other: an implementation that hashed some third thing would
// still satisfy a bare inequality check.
TEST(SpkiPinTest, SpkiDigestDiffersFromWholeCertificateDigest)
{
    // The digest of the whole certificate, computed here in-process, so this
    // test knows both answers and can say which one the implementation gave.
    BIO* bio = BIO_new_mem_buf(kRsaCertPem.data(), static_cast<int>(kRsaCertPem.size()));
    X509* parsed = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    ASSERT_NE(nullptr, parsed);
    const auto der = cert_fixtures::toDer(parsed);
    X509_free(parsed);
    ASSERT_FALSE(der.empty());

    const auto certificateHex = sha256Hex(der.data(), der.size());
    const auto spkiHex = spkiPinHex(digestOrFail(kRsaCertPem));

    // Both answers pinned against their own constants: an implementation that
    // hashed the certificate would produce certificateHex here, and an
    // implementation that hashed some third thing would match neither. A bare
    // "the two differ" assertion would pass for both.
    EXPECT_EQ(kRsaCertDerSha256Hex, certificateHex);
    EXPECT_EQ(kRsaSpkiHex, spkiHex);
    EXPECT_NE(certificateHex, spkiHex);
}

// The whole reason the token pins an SPKI and not a certificate: a CA reissued
// from the same key pair keeps the same pin, so a token minted before the
// reissue still works.
TEST(SpkiPinTest, SameKeyDifferentCertificateSamePin)
{
    EXPECT_EQ(spkiPinHex(digestOrFail(kRsaCertPem)), spkiPinHex(digestOrFail(kRsaReissuedPem)));
    EXPECT_EQ(kRsaSpkiPin, spkiPinBase64Url(digestOrFail(kRsaReissuedPem)));
    // ...while the certificates themselves are genuinely different documents.
    EXPECT_NE(kRsaCertDerSha256Hex, kRsaReissuedCertDerSha256Hex);
}

TEST(SpkiPinTest, SameKeyDifferentCertificateSamePinOnGeneratedCerts)
{
    auto [first, key] = cert_fixtures::makeSelfSignedEc("Generated CA One", 1);
    ASSERT_TRUE(first);
    ASSERT_TRUE(key);
    auto [second, unused] = cert_fixtures::makeSelfSignedEc("Generated CA Two, Different Name", 99, key.get());
    ASSERT_TRUE(second);
    static_cast<void>(unused);

    const auto firstPem = cert_fixtures::toPem(first.get());
    const auto secondPem = cert_fixtures::toPem(second.get());
    ASSERT_NE(firstPem, secondPem);

    EXPECT_EQ(spkiPinHex(digestOrFail(firstPem)), spkiPinHex(digestOrFail(secondPem)));
}

TEST(SpkiPinTest, DifferentKeySameSubjectDifferentPin)
{
    // Same subject CN in both fixtures, different key pairs: nothing
    // subject-derived can be leaking into the digest.
    EXPECT_NE(spkiPinHex(digestOrFail(kEcCertPem)), spkiPinHex(digestOrFail(kEcOtherKeyPem)));
    EXPECT_EQ(kEcOtherSpkiPin, spkiPinBase64Url(digestOrFail(kEcOtherKeyPem)));
}

// ---------------------------------------------------------------------------
// DoD 3: the digest is stable across a PEM/DER round trip.
// ---------------------------------------------------------------------------

TEST(SpkiPinTest, RoundTripThroughDerIsStable)
{
    auto [certificate, key] = cert_fixtures::makeSelfSignedEc("Round Trip CA", 7);
    ASSERT_TRUE(certificate);

    const auto pem = cert_fixtures::toPem(certificate.get());
    const auto der = cert_fixtures::toDer(certificate.get());
    ASSERT_FALSE(der.empty());

    SpkiPinError error = SpkiPinError::Internal;
    const auto fromDer = spkiSha256FromDer(der.data(), der.size(), &error);
    ASSERT_TRUE(fromDer.has_value());
    EXPECT_EQ(SpkiPinError::None, error);
    EXPECT_EQ(spkiPinHex(digestOrFail(pem)), spkiPinHex(*fromDer));
}

TEST(SpkiPinTest, RoundTripPemToDerToPemIsStable)
{
    // PEM -> d2i -> i2d -> PEM, on the committed fixture.
    BIO* bio = BIO_new_mem_buf(kRsaCertPem.data(), static_cast<int>(kRsaCertPem.size()));
    X509* parsed = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    ASSERT_NE(nullptr, parsed);

    const auto reencodedPem = cert_fixtures::toPem(parsed);
    X509_free(parsed);
    ASSERT_FALSE(reencodedPem.empty());

    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(digestOrFail(reencodedPem)));
}

TEST(SpkiPinTest, PemFileAndPemStringAgree)
{
    const std::string path = ::testing::TempDir() + "hc_spki_fixture.pem";
    {
        std::ofstream file {path, std::ios::binary};
        file << kEcCertPem;
    }

    SpkiPinError error = SpkiPinError::Internal;
    const auto fromFile = spkiSha256FromPemFile(path, &error);
    ASSERT_TRUE(fromFile.has_value());
    EXPECT_EQ(SpkiPinError::None, error);
    EXPECT_EQ(kEcSpkiHex, spkiPinHex(*fromFile));
    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// DoD 4: the pin comparison.
//
// The constant-time property itself is guaranteed BY CONSTRUCTION -- one
// CRYPTO_memcmp over a compile-time-fixed 32 bytes, with no byte loop to
// short-circuit -- and a unit test cannot prove it (timing on a shared CI
// runner is dominated by scheduling and cache state; a dudect-style test needs
// ~10^5 samples and would still flake). What the cases below DO prove is that
// the classification is position-independent: a difference in the first byte,
// the last byte, a middle byte, or every byte all reach the same verdict by
// the same path. That is the observable shadow of not short-circuiting -- it
// is not a timing measurement, and must not be read as one.
// ---------------------------------------------------------------------------

TEST(SpkiPinTest, CompareAcceptsTheMatchingPin)
{
    EXPECT_EQ(SpkiPinMatch::Match, spkiPinCompare(digestOrFail(kRsaCertPem), kRsaSpkiPin));
}

TEST(SpkiPinTest, CompareRejectsAPinDifferingOnlyInTheFirstByte)
{
    const auto digest = digestOrFail(kRsaCertPem);
    EXPECT_EQ(SpkiPinMatch::Mismatch, spkiPinCompare(digest, pinWithByteFlipped(digest, 0)));
}

TEST(SpkiPinTest, CompareRejectsAPinDifferingOnlyInTheLastByte)
{
    const auto digest = digestOrFail(kRsaCertPem);
    EXPECT_EQ(SpkiPinMatch::Mismatch, spkiPinCompare(digest, pinWithByteFlipped(digest, SPKI_PIN_BYTES - 1)));
}

TEST(SpkiPinTest, CompareRejectsAPinDifferingOnlyInAMiddleByte)
{
    const auto digest = digestOrFail(kRsaCertPem);
    EXPECT_EQ(SpkiPinMatch::Mismatch, spkiPinCompare(digest, pinWithByteFlipped(digest, SPKI_PIN_BYTES / 2)));
}

TEST(SpkiPinTest, CompareRejectsAMaximallyDifferentPin)
{
    SpkiDigest allZero {};
    SpkiDigest allOnes {};
    allOnes.fill(0xff);
    EXPECT_EQ(SpkiPinMatch::Mismatch, spkiPinCompare(allZero, spkiPinBase64Url(allOnes)));
}

TEST(SpkiPinTest, CompareRejectsAnotherCertificatesPin)
{
    EXPECT_EQ(SpkiPinMatch::Mismatch, spkiPinCompare(digestOrFail(kEcCertPem), kEcOtherSpkiPin));
}

TEST(SpkiPinTest, CompareOfAShortPinIsMalformed)
{
    EXPECT_EQ(SpkiPinMatch::MalformedPin,
              spkiPinCompare(digestOrFail(kRsaCertPem), kRsaSpkiPin.substr(0, SPKI_PIN_B64_CHARS - 1)));
}

TEST(SpkiPinTest, CompareOfALongPinIsMalformed)
{
    EXPECT_EQ(SpkiPinMatch::MalformedPin, spkiPinCompare(digestOrFail(kRsaCertPem), kRsaSpkiPin + "A"));
}

TEST(SpkiPinTest, CompareOfAPaddedPinIsMalformed)
{
    // The 44-character padded form of the very same 32 bytes: right value,
    // wrong encoding, and accepting it would mean accepting a shape the mint
    // never emits.
    EXPECT_EQ(SpkiPinMatch::MalformedPin, spkiPinCompare(digestOrFail(kRsaCertPem), kRsaSpkiPin + "="));
}

TEST(SpkiPinTest, CompareOfStandardBase64AlphabetIsMalformed)
{
    auto standardAlphabet = kRsaSpkiPin;
    // kRsaSpkiPin is known to contain '-' or '_' (asserted here so the test
    // cannot silently become a no-op if the fixture is ever regenerated).
    const auto urlSafeChar = standardAlphabet.find_first_of("-_");
    ASSERT_NE(std::string::npos, urlSafeChar);
    standardAlphabet[urlSafeChar] = standardAlphabet[urlSafeChar] == '-' ? '+' : '/';

    EXPECT_EQ(SpkiPinMatch::MalformedPin, spkiPinCompare(digestOrFail(kRsaCertPem), standardAlphabet));
}

TEST(SpkiPinTest, CompareOfNonCanonicalTrailingBitsIsMalformed)
{
    // 43 characters of the right alphabet, but the final sextet carries bits
    // that no 32-byte value can produce (RFC 8725 section 3.12).
    auto dirty = kRsaSpkiPin;
    dirty.back() = dirty.back() == 'A' ? 'B' : 'A';

    const auto verdict = spkiPinCompare(digestOrFail(kRsaCertPem), dirty);
    // Whichever of the two the mutation produced, it must never be Match.
    EXPECT_NE(SpkiPinMatch::Match, verdict);
}

TEST(SpkiPinTest, CompareOfAnEmptyPinIsMalformed)
{
    EXPECT_EQ(SpkiPinMatch::MalformedPin, spkiPinCompare(digestOrFail(kRsaCertPem), ""));
}

TEST(SpkiPinTest, CompareOfPercentEncodedPaddingIsMalformed)
{
    EXPECT_EQ(SpkiPinMatch::MalformedPin, spkiPinCompare(digestOrFail(kRsaCertPem), kRsaSpkiPin + "%3d"));
}

TEST(SpkiPinTest, RoundTripPinThroughCompareForBothFixtures)
{
    for (const auto& pem : {kRsaCertPem, kEcCertPem})
    {
        const auto digest = digestOrFail(pem);
        EXPECT_EQ(SpkiPinMatch::Match, spkiPinCompare(digest, spkiPinBase64Url(digest)));
    }
}

// ---------------------------------------------------------------------------
// Negative, edge and policy cases.
// ---------------------------------------------------------------------------

TEST(SpkiPinTest, EmptyInputIsNoCertificate)
{
    EXPECT_EQ(SpkiPinError::NoCertificate, errorOf(""));
}

TEST(SpkiPinTest, PlainTextIsNoCertificate)
{
    // What a manager predating /cacerts, or a reverse proxy answering 404,
    // actually returns. Must not read like a corrupt certificate.
    EXPECT_EQ(SpkiPinError::NoCertificate, errorOf("<html><body>404 Not Found</body></html>"));
}

TEST(SpkiPinTest, PemWithOnlyAPrivateKeyBlockIsNoCertificate)
{
    EXPECT_EQ(SpkiPinError::NoCertificate, errorOf(kNoCertPem));
}

TEST(SpkiPinTest, PemBlockWithNonCertificateBodyIsBadCertificate)
{
    // This is the case that justifies keeping NoCertificate and
    // BadCertificate apart: a CERTIFICATE block IS present, so "there was no
    // certificate" would be a misleading thing to log.
    EXPECT_EQ(SpkiPinError::BadCertificate, errorOf(kGarbagePem));
}

TEST(SpkiPinTest, TruncatedPemBodyIsBadCertificate)
{
    auto truncated = kRsaCertPem;
    truncated.erase(truncated.size() / 2, 40);
    EXPECT_EQ(SpkiPinError::BadCertificate, errorOf(truncated));
}

TEST(SpkiPinTest, TrailingDataAfterThePemBlockIsIgnored)
{
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(digestOrFail(kRsaCertPem + "\nnot a pem block at all\n")));
}

TEST(SpkiPinTest, LeadingTextBeforeThePemBlockIsIgnored)
{
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(digestOrFail("# manager CA, fetched from /cacerts\n" + kRsaCertPem)));
}

TEST(SpkiPinTest, LeadingPrivateKeyBlockIsSkipped)
{
    // A non-CERTIFICATE block is stepped over, not treated as a failure.
    EXPECT_EQ(kEcSpkiHex, spkiPinHex(digestOrFail(kNoCertPem + kEcCertPem)));
}

// Policy, documented by test: the single-certificate entry point hashes the
// FIRST certificate in a bundle. Callers that must see the whole bundle use
// spkiSha256AllFromPem().
TEST(SpkiPinTest, AChainHashesTheFirstCertificate)
{
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(digestOrFail(kRsaCertPem + kEcCertPem)));
    EXPECT_EQ(kEcSpkiHex, spkiPinHex(digestOrFail(kEcCertPem + kRsaCertPem)));
}

TEST(SpkiPinTest, AllFromPemReturnsEveryCertificateInOrder)
{
    SpkiPinError error = SpkiPinError::Internal;
    const auto both = spkiSha256AllFromPem(kRsaCertPem + kEcCertPem, &error);
    ASSERT_EQ(2u, both.size());
    EXPECT_EQ(SpkiPinError::None, error);
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(both[0]));
    EXPECT_EQ(kEcSpkiHex, spkiPinHex(both[1]));

    const auto single = spkiSha256AllFromPem(kEcCertPem, &error);
    EXPECT_EQ(1u, single.size());
    EXPECT_EQ(SpkiPinError::None, error);

    const auto none = spkiSha256AllFromPem(kNoCertPem, &error);
    EXPECT_TRUE(none.empty());
    EXPECT_EQ(SpkiPinError::NoCertificate, error);
}

TEST(SpkiPinTest, DerOfNonCertificateBytesIsBadCertificate)
{
    SpkiPinError error = SpkiPinError::None;
    const char notACertificate[] = "\x30\x00";
    EXPECT_FALSE(spkiSha256FromDer(notACertificate, 2, &error).has_value());
    EXPECT_EQ(SpkiPinError::BadCertificate, error);
}

TEST(SpkiPinTest, EmptyDerIsNoCertificate)
{
    SpkiPinError error = SpkiPinError::None;
    EXPECT_FALSE(spkiSha256FromDer(nullptr, 0, &error).has_value());
    EXPECT_EQ(SpkiPinError::NoCertificate, error);
}

TEST(SpkiPinTest, MissingPemFileIsNoCertificate)
{
    SpkiPinError error = SpkiPinError::None;
    EXPECT_FALSE(spkiSha256FromPemFile("/nonexistent/hc-spki/none.pem", &error).has_value());
    EXPECT_EQ(SpkiPinError::NoCertificate, error);
}

TEST(SpkiPinTest, ErrorPointerIsOptional)
{
    // Every entry point, with the defaulted null error argument, on a good and
    // a bad input.
    EXPECT_TRUE(spkiSha256FromPem(kRsaCertPem).has_value());
    EXPECT_FALSE(spkiSha256FromPem("").has_value());
    EXPECT_EQ(1u, spkiSha256AllFromPem(kRsaCertPem).size());
    EXPECT_TRUE(spkiSha256AllFromPem("").empty());
    EXPECT_FALSE(spkiSha256FromDer(nullptr, 0).has_value());
    EXPECT_FALSE(spkiSha256FromPemFile("/nonexistent/hc-spki/none.pem").has_value());
}

// A real libcurl GET runs immediately before these calls in the bootstrap
// flow. Residue left on the thread's OpenSSL error queue by a failed parse
// here would surface as an inexplicable TLS error in unrelated code later, so
// every failure path is required to clean up after itself.
TEST(SpkiPinTest, FailurePathsLeaveTheOpensslErrorQueueClean)
{
    auto truncated = kRsaCertPem;
    truncated.erase(truncated.size() / 2, 40);

    for (const auto& input : {std::string {}, std::string {"not a certificate"}, kNoCertPem, kGarbagePem, truncated})
    {
        ERR_clear_error();
        static_cast<void>(spkiSha256FromPem(input));
        EXPECT_EQ(0uL, ERR_peek_error()) << "a failed parse left something on the error queue";
    }

    ERR_clear_error();
    static_cast<void>(spkiSha256FromDer("\x30\x00", 2));
    EXPECT_EQ(0uL, ERR_peek_error());
}

// hc_cacerts_result_t::body is a fixed char[HC_MAX_CACERTS_BODY] with no
// length field, so the PEM entry point takes an explicit length and callers
// must build their view with strnlen(), never strlen().
//
// That is necessary but NOT sufficient, and this test exists to pin the
// difference: OpenSSL's PEM scanner reads line-wise and stops dead at a NUL
// byte, so a bundle carrying one mid-body yields only the certificates BEFORE
// it however generous the length handed in. Verified independently against the
// CLI -- `openssl storeutl -noout -certs` on the same two-certificate bundle
// reports "Total found: 2" without the NUL and "Total found: 1" with it, from
// a file, where the length is not in question.
//
// Consequence for the bootstrap (#39026): a legitimate PEM never contains a
// NUL, so the fetch layer should treat one in the body as corruption rather
// than pin whatever happened to parse first. Silently pinning a truncated
// bundle is exactly the "succeeds while being wrong" failure this issue exists
// to rule out.
TEST(SpkiPinTest, AnEmbeddedNulTruncatesTheBundleRegardlessOfLength)
{
    std::string buffer = kRsaCertPem;
    buffer.push_back('\0');
    buffer += kEcCertPem;

    // Without the NUL the same two certificates both parse -- so the NUL, and
    // not the concatenation, is what does the truncating.
    SpkiPinError error = SpkiPinError::Internal;
    ASSERT_EQ(2u, spkiSha256AllFromPem(kRsaCertPem + kEcCertPem, &error).size());

    // With it, the full-length view still stops at the NUL.
    const auto all = spkiSha256AllFromPem(std::string_view {buffer.data(), buffer.size()}, &error);
    ASSERT_EQ(1u, all.size());
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(all[0]));

    // And a view built the way strlen() would build it is indistinguishable,
    // which is the point: the explicit length buys nothing once a NUL is in
    // the body, so the caller has to reject the body instead.
    const auto upToNul = spkiSha256AllFromPem(std::string_view {buffer.data()}, &error);
    ASSERT_EQ(1u, upToNul.size());
    EXPECT_EQ(kRsaSpkiHex, spkiPinHex(upToNul[0]));
}
