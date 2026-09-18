/*
 * Wazuh CA bundle library - test certificate builders
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CA_BUNDLE_TEST_PKI_HPP
#define _CA_BUNDLE_TEST_PKI_HPP

// In-memory X.509 builders, so the bundle functions can be exercised over a throwaway PKI with no
// `openssl` CLI round trip and no on-disk fixture. A bounded COPY of remoted_module's
// test/unit/testCertificates.hpp (a shared module never includes another module's test headers,
// and no other shared module does): the subjectAltName shapes and the private-key writer that
// file carries for the listener tests have no question to answer here.

#include "ca_bundle/ca_bundle.hpp"

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace ca_bundle::test
{
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

    inline EvpPkeyPtr makeTestKey()
    {
        EvpPkeyPtr pkey {EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), &EVP_PKEY_free};
        if (!pkey)
        {
            throw std::runtime_error("Failed to generate test EC key pair");
        }
        return pkey;
    }

    /**
     * @brief Builds a minimal X509v3 certificate in memory: CN @p commonName, valid from
     *        @p notBeforeSeconds to @p notAfterSeconds relative to now (either may be negative, for
     *        an expired one), public key @p subjectKey, signed with @p signerKey and naming
     *        @p issuer (null = self-signed), with an optional CA shape (basicConstraints CA:TRUE +
     *        keyUsage keyCertSign/cRLSign) and an optional @p serial so two otherwise identical
     *        certificates differ in their DER encoding.
     */
    inline X509Ptr makeCertificate(const char* commonName,
                                   long notBeforeSeconds,
                                   long notAfterSeconds,
                                   EVP_PKEY* subjectKey,
                                   EVP_PKEY* signerKey,
                                   const X509* issuer,
                                   bool isCa = false,
                                   long serial = 1)
    {
        X509Ptr certificate {X509_new()};
        if (!certificate)
        {
            throw std::runtime_error("Failed to allocate test X509 certificate");
        }

        X509_set_version(certificate.get(), 2); // X509v3
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial);
        X509_gmtime_adj(X509_get_notBefore(certificate.get()), notBeforeSeconds);
        X509_gmtime_adj(X509_get_notAfter(certificate.get()), notAfterSeconds);

        X509_NAME* name = X509_get_subject_name(certificate.get());
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
        X509_set_issuer_name(certificate.get(), issuer != nullptr ? X509_get_subject_name(issuer) : name);

        X509_set_pubkey(certificate.get(), subjectKey);

        if (isCa)
        {
            X509V3_CTX ctx;
            X509V3_set_ctx_nodb(&ctx);
            X509V3_set_ctx(&ctx, certificate.get(), certificate.get(), nullptr, nullptr, 0);

            // Both extensions matter to a real verifier of the published bundle (`openssl verify`,
            // Python's ssl): a certificate with no CA extensions at all is not a trust anchor any
            // of them will accept past depth 0.
            X509_EXTENSION* basicConstraints =
                X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE");
            if (basicConstraints == nullptr)
            {
                throw std::runtime_error("Failed to build test basicConstraints extension");
            }
            X509_add_ext(certificate.get(), basicConstraints, -1);
            X509_EXTENSION_free(basicConstraints);

            X509_EXTENSION* keyUsage =
                X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
            if (keyUsage == nullptr)
            {
                throw std::runtime_error("Failed to build test keyUsage extension");
            }
            X509_add_ext(certificate.get(), keyUsage, -1);
            X509_EXTENSION_free(keyUsage);
        }

        if (X509_sign(certificate.get(), signerKey, EVP_sha256()) == 0)
        {
            throw std::runtime_error("Failed to sign test certificate");
        }

        return certificate;
    }

    /**
     * @brief Rewrites @p certificate's notBefore to the exact @p absoluteEpochSeconds -- which may
     *        be negative, for a calendar date before 1970 -- and re-signs it with @p signerKey.
     *
     * `makeCertificate()`'s notBefore/notAfter are offsets from "now" (`X509_gmtime_adj()`), which
     * cannot reach an exact fixed date independent of when the test runs. `ASN1_TIME_set()` sets
     * the field directly, no offset involved, so a test that needs to pin a specific pre-1970
     * calendar date (describe()'s date conversion, not "is expired") uses this instead. Signing has
     * to happen again afterwards: it hashes the certificate's current fields.
     */
    inline void setAbsoluteNotBeforeAndResign(X509* certificate, std::time_t absoluteEpochSeconds, EVP_PKEY* signerKey)
    {
        if (ASN1_TIME_set(X509_getm_notBefore(certificate), absoluteEpochSeconds) == nullptr)
        {
            throw std::runtime_error("Failed to set an absolute notBefore on a test certificate");
        }
        if (X509_sign(certificate, signerKey, EVP_sha256()) == 0)
        {
            throw std::runtime_error("Failed to re-sign a test certificate after setting an absolute notBefore");
        }
    }

    /// A reference of our own on @p certificate, so the same one can sit in two vectors at once.
    inline X509Ptr retain(const X509* certificate)
    {
        if (certificate == nullptr || X509_up_ref(const_cast<X509*>(certificate)) != 1)
        {
            return {};
        }
        return X509Ptr {const_cast<X509*>(certificate)};
    }

    /// Writes certificates to a PEM file (in order), for the tests that hand one to another tool.
    inline void writePemFile(const std::string& path, const std::vector<const X509*>& certificates)
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new_file(path.c_str(), "w"), &BIO_free};
        ASSERT_TRUE(bio) << "cannot create " << path;
        for (const auto* certificate : certificates)
        {
            ASSERT_EQ(PEM_write_bio_X509(bio.get(), const_cast<X509*>(certificate)), 1);
        }
    }

} // namespace ca_bundle::test

#endif // _CA_BUNDLE_TEST_PKI_HPP
