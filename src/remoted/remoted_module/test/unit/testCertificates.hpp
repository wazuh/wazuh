/*
 * Wazuh remoted module (C++ worker bridge) - shared test certificate builders
 * Copyright (C) 2015, Wazuh Inc.
 * September 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_TEST_CERTIFICATES_HPP
#define _REMOTED_MODULE_TEST_CERTIFICATES_HPP

// In-memory X.509 builders shared by every test file that needs a throwaway PKI without an
// `openssl` CLI round trip (extracted from httpServer_test.cpp when caCertificateSource_test.cpp
// and the chainValidates() coverage in httpServer_test.cpp both needed the same certificates).
//
// scratchPath() and readPemCertificates() stay local to httpServer_test.cpp: they are thin wrappers
// around a single test file's own scratch-file convention, not certificate construction.

#include "http_server/tlsCertificateStatus.hpp"

#include <gtest/gtest.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace remoted::test
{
    // X509Ptr belongs to remoted::http (tlsCertificateStatus.hpp); re-exported here (not a new
    // type: a using-declaration, so it is never ambiguous against `using namespace remoted::http;`
    // in a file that has both) so certificates built here feed the status functions directly.
    using remoted::http::X509Ptr;

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
     *        @p issuer (null = self-signed). An optional comma-separated subjectAltName (e.g.
     *        "IP:203.0.113.5") for the peer-address tests, and an optional CA shape (basicConstraints
     *        CA:TRUE + keyUsage keyCertSign/cRLSign) for the chainValidates() tests -- a certificate
     *        with no CA extensions at all is not a trust anchor X509_V_FLAG_PARTIAL_CHAIN or a
     *        purpose check will accept past depth 0. No socket, TLS handshake or on-disk fixture
     *        required.
     */
    inline X509Ptr makeCertificate(const char* commonName,
                                   long notBeforeSeconds,
                                   long notAfterSeconds,
                                   EVP_PKEY* subjectKey,
                                   EVP_PKEY* signerKey,
                                   const X509* issuer,
                                   const char* subjectAltName = nullptr,
                                   bool isCa = false)
    {
        X509Ptr certificate {X509_new()};
        if (!certificate)
        {
            throw std::runtime_error("Failed to allocate test X509 certificate");
        }

        X509_set_version(certificate.get(), 2); // X509v3
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1);
        X509_gmtime_adj(X509_get_notBefore(certificate.get()), notBeforeSeconds);
        X509_gmtime_adj(X509_get_notAfter(certificate.get()), notAfterSeconds);

        X509_NAME* name = X509_get_subject_name(certificate.get());
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
        X509_set_issuer_name(certificate.get(), issuer != nullptr ? X509_get_subject_name(issuer) : name);

        X509_set_pubkey(certificate.get(), subjectKey);

        if (subjectAltName != nullptr || isCa)
        {
            X509V3_CTX ctx;
            X509V3_set_ctx_nodb(&ctx);
            X509V3_set_ctx(&ctx, certificate.get(), certificate.get(), nullptr, nullptr, 0);

            if (subjectAltName != nullptr)
            {
                X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, subjectAltName);
                if (extension == nullptr)
                {
                    throw std::runtime_error("Failed to build test subjectAltName extension");
                }
                X509_add_ext(certificate.get(), extension, -1);
                X509_EXTENSION_free(extension);
            }

            if (isCa)
            {
                // Same X509V3_EXT_conf_nid() pattern as the SAN extension above. Both extensions
                // matter to chainValidates(): X509_V_FLAG_PARTIAL_CHAIN still runs the ordinary CA
                // checks on every non-leaf certificate of the path, and its purpose is
                // X509_PURPOSE_SSL_SERVER, which requires keyCertSign on the signer.
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
        }

        if (X509_sign(certificate.get(), signerKey, EVP_sha256()) == 0)
        {
            throw std::runtime_error("Failed to sign test certificate");
        }

        return certificate;
    }

    /// Writes certificates to a PEM file (in order), for the CA-file side of the status functions.
    inline void writePemFile(const std::string& path, const std::vector<const X509*>& certificates)
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new_file(path.c_str(), "w"), &BIO_free};
        ASSERT_TRUE(bio) << "cannot create " << path;
        for (const auto* certificate : certificates)
        {
            ASSERT_EQ(PEM_write_bio_X509(bio.get(), const_cast<X509*>(certificate)), 1);
        }
    }

    /// Writes an unencrypted private key to a PEM file, so a test can start a real server from a
    /// PKI built entirely in memory -- no `openssl` CLI dependency -- when a certificate shape the
    /// CLI recipes cannot produce is needed (e.g. a signer without CA:TRUE that `x509 -req` refuses).
    inline bool writePemKey(const std::string& path, EVP_PKEY* key)
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio {BIO_new_file(path.c_str(), "w"), &BIO_free};
        if (!bio)
        {
            return false;
        }
        return PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    }

} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_CERTIFICATES_HPP
