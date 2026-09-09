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

#ifndef _HC_CERT_FIXTURES_HPP
#define _HC_CERT_FIXTURES_HPP

/*
 * Certificates generated in-process, for the two spkiPin properties that must
 * hold for keys nobody hand-picked: an SPKI digest is stable across a DER
 * round trip, and two certificates sharing a key pair share a pin. Everything
 * else in spkiPin_test.cpp runs against committed PEM literals, which is what
 * the issue asks for ("a fixed certificate") and what a reviewer can
 * reproduce with three openssl commands.
 *
 * Deliberately NOT shared with tests/component/tlsVerification_component_test.cpp's
 * makeSelfSigned(): that one belongs to a different test binary's glob and
 * bakes in RSA-2048 plus SAN IP:127.0.0.1 for TLS-handshake reasons that are
 * noise here. EVP_EC_gen("P-256") also costs milliseconds where EVP_RSA_gen(2048)
 * is a 50 ms - 2 s dice roll on a loaded CI box.
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <string>

namespace cert_fixtures
{
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    /// Adds one X509v3 extension by NID, ignoring a value OpenSSL rejects
    /// (the caller's fixtures are fixed strings, so that cannot happen here).
    inline void addExtension(X509* certificate, int nid, const char* value)
    {
        X509V3_CTX context;
        X509V3_set_ctx_nodb(&context);
        X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &context, nid, value);

        if (extension != nullptr)
        {
            X509_add_ext(certificate, extension, -1);
            X509_EXTENSION_free(extension);
        }
    }

    /// A self-signed EC P-256 CA certificate.
    ///
    /// @param subjectCn CN to put in the subject (and, self-signed, the issuer).
    /// @param serial Serial number, so two certificates from one key differ.
    /// @param reuseKey When non-null, this key is used instead of a fresh one --
    ///        which is how the "same key, different certificate, same pin"
    ///        property gets its second certificate.
    /// @return The certificate and the key that signed it. Null on failure.
    inline std::pair<X509Ptr, EvpPkeyPtr> makeSelfSignedEc(const char* subjectCn, long serial,
                                                           EVP_PKEY* reuseKey = nullptr)
    {
        EvpPkeyPtr key {reuseKey != nullptr ? nullptr : EVP_EC_gen("P-256"), EVP_PKEY_free};
        EVP_PKEY* signing = reuseKey != nullptr ? reuseKey : key.get();

        if (signing == nullptr)
        {
            return {X509Ptr {nullptr, X509_free}, std::move(key)}; // LCOV_EXCL_LINE: keygen does not fail here.
        }

        X509Ptr certificate {X509_new(), X509_free};
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial);
        X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(certificate.get()), 60L * 60L);
        X509_set_pubkey(certificate.get(), signing);

        X509_NAME* name = X509_get_subject_name(certificate.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(subjectCn), -1,
                                   -1, 0);
        X509_set_issuer_name(certificate.get(), name);
        addExtension(certificate.get(), NID_basic_constraints, "critical,CA:TRUE");
        X509_sign(certificate.get(), signing, EVP_sha256());

        return {std::move(certificate), std::move(key)};
    }

    /// PEM-encodes a certificate through a memory BIO (no temp file).
    inline std::string toPem(X509* certificate)
    {
        const BioPtr bio {BIO_new(BIO_s_mem()), BIO_free};

        if (!bio || PEM_write_bio_X509(bio.get(), certificate) != 1)
        {
            return {}; // LCOV_EXCL_LINE: not reproducible for a well-formed certificate.
        }

        char* data = nullptr;
        const long length = BIO_get_mem_data(bio.get(), &data);
        return std::string(data, static_cast<std::size_t>(length));
    }

    /// DER-encodes a certificate. Backs the PEM/DER round-trip property.
    inline std::string toDer(X509* certificate)
    {
        unsigned char* raw = nullptr;
        const int length = i2d_X509(certificate, &raw);

        if (length <= 0)
        {
            return {}; // LCOV_EXCL_LINE: not reproducible for a well-formed certificate.
        }

        std::string der(reinterpret_cast<const char*>(raw), static_cast<std::size_t>(length));
        OPENSSL_free(raw);
        return der;
    }
} // namespace cert_fixtures

#endif // _HC_CERT_FIXTURES_HPP
