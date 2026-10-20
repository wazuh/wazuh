/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TESTS_TLS_MATERIAL_FACTORY_HPP
#define _INDEXER_CLIENT_TESTS_TLS_MATERIAL_FACTORY_HPP

// Only the component suite compiles TLS (it defines CPPHTTPLIB_OPENSSL_SUPPORT and reaches OpenSSL through wazuhext);
// in any other translation unit this header is empty.
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace indexer_client::testing
{
    /**
     * @brief Generates, with OpenSSL's EVP/X509 API (never the `openssl` binary), every TLS file the suites need.
     *
     * Everything is written at construction into a private temporary directory that the destructor removes; every
     * accessor returns an absolute path. Keys are EC P-256 (fast to generate); certificates are SHA-256 signed, valid
     * from one hour ago for 30 days, with subject/authority key identifiers.
     *
     * Files:
     * - caCertificate(): good root CA (self-signed, CA:TRUE).
     * - otherCaCertificate(): a second, unrelated root CA.
     * - caBundleOtherThenGood(): otherCaCertificate() followed by caCertificate(), in one file.
     * - caThenMalformed(): caCertificate() followed by malformedCa()'s block, in one file.
     * - largeCaBundle(): caCertificate() repeated up to just under 1 MiB (valid; 8 of them exceed curl's blob limit).
     * - oversizedCa(): caCertificate() padded with blank lines to 1 MiB + 1 byte.
     * - serverCertificate() / serverKey(): server pair signed by the good CA, SAN `IP:127.0.0.1`, EKU serverAuth.
     * - wrongNameServerCertificate() / wrongNameServerKey(): server pair signed by the good CA, SAN `DNS:` wrongName()
     *   only.
     * - clientCertificate() / clientKey(): client pair signed by the good CA, EKU clientAuth.
     * - intermediateCaCertificate(): intermediate CA signed by the good CA.
     * - chainCertificate() / chainKey(): client leaf signed by the intermediate, followed by the intermediate, in one
     *   file.
     * - chainThenMalformed(): chainCertificate() followed by malformedCa()'s block, in one file (key: chainKey()).
     * - encryptedClientKey(): clientKey()'s key as an AES-256-CBC encrypted PEM, passphrase().
     * - otherKey(): the key of no generated certificate (mismatches every certificate).
     * - malformedCa(): a CERTIFICATE PEM block whose body is not base64 DER.
     * - emptyFile(): zero bytes.
     * - keyOnlyPem(): a PEM with a private key and no certificate.
     */
    class TlsMaterialFactory final
    {
    public:
        TlsMaterialFactory()
        {
            std::string pattern = (std::filesystem::temp_directory_path() / "indexer_client_tls_XXXXXX").string();
            std::vector<char> buffer(pattern.begin(), pattern.end());
            buffer.push_back('\0');
            if (::mkdtemp(buffer.data()) == nullptr)
            {
                throw std::runtime_error("TlsMaterialFactory: mkdtemp failed");
            }
            m_directory = std::filesystem::absolute(buffer.data()).string();
            try
            {
                generate();
            }
            catch (...)
            {
                removeDirectory();
                throw;
            }
        }

        ~TlsMaterialFactory()
        {
            removeDirectory();
        }

        TlsMaterialFactory(const TlsMaterialFactory&) = delete;
        TlsMaterialFactory& operator=(const TlsMaterialFactory&) = delete;
        TlsMaterialFactory(TlsMaterialFactory&&) = delete;
        TlsMaterialFactory& operator=(TlsMaterialFactory&&) = delete;

        /// The private directory (absolute); removed with everything in it by the destructor.
        const std::string& directory() const
        {
            return m_directory;
        }

        std::string caCertificate() const
        {
            return path("ca.pem");
        }
        std::string otherCaCertificate() const
        {
            return path("other-ca.pem");
        }
        std::string caBundleOtherThenGood() const
        {
            return path("bundle-other-then-good.pem");
        }
        std::string serverCertificate() const
        {
            return path("server.pem");
        }
        std::string serverKey() const
        {
            return path("server-key.pem");
        }
        std::string wrongNameServerCertificate() const
        {
            return path("wrong-name-server.pem");
        }
        std::string wrongNameServerKey() const
        {
            return path("wrong-name-server-key.pem");
        }
        std::string clientCertificate() const
        {
            return path("client.pem");
        }
        std::string clientKey() const
        {
            return path("client-key.pem");
        }
        std::string intermediateCaCertificate() const
        {
            return path("intermediate-ca.pem");
        }
        std::string chainCertificate() const
        {
            return path("chain.pem");
        }
        std::string chainKey() const
        {
            return path("chain-key.pem");
        }
        std::string encryptedClientKey() const
        {
            return path("client-key-encrypted.pem");
        }
        std::string otherKey() const
        {
            return path("other-key.pem");
        }
        std::string caThenMalformed() const
        {
            return path("ca-then-malformed.pem");
        }
        std::string largeCaBundle() const
        {
            return path("large-ca-bundle.pem");
        }
        std::string oversizedCa() const
        {
            return path("oversized-ca.pem");
        }
        std::string chainThenMalformed() const
        {
            return path("chain-then-malformed.pem");
        }
        std::string malformedCa() const
        {
            return path("malformed-ca.pem");
        }
        std::string emptyFile() const
        {
            return path("empty.pem");
        }
        std::string keyOnlyPem() const
        {
            return path("key-only.pem");
        }

        /// Passphrase of encryptedClientKey().
        static std::string passphrase()
        {
            return "fake-passphrase";
        }

        /// The only SAN (DNS) of wrongNameServerCertificate().
        static std::string wrongName()
        {
            return "not-this-host.invalid";
        }

    private:
        using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
        using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

        enum class Kind
        {
            Ca,
            Server,
            Client
        };

        std::string path(const char* name) const
        {
            return (std::filesystem::path(m_directory) / name).string();
        }

        void removeDirectory() noexcept
        {
            if (!m_directory.empty())
            {
                std::error_code ignored;
                std::filesystem::remove_all(m_directory, ignored);
            }
        }

        static void check(bool ok, const char* what)
        {
            if (!ok)
            {
                throw std::runtime_error(std::string("TlsMaterialFactory: ") + what);
            }
        }

        static KeyPtr newKey()
        {
            KeyPtr key(EVP_EC_gen("P-256"), &EVP_PKEY_free);
            check(key != nullptr, "EVP_EC_gen");
            return key;
        }

        static void addExtension(X509* cert, X509V3_CTX* ctx, int nid, const char* value)
        {
            X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
            check(extension != nullptr, "X509V3_EXT_conf_nid");
            const bool added = X509_add_ext(cert, extension, -1) == 1;
            X509_EXTENSION_free(extension);
            check(added, "X509_add_ext");
        }

        /// A certificate for @p key named @p commonName; self-signed when @p issuer is null.
        static CertPtr newCertificate(EVP_PKEY* key,
                                      const std::string& commonName,
                                      Kind kind,
                                      const std::string& subjectAltName,
                                      X509* issuer,
                                      EVP_PKEY* issuerKey)
        {
            CertPtr cert(X509_new(), &X509_free);
            check(cert != nullptr, "X509_new");
            check(X509_set_version(cert.get(), X509_VERSION_3) == 1, "X509_set_version");

            unsigned char serial[16];
            check(RAND_bytes(serial, sizeof(serial)) == 1, "RAND_bytes");
            serial[0] &= 0x7f; // positive
            BIGNUM* number = BN_bin2bn(serial, sizeof(serial), nullptr);
            check(number != nullptr, "BN_bin2bn");
            const bool serialSet = BN_to_ASN1_INTEGER(number, X509_get_serialNumber(cert.get())) != nullptr;
            BN_free(number);
            check(serialSet, "BN_to_ASN1_INTEGER");

            check(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) != nullptr, "notBefore");
            check(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 30L * 24 * 3600) != nullptr, "notAfter");
            check(X509_set_pubkey(cert.get(), key) == 1, "X509_set_pubkey");

            X509_NAME* name = X509_get_subject_name(cert.get());
            check(
                X509_NAME_add_entry_by_txt(
                    name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0) ==
                    1,
                "X509_NAME_add_entry_by_txt");
            X509* signer = issuer != nullptr ? issuer : cert.get();
            check(X509_set_issuer_name(cert.get(), X509_get_subject_name(signer)) == 1, "X509_set_issuer_name");

            X509V3_CTX ctx;
            X509V3_set_ctx_nodb(&ctx);
            X509V3_set_ctx(&ctx, signer, cert.get(), nullptr, nullptr, 0);
            addExtension(cert.get(), &ctx, NID_subject_key_identifier, "hash");
            addExtension(cert.get(), &ctx, NID_authority_key_identifier, "keyid:always");
            switch (kind)
            {
                case Kind::Ca:
                    addExtension(cert.get(), &ctx, NID_basic_constraints, "critical,CA:TRUE");
                    addExtension(cert.get(), &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
                    break;
                case Kind::Server:
                    addExtension(cert.get(), &ctx, NID_basic_constraints, "critical,CA:FALSE");
                    addExtension(cert.get(), &ctx, NID_key_usage, "critical,digitalSignature");
                    addExtension(cert.get(), &ctx, NID_ext_key_usage, "serverAuth");
                    break;
                case Kind::Client:
                    addExtension(cert.get(), &ctx, NID_basic_constraints, "critical,CA:FALSE");
                    addExtension(cert.get(), &ctx, NID_key_usage, "critical,digitalSignature");
                    addExtension(cert.get(), &ctx, NID_ext_key_usage, "clientAuth");
                    break;
            }
            if (!subjectAltName.empty())
            {
                addExtension(cert.get(), &ctx, NID_subject_alt_name, subjectAltName.c_str());
            }

            check(X509_sign(cert.get(), issuerKey != nullptr ? issuerKey : key, EVP_sha256()) > 0, "X509_sign");
            return cert;
        }

        static BioPtr openForWrite(const std::string& file, const char* mode = "w")
        {
            BioPtr bio(BIO_new_file(file.c_str(), mode), &BIO_free);
            check(bio != nullptr, "BIO_new_file");
            return bio;
        }

        static void writeCertificates(const std::string& file, const std::vector<X509*>& certificates)
        {
            auto bio = openForWrite(file);
            for (X509* cert : certificates)
            {
                check(PEM_write_bio_X509(bio.get(), cert) == 1, "PEM_write_bio_X509");
            }
        }

        static void writeKey(const std::string& file, EVP_PKEY* key, const std::string& passphrase = {})
        {
            auto bio = openForWrite(file);
            const bool encrypted = !passphrase.empty();
            check(PEM_write_bio_PrivateKey(bio.get(),
                                           key,
                                           encrypted ? EVP_aes_256_cbc() : nullptr,
                                           encrypted ? reinterpret_cast<const unsigned char*>(passphrase.data())
                                                     : nullptr,
                                           static_cast<int>(passphrase.size()),
                                           nullptr,
                                           nullptr) == 1,
                  "PEM_write_bio_PrivateKey");
        }

        static std::string readText(const std::string& file)
        {
            std::ifstream in(file, std::ios::binary);
            std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            check(static_cast<bool>(in) || in.eof(), "read");
            return text;
        }

        static void writeText(const std::string& file, const std::string& text)
        {
            std::ofstream out(file, std::ios::binary | std::ios::trunc);
            out << text;
            check(static_cast<bool>(out), "write");
        }

        void generate()
        {
            auto caKey = newKey();
            auto ca = newCertificate(caKey.get(), "indexer-client fake CA", Kind::Ca, {}, nullptr, nullptr);
            writeCertificates(caCertificate(), {ca.get()});

            auto otherCaKey = newKey();
            auto otherCa =
                newCertificate(otherCaKey.get(), "indexer-client foreign CA", Kind::Ca, {}, nullptr, nullptr);
            writeCertificates(otherCaCertificate(), {otherCa.get()});
            writeCertificates(caBundleOtherThenGood(), {otherCa.get(), ca.get()});

            auto serverKeyPair = newKey();
            auto server =
                newCertificate(serverKeyPair.get(), "127.0.0.1", Kind::Server, "IP:127.0.0.1", ca.get(), caKey.get());
            writeCertificates(serverCertificate(), {server.get()});
            writeKey(serverKey(), serverKeyPair.get());

            auto wrongKey = newKey();
            auto wrong =
                newCertificate(wrongKey.get(), wrongName(), Kind::Server, "DNS:" + wrongName(), ca.get(), caKey.get());
            writeCertificates(wrongNameServerCertificate(), {wrong.get()});
            writeKey(wrongNameServerKey(), wrongKey.get());

            auto clientKeyPair = newKey();
            auto client = newCertificate(
                clientKeyPair.get(), "indexer-client fake client", Kind::Client, {}, ca.get(), caKey.get());
            writeCertificates(clientCertificate(), {client.get()});
            writeKey(clientKey(), clientKeyPair.get());
            writeKey(encryptedClientKey(), clientKeyPair.get(), passphrase());

            auto intermediateKey = newKey();
            auto intermediate = newCertificate(
                intermediateKey.get(), "indexer-client fake intermediate CA", Kind::Ca, {}, ca.get(), caKey.get());
            writeCertificates(intermediateCaCertificate(), {intermediate.get()});
            auto leafKey = newKey();
            auto leaf = newCertificate(leafKey.get(),
                                       "indexer-client fake chained client",
                                       Kind::Client,
                                       {},
                                       intermediate.get(),
                                       intermediateKey.get());
            writeCertificates(chainCertificate(), {leaf.get(), intermediate.get()});
            writeKey(chainKey(), leafKey.get());

            auto unrelatedKey = newKey();
            writeKey(otherKey(), unrelatedKey.get());
            writeKey(keyOnlyPem(), unrelatedKey.get());

            const std::string malformed = "-----BEGIN CERTIFICATE-----\n"
                                          "this is not base64 DER at all!\n"
                                          "-----END CERTIFICATE-----\n";
            writeText(malformedCa(), malformed);
            const auto caPem = readText(caCertificate());
            writeText(caThenMalformed(), caPem + malformed);
            writeText(chainThenMalformed(), readText(chainCertificate()) + malformed);

            constexpr std::size_t MIB = 1024 * 1024;
            std::string large;
            while (large.size() + caPem.size() <= MIB)
            {
                large += caPem;
            }
            writeText(largeCaBundle(), large);
            std::string oversized = caPem;
            oversized.resize(MIB + 1, '\n');
            writeText(oversizedCa(), oversized);
            writeText(emptyFile(), {});
        }

        std::string m_directory;
    };
} // namespace indexer_client::testing

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

#endif // _INDEXER_CLIENT_TESTS_TLS_MATERIAL_FACTORY_HPP
