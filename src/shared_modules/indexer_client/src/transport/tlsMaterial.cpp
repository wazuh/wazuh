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

// Loading and validation of <indexer>.ssl (plan 18, I48) over the OpenSSL that libwazuhext exports. Nothing is written
// to disk: the files are read once and handed to curl as in-memory blobs by the loops. The system CA store (no CA
// configured, E11e) is only located here, never read: curl loads it by path.

#include "transport/tlsMaterial.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "transport/seams.hpp"

namespace indexer_client::detail
{
    namespace
    {
        using Result = Outcome<TlsMaterial>;

        /// Removes, on every exit, the errors the load pushed onto OpenSSL's per-thread queue, and only those: an
        /// error queued earlier by another component of the owner thread is left for it to read.
        struct ErrorQueueGuard final
        {
            ErrorQueueGuard() noexcept
            {
                ERR_set_mark();
            }
            ~ErrorQueueGuard()
            {
                ERR_pop_to_mark();
            }
            ErrorQueueGuard(const ErrorQueueGuard&) = delete;
            ErrorQueueGuard& operator=(const ErrorQueueGuard&) = delete;
        };

        /// Wipes a string that held key material when it goes out of scope without having been moved out.
        struct CleanseOnExit final
        {
            std::string& text;
            ~CleanseOnExit()
            {
                cleanseString(text);
            }
        };

        struct BioDeleter final
        {
            void operator()(BIO* bio) const noexcept
            {
                BIO_free(bio);
            }
        };
        struct X509Deleter final
        {
            void operator()(X509* cert) const noexcept
            {
                X509_free(cert);
            }
        };
        struct PkeyDeleter final
        {
            void operator()(EVP_PKEY* key) const noexcept
            {
                EVP_PKEY_free(key);
            }
        };
        using BioPtr = std::unique_ptr<BIO, BioDeleter>;
        using X509Ptr = std::unique_ptr<X509, X509Deleter>;
        struct X509InfoStackDeleter final
        {
            void operator()(STACK_OF(X509_INFO) * stack) const noexcept
            {
                sk_X509_INFO_pop_free(stack, X509_INFO_free);
            }
        };
        using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
        using X509InfoStackPtr = std::unique_ptr<STACK_OF(X509_INFO), X509InfoStackDeleter>;

        /// Each file of <indexer>.ssl is at most this size; no PEM CA, certificate or key comes near it.
        constexpr std::size_t MAX_FILE_BYTES = 1024 * 1024;
        /// curl refuses any blob of CURL_MAX_INPUT_LENGTH bytes or more (lib/urldata.h, an internal header; curl 8.20)
        /// with CURLE_BAD_FUNCTION_ARGUMENT on every transfer, so the concatenated CA bundle must stay below it.
        constexpr std::size_t CURL_MAX_INPUT_LENGTH = 8000000;

        /// Passphrase callback that always fails: an encrypted key is a configuration error, never a prompt on the
        /// terminal (OpenSSL's default callback) and never an empty passphrase (a 0 return would be one).
        int refusePassphrase(char* /*buf*/, int /*size*/, int /*rwflag*/, void* /*userdata*/)
        {
            return -1;
        }

        std::string quoted(std::string_view key, const std::string& path)
        {
            return "indexer " + std::string(key) + " '" + path + "'";
        }

        /// Reads a whole file of at most MAX_FILE_BYTES, path as is (relative to the process's cwd); never reads more
        /// than one buffer past that bound. On failure `error` says why (strerror, or the size).
        bool readFile(const std::string& path, std::string& out, std::string& error)
        {
            out.clear();
            const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0)
            {
                error = std::strerror(errno);
                return false;
            }
            char buffer[16384];
            for (;;)
            {
                const auto n = ::read(fd, buffer, sizeof(buffer));
                if (n > 0)
                {
                    out.append(buffer, static_cast<std::size_t>(n));
                    if (out.size() > MAX_FILE_BYTES)
                    {
                        error = "larger than " + std::to_string(MAX_FILE_BYTES) + " bytes";
                        cleanseString(out);
                        OPENSSL_cleanse(buffer, sizeof(buffer));
                        ::close(fd);
                        return false;
                    }
                    continue;
                }
                if (n == 0)
                {
                    break;
                }
                if (errno == EINTR)
                {
                    continue;
                }
                error = std::strerror(errno);
                OPENSSL_cleanse(buffer, sizeof(buffer));
                ::close(fd);
                return false;
            }
            OPENSSL_cleanse(buffer, sizeof(buffer));
            ::close(fd);
            return true;
        }

        BioPtr memoryBio(const std::string& text)
        {
            return BioPtr(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())));
        }

        /// Number of certificates in a CA blob, parsed exactly as curl parses CURLOPT_CAINFO_BLOB
        /// (`PEM_X509_INFO_read_bio` over the whole blob, lib/vtls/openssl.c): -1 when curl would refuse the blob
        /// (any malformed PEM block, wherever it is), else the number of `x509` entries.
        int countCaCertificates(const std::string& text)
        {
            auto bio = memoryBio(text);
            if (!bio)
            {
                return -1;
            }
            X509InfoStackPtr entries(PEM_X509_INFO_read_bio(bio.get(), nullptr, &refusePassphrase, nullptr));
            if (!entries)
            {
                return -1;
            }
            int count = 0;
            for (int i = 0; i < sk_X509_INFO_num(entries.get()); ++i)
            {
                if (sk_X509_INFO_value(entries.get(), i)->x509 != nullptr)
                {
                    ++count;
                }
            }
            return count;
        }

        /// The leaf of a client chain blob, parsed exactly as curl parses CURLOPT_SSLCERT_BLOB (lib/vtls/openssl.c,
        /// use_certificate_chain_blob): `PEM_read_bio_X509_AUX` for the leaf, then `PEM_read_bio_X509` until the
        /// input ends; the chain is valid only if that end is `PEM_R_NO_START_LINE`. Null when curl would refuse it.
        X509Ptr readCertificateChain(const std::string& text)
        {
            auto bio = memoryBio(text);
            if (!bio)
            {
                return nullptr;
            }
            X509Ptr leaf(PEM_read_bio_X509_AUX(bio.get(), nullptr, &refusePassphrase, nullptr));
            if (!leaf)
            {
                return nullptr;
            }
            while (X509Ptr(PEM_read_bio_X509(bio.get(), nullptr, &refusePassphrase, nullptr)))
            {
            }
            const auto error = ERR_peek_last_error();
            if (ERR_GET_LIB(error) != ERR_LIB_PEM || ERR_GET_REASON(error) != PEM_R_NO_START_LINE)
            {
                return nullptr;
            }
            return leaf;
        }

        /// `host` starts with `prefix`, ASCII case-insensitively (RFC 3986 schemes), with something after it: the
        /// same comparison as admittedUrl's startsWithScheme (transport.cpp).
        bool hasScheme(std::string_view host, std::string_view prefix)
        {
            if (host.size() <= prefix.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < prefix.size(); ++i)
            {
                const char c = host[i];
                if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c) != prefix[i])
                {
                    return false;
                }
            }
            return true;
        }

        bool isHttps(std::string_view host)
        {
            return hasScheme(host, "https://");
        }

        bool isHttp(std::string_view host)
        {
            return hasScheme(host, "http://");
        }

        /// "Does not exist" is only ENOENT / ENOTDIR; anything else (EACCES, ELOOP, EIO...) picks the path, so that
        /// a store this process cannot read fails the handshake instead of turning verification off (I216). Never
        /// access(R_OK): after the privilege drop it would turn an unreadable store into "no store".
        bool pathExists(const std::string& path)
        {
            std::error_code error;
            static_cast<void>(std::filesystem::status(path, error)); // Follows symlinks, as curl's open does.
            if (!error)
            {
                return true;
            }
            return error != std::errc::no_such_file_or_directory && error != std::errc::not_a_directory;
        }

        std::string joined(const std::vector<std::string>& values)
        {
            std::string out;
            for (const auto& value : values)
            {
                out += (out.empty() ? "" : ", ") + value;
            }
            return out;
        }

        Result load(const RuntimeConfig& config)
        {
            TlsMaterial material;
            const auto& ssl = config.ssl;

            // Hosts: http or https only.
            std::vector<std::string> httpsHosts;
            for (const auto& host : config.hosts)
            {
                if (isHttps(host))
                {
                    httpsHosts.push_back(host);
                }
                else if (!isHttp(host))
                {
                    return Result::failure(Cause::InvalidConfig,
                                           "indexer host '" + host + "': the scheme must be http or https");
                }
            }

            // Certificate authorities: each file exists, is well-formed PEM as curl reads it and holds at least one
            // certificate; the concatenation is checked again (it is what curl gets) and must fit a curl blob.
            for (const auto& path : ssl.certificateAuthorities)
            {
                std::string text;
                std::string error;
                if (!readFile(path, text, error))
                {
                    return Result::failure(Cause::InvalidConfig,
                                           quoted("ssl.certificate_authorities", path) + ": cannot read: " + error);
                }
                const auto count = countCaCertificates(text);
                if (count < 0)
                {
                    return Result::failure(Cause::InvalidConfig,
                                           quoted("ssl.certificate_authorities", path) + ": malformed PEM content");
                }
                if (count == 0)
                {
                    return Result::failure(Cause::InvalidConfig,
                                           quoted("ssl.certificate_authorities", path) + ": holds no PEM certificate");
                }
                material.caBundle.append(text);
                if (material.caBundle.back() != '\n')
                {
                    material.caBundle.push_back('\n'); // Never glue an END line to the next BEGIN line.
                }
                if (material.caBundle.size() >= CURL_MAX_INPUT_LENGTH)
                {
                    return Result::failure(Cause::InvalidConfig,
                                           quoted("ssl.certificate_authorities", path) +
                                               ": the CA files together reach " +
                                               std::to_string(CURL_MAX_INPUT_LENGTH) + " bytes (curl's blob limit)");
                }
            }
            if (!material.caBundle.empty() && countCaCertificates(material.caBundle) < 1)
            {
                return Result::failure(Cause::InvalidConfig,
                                       "indexer ssl.certificate_authorities: the concatenated files are not valid PEM");
            }

            // Verification policy (E11e, I207/I216): the v1's behaviour when updating from 5.0.
            if (!ssl.verifyCertificates)
            {
                material.verifyPeer = false;
                material.verifyHost = false;
                if (!httpsHosts.empty())
                {
                    material.warning = "indexer TLS: certificate and host name verification disabled "
                                       "(verify_certificates is false) for https host(s) " +
                                       joined(httpsHosts) +
                                       "; the indexer credentials are sent to an unverified server";
                }
            }
            else if (material.caBundle.empty())
            {
                const auto testPaths = seams::systemCaPaths();
                const auto& paths = testPaths ? *testPaths : systemCaStorePaths();
                for (const auto& path : paths)
                {
                    if (pathExists(path))
                    {
                        material.systemCaPath = path; // The first existing one, whatever it holds (v1).
                        break;
                    }
                }
                if (!material.systemCaPath.empty() && !httpsHosts.empty())
                {
                    material.notice = "indexer TLS: using the system CA store " + material.systemCaPath;
                }
                if (material.systemCaPath.empty())
                {
                    material.verifyPeer = false; // The host name is still checked, as curl did in the v1.
                    if (!httpsHosts.empty())
                    {
                        material.warning =
                            "indexer TLS: no CA configured and no system CA store found (" + joined(paths) +
                            "); the server certificate is not verified (the host name is) for https "
                            "host(s) " +
                            joined(httpsHosts) + "; the indexer credentials are sent to an unverified server";
                    }
                }
            }

            // Client pair (mTLS): both or neither; "" counts as absent.
            const bool hasCert = !ssl.certificate.empty();
            const bool hasKey = !ssl.key.empty();
            if (hasCert != hasKey)
            {
                return hasCert ? Result::failure(Cause::InvalidConfig,
                                                 quoted("ssl.certificate", ssl.certificate) +
                                                     ": configured without ssl.key (both or neither)")
                               : Result::failure(Cause::InvalidConfig,
                                                 quoted("ssl.key", ssl.key) +
                                                     ": configured without ssl.certificate (both or neither)");
            }
            if (!hasCert)
            {
                return Result::success(std::move(material));
            }

            std::string chain;
            std::string error;
            if (!readFile(ssl.certificate, chain, error))
            {
                return Result::failure(Cause::InvalidConfig,
                                       quoted("ssl.certificate", ssl.certificate) + ": cannot read: " + error);
            }
            X509Ptr leaf = readCertificateChain(chain);
            if (!leaf)
            {
                return Result::failure(Cause::InvalidConfig,
                                       quoted("ssl.certificate", ssl.certificate) +
                                           ": not a PEM certificate chain (a leaf, then only PEM certificates)");
            }

            std::string key;
            CleanseOnExit wipeKey {key};
            if (!readFile(ssl.key, key, error))
            {
                return Result::failure(Cause::InvalidConfig, quoted("ssl.key", ssl.key) + ": cannot read: " + error);
            }
            PkeyPtr pkey;
            {
                auto bio = memoryBio(key);
                if (bio)
                {
                    pkey.reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, &refusePassphrase, nullptr));
                }
            }
            if (!pkey)
            {
                const bool encrypted = key.find("ENCRYPTED") != std::string::npos;
                return Result::failure(Cause::InvalidConfig,
                                       quoted("ssl.key", ssl.key) +
                                           (encrypted
                                                ? ": the key is encrypted (only unencrypted PEM keys are supported)"
                                                : ": holds no readable PEM private key"));
            }
            if (X509_check_private_key(leaf.get(), pkey.get()) != 1)
            {
                return Result::failure(Cause::InvalidConfig,
                                       quoted("ssl.key", ssl.key) + ": does not match the first certificate of '" +
                                           ssl.certificate + "'");
            }

            material.certificateChain = std::move(chain); // The whole file, so that the chain travels.
            material.privateKey = std::move(key);
            return Result::success(std::move(material));
        }
    } // namespace

    const std::vector<std::string>& systemCaStorePaths()
    {
        static const std::vector<std::string> PATHS {
            "/etc/ssl/certs/ca-certificates.crt",     // Debian systems
            "/etc/pki/tls/certs/ca-bundle.crt",       // Redhat and Mandriva
            "/usr/share/ssl/certs/ca-bundle.crt",     // RedHat
            "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
            "/etc/ssl/cert.pem",                      // OpenBSD, FreeBSD, MacOS
        };
        return PATHS;
    }

    TlsMaterial::~TlsMaterial()
    {
        cleanseString(privateKey);
    }

    void cleanseString(std::string& text) noexcept
    {
        if (!text.empty())
        {
            OPENSSL_cleanse(text.data(), text.size());
        }
        text.clear();
    }

    Outcome<TlsMaterial> loadTlsMaterial(const RuntimeConfig& config) noexcept
    {
        ErrorQueueGuard errors;
        try
        {
            return load(config);
        }
        catch (...)
        {
            // E.g. std::bad_alloc. Built field by field: only the reason allocates, and its failure is swallowed.
            Outcome<TlsMaterial> failed;
            failed.cause = Cause::InvalidConfig;
            try
            {
                failed.reason = "cannot load the indexer TLS material: unexpected exception";
            }
            catch (...)
            {
            }
            return failed;
        }
    }
} // namespace indexer_client::detail
