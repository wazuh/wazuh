/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tlsCertificateStatus.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <utility>

namespace remoted::http
{
    namespace
    {
        using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

        std::string subjectOf(const X509* certificate)
        {
            if (certificate == nullptr)
            {
                return {};
            }
            // X509_NAME_oneline's fixed buffer is fine here: the value is for a log line, not for
            // matching, and a subject longer than this is truncated rather than lost.
            char buffer[256];
            const char* oneline = X509_NAME_oneline(X509_get_subject_name(certificate), buffer, sizeof(buffer));
            return oneline != nullptr ? std::string {oneline} : std::string {};
        }

        bool equalsIgnoreCase(const std::string& a, const std::string& b)
        {
            return a.size() == b.size() &&
                   std::equal(a.begin(),
                              a.end(),
                              b.begin(),
                              [](unsigned char x, unsigned char y) { return std::tolower(x) == std::tolower(y); });
        }

        /// 127.0.0.0/8 or ::1, read straight off the SAN's octets -- OpenSSL stores an iPAddress as
        /// 4 or 16 raw bytes, so there is nothing to parse. Any other length is not an address this
        /// code understands, and is treated as usable rather than silently dropped.
        bool isLoopbackAddress(const unsigned char* octets, int length)
        {
            if (octets == nullptr)
            {
                return false;
            }
            if (length == 4)
            {
                return octets[0] == 127;
            }
            if (length == 16)
            {
                static const unsigned char IPV6_LOOPBACK[16] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                return std::memcmp(octets, IPV6_LOOPBACK, sizeof(IPV6_LOOPBACK)) == 0;
            }
            return false;
        }

        /// A dNSName that only ever names this host to itself.
        bool isLocalName(const std::string& name, const std::vector<std::string>& localNames)
        {
            return std::any_of(localNames.begin(),
                               localNames.end(),
                               [&name](const std::string& local) { return equalsIgnoreCase(name, local); });
        }

        using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>;
    } // namespace

    void X509Deleter::operator()(X509* certificate) const noexcept
    {
        X509_free(certificate);
    }

    std::vector<X509Ptr> loadCertificates(const std::string& pemPath)
    {
        std::vector<X509Ptr> certificates;
        if (pemPath.empty())
        {
            return certificates;
        }

        BioPtr bio {BIO_new_file(pemPath.c_str(), "r"), &BIO_free};
        if (!bio)
        {
            ERR_clear_error();
            return certificates;
        }

        // PEM_read_bio_X509 skips blocks that are not a CERTIFICATE, so a combined key+cert file
        // or a bundle yields exactly its certificates. It fails at end of file with a "no start
        // line" error -- expected, cleared below so it never leaks into a later TLS operation.
        for (X509Ptr certificate {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)}; certificate;
             certificate.reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)))
        {
            certificates.push_back(std::move(certificate));
        }
        ERR_clear_error();
        return certificates;
    }

    std::optional<int> daysUntilExpiry(const X509* certificate)
    {
        if (certificate == nullptr)
        {
            return std::nullopt;
        }

        const ASN1_TIME* notAfter = X509_get0_notAfter(certificate);
        if (notAfter == nullptr)
        {
            return std::nullopt;
        }

        // ASN1_TIME_diff(days, seconds, from=now, to=notAfter): both parts carry the sign of the
        // difference, so an expired certificate reads negative days -- or 0 days with negative
        // seconds during the first 24 h past notAfter, which is folded into -1 so "negative"
        // stays a strict synonym of "expired".
        int days = 0;
        int seconds = 0;
        if (ASN1_TIME_diff(&days, &seconds, nullptr, notAfter) != 1)
        {
            return std::nullopt;
        }
        if (days == 0 && seconds < 0)
        {
            days = -1;
        }
        return days;
    }

    bool anyCaSignsLeaf(const X509* leaf, const std::vector<X509Ptr>& cas)
    {
        if (leaf == nullptr)
        {
            return false;
        }
        for (const auto& ca : cas)
        {
            EVP_PKEY* key = X509_get0_pubkey(ca.get());
            // X509_verify takes a non-const X509* (it may cache the encoding) but does not modify
            // the certificate in any observable way.
            if (key != nullptr && X509_verify(const_cast<X509*>(leaf), key) == 1)
            {
                return true;
            }
        }
        ERR_clear_error(); // a failed X509_verify queues a signature error
        return false;
    }

    std::vector<std::string> localHostNames()
    {
        std::vector<std::string> names {"localhost", "localhost.localdomain"};

        // POSIX allows gethostname() to truncate WITHOUT NUL-terminating, so the buffer is one byte
        // longer than the name it can hold and that byte is pre-zeroed.
        char hostname[257] {};
        if (::gethostname(hostname, sizeof(hostname) - 1) == 0 && hostname[0] != '\0')
        {
            std::string full {hostname};
            names.push_back(full);

            // Only ever REDUCED to the short form, never expanded to a guessed FQDN: subtracting
            // "foo.example.com" because this host is called "foo" would silence the warning for a
            // certificate that is, as far as anything here can tell, perfectly routable.
            const auto dot = full.find('.');
            if (dot != std::string::npos && dot > 0)
            {
                names.push_back(full.substr(0, dot));
            }
        }
        return names;
    }

    bool leafHasUsableSan(const X509* leaf, const std::vector<std::string>& localNames)
    {
        if (leaf == nullptr)
        {
            return false;
        }

        // X509_get_ext_d2i takes a non-const X509*; it only decodes an extension already parsed
        // into the certificate, and does not modify it observably.
        GeneralNamesPtr names {static_cast<GENERAL_NAMES*>(
                                   X509_get_ext_d2i(const_cast<X509*>(leaf), NID_subject_alt_name, nullptr, nullptr)),
                               &GENERAL_NAMES_free};
        if (!names)
        {
            // No SAN extension at all. RFC 6125 has clients ignore the subject CN, so this
            // certificate identifies no host to anyone.
            ERR_clear_error();
            return false;
        }

        const int count = sk_GENERAL_NAME_num(names.get());
        for (int index = 0; index < count; ++index)
        {
            const GENERAL_NAME* entry = sk_GENERAL_NAME_value(names.get(), index);
            if (entry == nullptr)
            {
                continue;
            }

            if (entry->type == GEN_IPADD)
            {
                if (!isLoopbackAddress(ASN1_STRING_get0_data(entry->d.iPAddress),
                                       ASN1_STRING_length(entry->d.iPAddress)))
                {
                    return true;
                }
            }
            else if (entry->type == GEN_DNS)
            {
                // Length-delimited, not treated as a C string: a dNSName is an IA5String and may
                // legally carry an embedded NUL, which is exactly how a name is smuggled past a
                // strlen-based comparison.
                const std::string name {reinterpret_cast<const char*>(ASN1_STRING_get0_data(entry->d.dNSName)),
                                        static_cast<std::size_t>(std::max(0, ASN1_STRING_length(entry->d.dNSName)))};
                if (!name.empty() && !isLocalName(name, localNames))
                {
                    return true;
                }
            }
            // Every other type (URI, email, directoryName, ...) is not something a TLS client ever
            // matches a server identity against, so it neither counts nor disqualifies.
        }

        return false;
    }

    bool leafHasUsableSan(const X509* leaf)
    {
        return leafHasUsableSan(leaf, localHostNames());
    }

    TlsCertificateSnapshot evaluateCertificateStatus(const X509* leaf, const std::string& caPath)
    {
        TlsCertificateSnapshot snapshot;
        snapshot.expiryDays = daysUntilExpiry(leaf);
        snapshot.leafSubject = subjectOf(leaf);

        const auto cas = loadCertificates(caPath);
        if (!cas.empty())
        {
            snapshot.caMatchesLeaf = anyCaSignsLeaf(leaf, cas);
            for (const auto& ca : cas)
            {
                if (!snapshot.caSubjects.empty())
                {
                    snapshot.caSubjects += ", ";
                }
                snapshot.caSubjects += subjectOf(ca.get());
            }
        }
        return snapshot;
    }

    TlsCertificateMonitor::~TlsCertificateMonitor()
    {
        stop();
    }

    void TlsCertificateMonitor::record(TlsCertificateSnapshot snapshot)
    {
        std::lock_guard<std::mutex> lock {m_snapshotMutex};
        snapshot.evaluations = m_snapshot.evaluations + 1;
        m_snapshot = std::move(snapshot);
    }

    void TlsCertificateMonitor::start(std::chrono::seconds interval, EvaluateFn evaluate)
    {
        if (m_thread.joinable() || interval <= std::chrono::seconds {0} || !evaluate)
        {
            return;
        }
        m_stopping.store(false, std::memory_order_relaxed);
        m_thread = std::thread(
            [this, interval, evaluate = std::move(evaluate)]
            {
                std::unique_lock<std::mutex> lock {m_waitMutex};
                while (!m_stopping.load(std::memory_order_relaxed))
                {
                    // Woken early by stop(); a spurious wakeup just re-arms the wait.
                    if (m_wakeup.wait_for(
                            lock, interval, [this] { return m_stopping.load(std::memory_order_relaxed); }))
                    {
                        break;
                    }
                    lock.unlock();
                    try
                    {
                        record(evaluate());
                    }
                    catch (...)
                    {
                        // The evaluate function owns its logging; a failed tick must not take the
                        // thread (and every future tick) down with it.
                    }
                    lock.lock();
                }
            });
    }

    void TlsCertificateMonitor::stop() noexcept
    {
        {
            std::lock_guard<std::mutex> lock {m_waitMutex};
            m_stopping.store(true, std::memory_order_relaxed);
        }
        m_wakeup.notify_all();
        if (m_thread.joinable())
        {
            try
            {
                m_thread.join();
            }
            catch (...)
            {
                // join() only throws for a deadlock/invalid handle; neither is recoverable here.
            }
        }
    }

    TlsCertificateSnapshot TlsCertificateMonitor::snapshot() const
    {
        std::lock_guard<std::mutex> lock {m_snapshotMutex};
        return m_snapshot;
    }

} // namespace remoted::http
