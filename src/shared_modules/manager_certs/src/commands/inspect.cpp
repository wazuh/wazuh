/*
 * Wazuh manager certs tool - `inspect`
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "manager_certs/commands.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <ctime>
#include <string>

namespace manager_certs
{
    namespace
    {
        constexpr long kSecondsPerDay = 24L * 60L * 60L;

        /// `notAfter` as `YYYY-MM-DDTHH:MM:SSZ` (UTC); a fixed placeholder when it cannot be
        /// rendered (ASN1_TIME_to_tm already failed upstream in describe(), so this never happens
        /// for a certificate OpenSSL parsed, but a formatting failure still prints something).
        std::string formatUtc(std::time_t epochSeconds)
        {
            struct tm parts {};
            if (gmtime_r(&epochSeconds, &parts) == nullptr)
            {
                return "unknown";
            }
            char buffer[32];
            const std::size_t written = std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &parts);
            return written > 0 ? std::string {buffer, written} : "unknown";
        }

        /// Whole days between now and @p notAfter, floored -- negative once the certificate has
        /// expired, and a certificate that expired less than a day ago still reads as -1, not 0:
        /// plain integer division truncates toward zero, so a cert expired 3 hours ago (diff in
        /// (-kSecondsPerDay, 0)) would otherwise read "0 days remaining", indistinguishable from
        /// one still valid.
        long daysRemaining(std::time_t notAfter, std::time_t now)
        {
            const long diff = static_cast<long>(notAfter - now);
            long days = diff / kSecondsPerDay;
            if (diff % kSecondsPerDay != 0 && diff < 0)
            {
                --days;
            }
            return days;
        }

    } // namespace

    int runInspect(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::ostream& out)
    {
        const std::time_t now = std::time(nullptr);

        for (const auto& certificate : bundle.certificates)
        {
            const ca_bundle::CertificateFacts facts = ca_bundle::describe(certificate.get(), leaf);
            out << "subject: " << facts.subject << '\n';
            out << "issuer: " << facts.issuer << '\n';
            out << "notAfter: " << formatUtc(facts.notAfter) << " (" << daysRemaining(facts.notAfter, now)
                << " days remaining)\n";
            out << "identity: " << facts.identity << '\n';
            out << "signsLeaf: " << (facts.signsLeaf ? "yes" : "no") << '\n';
            out << '\n';
        }

        if (bundle.block)
        {
            out << "publication: " << bundle.block->publication << '\n';
        }
        else
        {
            out << "publication: 0 (unpublished)\n";
        }

        const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();
        // A bundle that DOES carry certificates but fails to re-serialise has nothing to hand out,
        // whatever vouch()'s own byte-cap guard says about 0 bytes (it would read as "small enough"
        // and pass) -- the same call main.cpp's `check` path makes before it ever reaches runCheck(),
        // and remoted's buildLocked() makes for GET /cacerts (caCertificateSource.cpp:140). inspect()
        // never fails outright (commands.hpp), so here it is simply never "vouched: yes".
        const bool serialisationFailed = !bundle.certificates.empty() && serializedBytes == 0;
        const ca_bundle::Vouch vouch = ca_bundle::vouch(bundle, leaf, serializedBytes);
        const bool vouchedYes = !serialisationFailed && vouch.failure == ca_bundle::GuardFailure::none;
        out << "vouched: " << (vouchedYes ? "yes" : "no") << '\n';

        return 0;
    }

} // namespace manager_certs
