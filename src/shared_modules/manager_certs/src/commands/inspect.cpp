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

        /// Whole days between now and @p notAfter; negative once the certificate has expired.
        long daysRemaining(std::time_t notAfter, std::time_t now)
        {
            return static_cast<long>(notAfter - now) / kSecondsPerDay;
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
        const ca_bundle::Vouch vouch = ca_bundle::vouch(bundle, leaf, serializedBytes);
        out << "vouched: " << (vouch.failure == ca_bundle::GuardFailure::none ? "yes" : "no") << '\n';

        return 0;
    }

} // namespace manager_certs
