/*
 * Wazuh manager certs tool - `check`
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

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <ctime>
#include <string>

namespace manager_certs
{
    namespace
    {
        /// One line per ca_bundle::GuardFailure, naming the guard the way an operator can act on:
        /// the two size guards name the observed count/bytes against the limit, the rest name the
        /// failure in words. `none` never reaches here (runCheck() returns before calling this).
        std::string describeFailure(ca_bundle::GuardFailure failure,
                                    const ca_bundle::ParsedBundle& bundle,
                                    std::size_t serializedBytes)
        {
            switch (failure)
            {
                case ca_bundle::GuardFailure::no_certificates: return "no certificates";
                case ca_bundle::GuardFailure::no_block: return "no publication block (unpublished)";
                case ca_bundle::GuardFailure::hash_mismatch: return "content hash does not match the publication block";
                case ca_bundle::GuardFailure::no_ca_signs_leaf: return "no CA signs the served leaf";
                case ca_bundle::GuardFailure::too_many_certificates:
                    return std::to_string(bundle.certificates.size()) + " certificates (max " +
                           std::to_string(ca_bundle::kMaxCertificates) + ")";
                case ca_bundle::GuardFailure::too_many_bytes:
                    return std::to_string(serializedBytes) + " bytes (max " +
                           std::to_string(ca_bundle::kMaxSerializedBytes) + ")";
                case ca_bundle::GuardFailure::none: break;
            }
            return "rejected";
        }

        /// `epochSeconds` as `YYYY-MM-DDTHH:MM:SSZ` (UTC), the same shape inspect.cpp prints
        /// `notAfter` in, so an operator reads the same certificate's date the same way from
        /// either command. "unknown" only if the conversion itself fails.
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

        /// Whether @p time converts to a Unix timestamp at all, independent of what
        /// ca_bundle::describe() reports. describe() maps a conversion failure to notBefore/
        /// notAfter == 0 (src/shared_modules/ca_bundle/src/ca_bundle.cpp:131, asUnixTime()), and 0
        /// is indistinguishable from a certificate whose real date IS 1970-01-01T00:00:00Z -- so
        /// the validity-window guard below cannot tell "this ASN.1 time is bogus" from "this ASN.1
        /// time is exactly the epoch" by looking at CertificateFacts alone. Re-derived here,
        /// straight from the certificate's own ASN1_TIME, the same call ca_bundle's own asUnixTime()
        /// makes -- without touching ca_bundle, and without breaking a legitimate pre-1970
        /// notBefore/notAfter, which still converts (a negative but real timestamp).
        bool asn1TimeConverts(const ASN1_TIME* time)
        {
            if (time == nullptr)
            {
                return false;
            }
            struct tm parts {};
            const bool converts = ASN1_TIME_to_tm(time, &parts) == 1;
            if (!converts)
            {
                ERR_clear_error();
            }
            return converts;
        }

        /// RF-12 / 02-diseno.md §2.6: `ca_bundle::vouch()` checks structure, the publication hash,
        /// leaf-signing and the size caps, but never a certificate's `isCa` flag or its validity
        /// window -- `check` owns both itself, per certificate, in bundle order, stopping at the
        /// first one that fails either (isCa first, then the window: not yet valid, then expired).
        /// Empty when every certificate passes both.
        std::string
        firstCertificateGuardFailure(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::time_t now)
        {
            for (const auto& certificate : bundle.certificates)
            {
                const ca_bundle::CertificateFacts facts = ca_bundle::describe(certificate.get(), leaf);
                if (!facts.isCa)
                {
                    return facts.identity + ": not a CA";
                }
                // Ahead of the notBefore/notAfter comparisons themselves: a malformed ASN.1 time
                // that OpenSSL still parses into an X509 (but cannot convert to a struct tm) must
                // not silently read as facts.notBefore/notAfter == 0, which "now <= 0" and
                // "now >= 0" would both accept as a real, ancient-but-valid date.
                if (!asn1TimeConverts(X509_get0_notBefore(certificate.get())) ||
                    !asn1TimeConverts(X509_get0_notAfter(certificate.get())))
                {
                    return facts.identity + ": notBefore/notAfter is not a valid ASN.1 time";
                }
                if (now < facts.notBefore)
                {
                    return facts.identity + ": not yet valid (notBefore " + formatUtc(facts.notBefore) + ")";
                }
                if (now > facts.notAfter)
                {
                    return facts.identity + ": expired (notAfter " + formatUtc(facts.notAfter) + ")";
                }
            }
            return {};
        }

    } // namespace

    int
    runCheck(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::size_t serializedBytes, std::ostream& err)
    {
        // Per certificate FIRST, and only then the guards remoted vouches with. Both orders reject
        // exactly the same bundles -- these guards are the stricter set, so anything they refuse
        // vouch() would refuse too or the operator would want refused anyway -- but they differ in
        // what the operator is told. Since leafChainsToAnyCa() started verifying the chain (C33),
        // an expired CA or one without CA:TRUE already fails vouch()'s no_ca_signs_leaf, and
        // reporting that first would answer "no CA signs the served leaf" for a bundle whose real
        // problem is a date. `check` exists to say which certificate is wrong and why.
        const std::string perCertificateFailure = firstCertificateGuardFailure(bundle, leaf, std::time(nullptr));
        if (!perCertificateFailure.empty())
        {
            err << "wazuh-manager-certs: check: " << perCertificateFailure << '\n';
            return 1;
        }

        const ca_bundle::Vouch vouch = ca_bundle::vouch(bundle, leaf, serializedBytes);
        if (vouch.failure != ca_bundle::GuardFailure::none)
        {
            err << "wazuh-manager-certs: check: " << describeFailure(vouch.failure, bundle, serializedBytes) << '\n';
            return 1;
        }

        return 0;
    }

} // namespace manager_certs
