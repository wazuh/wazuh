/*
 * Wazuh manager certs tool - `add`
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
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

#include <algorithm>
#include <array>
#include <ctime>
#include <string>
#include <vector>

namespace manager_certs
{
    namespace
    {
        /// `epochSeconds` as `YYYY-MM-DDTHH:MM:SSZ`, the same shape `inspect` and `check` print
        /// dates in, so the same certificate reads the same way whichever command names it.
        std::string formatUtc(std::time_t epochSeconds)
        {
            struct tm parts {};
            if (gmtime_r(&epochSeconds, &parts) == nullptr)
            {
                return "unknown";
            }
            std::array<char, 32> buffer {};
            const std::size_t written = std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &parts);
            return written > 0 ? std::string {buffer.data(), written} : std::string {"unknown"};
        }

        /// Whether @p time converts to a Unix timestamp at all. Same call, and same reason, as
        /// `check`'s own asn1TimeConverts() (src/shared_modules/manager_certs/src/commands/check.cpp:75):
        /// ca_bundle::describe() maps an unconvertible ASN.1 time to 0, and 0 is indistinguishable
        /// from a real 1970-01-01 date -- so the window comparisons below would accept a bogus date
        /// as an ancient but valid one (C36g). Re-derived here rather than shared, exactly as
        /// check.cpp re-derives it: neither file may reach into the other's anonymous namespace,
        /// and moving it to ca_bundle would change a library whose contract E7a must not touch.
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

        /// G3 for one certificate at @p now: an unreadable ASN.1 date first, then the window.
        /// Empty when it passes. Evaluated once before the publication is decided and again after
        /// the wait of C28b, which is why it is a function of the hour and of nothing else.
        std::string dateFailure(const X509* certificate, const std::string& identity, std::time_t now)
        {
            if (!asn1TimeConverts(X509_get0_notBefore(certificate)) ||
                !asn1TimeConverts(X509_get0_notAfter(certificate)))
            {
                return identity + ": notBefore/notAfter is not a valid ASN.1 time";
            }

            const ca_bundle::CertificateFacts facts = ca_bundle::describe(certificate, nullptr);
            if (now < facts.notBefore)
            {
                return identity + ": not yet valid (notBefore " + formatUtc(facts.notBefore) + ")";
            }
            if (now > facts.notAfter)
            {
                return identity + ": expired (notAfter " + formatUtc(facts.notAfter) + ")";
            }
            return {};
        }

        /// A reference of our own on @p certificate, so the candidate can hold the same object the
        /// bundle or the input file still owns.
        ca_bundle::X509Ptr retain(X509* certificate)
        {
            if (certificate == nullptr || X509_up_ref(certificate) != 1)
            {
                return {};
            }
            return ca_bundle::X509Ptr {certificate};
        }
    } // namespace

    int runAdd(WriteContext& context,
               const std::string& inputContents,
               const std::filesystem::path& inputPath,
               std::ostream& out,
               std::ostream& err)
    {
        const auto refuse = [&err](int code, const std::string& text)
        {
            err << "wazuh-manager-certs: add: " << text << '\n';
            return code;
        };

        // GI (C34b): the input is refused whole, exactly like the bundle in prepareWrite(). Reading
        // a file "up to the first block we could not decode" is how a caller ends up adding half of
        // what the operator meant to add.
        const ca_bundle::ParsedBundle input = ca_bundle::parseBundle(inputContents);
        if (!input.wellFormed)
        {
            return refuse(2, "input file at " + inputPath.string() + " is malformed");
        }
        if (input.certificates.empty())
        {
            return refuse(2, "input file at " + inputPath.string() + " contains no certificates");
        }

        // What the file holds today, in order, plus what survives the guards below.
        std::vector<ca_bundle::X509Ptr> candidate;
        std::vector<std::string> identities;
        candidate.reserve(context.bundle.certificates.size() + input.certificates.size());
        for (const auto& certificate : context.bundle.certificates)
        {
            candidate.push_back(retain(certificate.get()));
            identities.push_back(ca_bundle::identityOf(certificate.get()));
        }
        const std::size_t existing = identities.size();

        // Raw pointers to the certificates this command is adding, for the post-wait re-check. They
        // are owned by `input` and by `candidate`, both of which outlive finishWrite().
        std::vector<X509*> added;
        const std::time_t now = context.time.now ? context.time.now() : std::time(nullptr);

        for (const auto& certificate : input.certificates)
        {
            const std::string identity = ca_bundle::identityOf(certificate.get());
            if (identity.empty())
            {
                return refuse(2, "a certificate in " + inputPath.string() + " could not be identified");
            }

            // G1, against the bundle AND against what this same input already contributed (C34d):
            // a file listing the same CA twice must not publish it twice.
            const auto known = std::find(identities.begin(), identities.end(), identity);
            if (known != identities.end())
            {
                return refuse(1,
                              identity + (static_cast<std::size_t>(known - identities.begin()) < existing
                                              ? ": duplicate of an existing certificate"
                                              : ": duplicate within the input file"));
            }

            // G2: what is not a CA can never be an anchor, whatever else it can do.
            const ca_bundle::CertificateFacts facts = ca_bundle::describe(certificate.get(), context.leaf);
            if (!facts.isCa)
            {
                return refuse(1, identity + ": not a CA");
            }

            // G3.
            const std::string dates = dateFailure(certificate.get(), identity, now);
            if (!dates.empty())
            {
                return refuse(1, dates);
            }

            identities.push_back(identity);
            added.push_back(certificate.get());
            candidate.push_back(retain(certificate.get()));
        }

        const WriteOutcome outcome =
            finishWrite(context,
                        std::move(candidate),
                        [&added](std::time_t afterWait) -> std::string
                        {
                            for (X509* certificate : added)
                            {
                                const std::string failure =
                                    dateFailure(certificate, ca_bundle::identityOf(certificate), afterWait);
                                if (!failure.empty())
                                {
                                    return failure;
                                }
                            }
                            return {};
                        });

        if (outcome.exitCode != 0)
        {
            err << "wazuh-manager-certs: " << outcome.message << '\n';
            return outcome.exitCode;
        }

        // Published. A failed fsync of the DIRECTORY is the one case where that is still true and
        // the operator has to be told anyway (C31).
        if (outcome.durabilityUnknown)
        {
            err << "wazuh-manager-certs: " << outcome.message << '\n';
        }
        out << "added " << input.certificates.size() << " certificate(s); published generation " << outcome.publication
            << '\n';
        return 0;
    }

} // namespace manager_certs
