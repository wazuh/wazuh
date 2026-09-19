/*
 * Wazuh manager certs tool - `prune-expired`
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

#include <openssl/x509.h>

#include <cstddef>
#include <ctime>
#include <string>
#include <vector>

namespace manager_certs
{
    namespace
    {
        /// A reference of our own on @p certificate (see remove.cpp's copy for why it is not
        /// shared).
        ca_bundle::X509Ptr retain(X509* certificate)
        {
            if (certificate == nullptr || X509_up_ref(certificate) != 1)
            {
                return {};
            }
            return ca_bundle::X509Ptr {certificate};
        }
    } // namespace

    int runPruneExpired(WriteContext& context, std::ostream& out, std::ostream& err)
    {
        const auto refuse = [&err](int code, const std::string& text)
        {
            err << "wazuh-manager-certs: prune-expired: " << text << '\n';
            return code;
        };

        const std::time_t now = context.time.now ? context.time.now() : std::time(nullptr);

        // What stays: everything whose notAfter has not passed. A certificate whose ASN.1 dates do
        // not convert at all reads as notAfter == 0 (ca_bundle::describe()), so it is pruned like
        // any other expired one -- which is the right answer for this command: a date nothing can
        // read is not an anchor any agent's OpenSSL will accept either.
        std::vector<ca_bundle::X509Ptr> candidate;
        candidate.reserve(context.bundle.certificates.size());
        std::size_t pruned {0};
        for (const auto& certificate : context.bundle.certificates)
        {
            const ca_bundle::CertificateFacts facts = ca_bundle::describe(certificate.get(), nullptr);
            if (facts.notAfter < now)
            {
                ++pruned;
                continue;
            }
            candidate.push_back(retain(certificate.get()));
        }

        if (pruned == 0)
        {
            // C35: nothing expired, so nothing is written and NOTHING is published. Publishing an
            // unchanged bundle under a new generation would send every agent in the fleet back to
            // `GET /cacerts` for bytes they already have -- every night, if this runs from cron.
            //
            // C36i: but silence here would leave an operator believing the bundle is published when
            // it may not be. The same verdict `check` and `GET /cacerts` reach, over the bundle as
            // it is on disk right now: unsealed (a plain PEM), or stamped with a Content-SHA256
            // that no longer describes its certificates, and the tool says so instead of exiting 0
            // without a word. It still writes nothing -- `stamp` is the command that fixes it.
            const std::size_t serializedBytes = ca_bundle::serializeCertificates(context.bundle.certificates).size();
            const ca_bundle::Vouch vouch = ca_bundle::vouch(context.bundle, context.leaf, serializedBytes);
            if (vouch.failure != ca_bundle::GuardFailure::none || vouch.publication != context.previousPublication)
            {
                err << "wazuh-manager-certs: prune-expired: bundle is not vouched; run 'stamp' to publish it\n";
            }
            out << "nothing to prune\n";
            return 0;
        }

        // Like `remove`: no guard of its own to re-evaluate after the wait of C28b. A certificate
        // that expires during that second is one this run will not have pruned, which costs the
        // next run one more pass -- while the guard that DOES matter for the invariant (a CA still
        // chains to the leaf) is re-checked by finishWrite() itself.
        const WriteOutcome outcome = finishWrite(context, std::move(candidate));
        if (outcome.exitCode != 0)
        {
            err << "wazuh-manager-certs: " << outcome.message << '\n';
            return outcome.exitCode;
        }

        if (outcome.durabilityUnknown)
        {
            err << "wazuh-manager-certs: " << outcome.message << '\n';
        }
        out << "pruned " << pruned << " certificate(s); published generation " << outcome.publication << '\n';
        return 0;
    }

} // namespace manager_certs
