/*
 * Wazuh manager certs tool - `stamp`
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

    int runStamp(WriteContext& context, std::ostream& out, std::ostream& err)
    {
        // The candidate IS what the bundle already holds: `stamp` changes no certificate, it gives
        // the file a publication block the whole fleet can compare generations with. That is why it
        // carries no guard of its own (C29): the only guards that apply are the structural ones
        // finishWrite() runs for every command -- at least one certificate, at most six, one of
        // them chaining to the served leaf, under the byte cap.
        //
        // In particular NOT vouch()'s `no_block`/`hash_mismatch`: a plain PEM that was never
        // stamped, and a bundle whose block no longer describes its certificates, are exactly the
        // two states this command exists to fix. Refusing them here would leave the operator with a
        // tool that only works once the problem is already solved -- and the block written below
        // satisfies both by construction.
        std::vector<ca_bundle::X509Ptr> candidate;
        candidate.reserve(context.bundle.certificates.size());
        for (const auto& certificate : context.bundle.certificates)
        {
            candidate.push_back(retain(certificate.get()));
        }
        const std::size_t certificates = candidate.size();

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
        out << "stamped " << certificates << " certificate(s); published generation " << outcome.publication << '\n';
        return 0;
    }

} // namespace manager_certs
