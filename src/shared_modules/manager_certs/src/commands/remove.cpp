/*
 * Wazuh manager certs tool - `remove`
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
        /// A reference of our own on @p certificate, so the candidate can hold the same object the
        /// bundle still owns. The same five lines as add.cpp's own retain(): no translation unit
        /// here may reach into another's anonymous namespace, and a fourth private header carrying
        /// one X509_up_ref() would be more surface than the repetition costs (the same call
        /// check.cpp and add.cpp already make of asn1TimeConverts()).
        ca_bundle::X509Ptr retain(X509* certificate)
        {
            if (certificate == nullptr || X509_up_ref(certificate) != 1)
            {
                return {};
            }
            return ca_bundle::X509Ptr {certificate};
        }
    } // namespace

    int runRemove(WriteContext& context, const std::string& identity, std::ostream& out, std::ostream& err)
    {
        const auto refuse = [&err](int code, const std::string& text)
        {
            err << "wazuh-manager-certs: remove: " << text << '\n';
            return code;
        };

        // An empty identity is never a certificate's: ca_bundle::identityOf() returns one only for
        // a certificate it could not encode at all, and matching THOSE is not what an operator who
        // typed an empty argument meant.
        if (identity.empty())
        {
            return refuse(1, "no identity given; pass the identity 'inspect' prints for the certificate");
        }

        // EVERY occurrence, not the first (C34d, objection 7): a bundle that somehow carries the
        // same CA twice -- two operators adding it through different paths, a hand-edited file --
        // must come out of `remove` without it at all. Removing one copy would leave the anchor
        // published while the operator was told it was gone, which is the whole point of the
        // command.
        std::vector<ca_bundle::X509Ptr> candidate;
        candidate.reserve(context.bundle.certificates.size());
        std::size_t removed {0};
        for (const auto& certificate : context.bundle.certificates)
        {
            if (ca_bundle::identityOf(certificate.get()) == identity)
            {
                ++removed;
                continue;
            }
            candidate.push_back(retain(certificate.get()));
        }

        if (removed == 0)
        {
            // Nothing to do, and nothing published: re-stamping a bundle the operator asked to
            // change would raise the generation for a change that never happened.
            return refuse(1, "identity " + identity + " not found in bundle");
        }

        // No time-sensitive guard of its own: `remove` adds no certificate, so the only thing that
        // can change during the wait of C28b is whether the REST still chains to the leaf, and
        // finishWrite() re-evaluates that itself (G6, second pass).
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
        out << "removed " << removed << " certificate(s); published generation " << outcome.publication << '\n';
        return 0;
    }

} // namespace manager_certs
