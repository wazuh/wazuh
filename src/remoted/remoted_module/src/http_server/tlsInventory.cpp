/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tlsInventory.hpp"

#include "json.hpp"

#include <cstdint>

namespace remoted::http
{
    namespace
    {
        // Keys come out in the order they are written: the document reads top-down like the
        // issue's example, and a `curl | jq` shows `listener` before `ca_bundle`.
        using Json = nlohmann::ordered_json;

        std::int64_t epochSeconds(std::chrono::system_clock::time_point instant)
        {
            return std::chrono::duration_cast<std::chrono::seconds>(instant.time_since_epoch()).count();
        }

        /// The fields every certificate of the document carries. `sans` only for the listener: a
        /// CA's names are not something an agent dials.
        Json describe(const CertificateDescriptor& certificate, std::int64_t now, bool withSubjectAltNames)
        {
            Json document;
            document["subject"] = certificate.subject;
            document["issuer"] = certificate.issuer;
            if (withSubjectAltNames)
            {
                document["sans"] = certificate.subjectAltNames;
            }
            document["not_before"] = rfc3339Utc(certificate.notBefore);
            document["not_before_ts"] = certificate.notBefore;
            document["not_after"] = rfc3339Utc(certificate.notAfter);
            document["not_after_ts"] = certificate.notAfter;
            document["seconds_until_expiry"] = certificate.notAfter - now;
            document["fingerprint"] = certificate.fingerprint;
            document["serial"] = certificate.serial;
            return document;
        }
    } // namespace

    std::string renderTlsInventory(const TlsInventory& inventory, std::chrono::system_clock::time_point now)
    {
        const auto nowSeconds = epochSeconds(now);

        Json document;
        document["evaluated_at"] = rfc3339Utc(nowSeconds);
        document["evaluated_at_ts"] = nowSeconds;

        if (inventory.listener.has_value())
        {
            Json listener = describe(inventory.listener->certificate, nowSeconds, /*withSubjectAltNames=*/true);
            listener["path"] = inventory.listener->certificatePath;
            const auto loadedAt = epochSeconds(inventory.listener->loadedAt);
            listener["loaded_at"] = rfc3339Utc(loadedAt);
            listener["loaded_at_ts"] = loadedAt;
            document["listener"] = std::move(listener);
        }

        const CaCertificateSnapshot& ca = inventory.ca;
        Json bundle;
        bundle["path"] = inventory.caCertificatePath;
        bundle["publication"] = ca.publication;
        bundle["publication_vouched"] = ca.publicationVouched;
        bundle["content_sha256"] = ca.contentSha256;
        bundle["certificates_count"] = ca.certificates;
        bundle["certificates_limit"] = CaCertificateSource::kMaxCertificates;
        bundle["serialized_bytes"] = ca.serializedBytes;
        bundle["serialized_bytes_limit"] = CaCertificateSource::kAgentBodyLimit;
        if (ca.chainValid.has_value())
        {
            bundle["chain_valid"] = *ca.chainValid;
            if (!*ca.chainValid)
            {
                bundle["chain_error"] = ca.chainError;
            }
        }
        else
        {
            bundle["chain_valid"] = nullptr;
        }

        Json certificates = Json::array();
        for (const auto& entry : ca.entries)
        {
            Json certificate = describe(entry.certificate, nowSeconds, /*withSubjectAltNames=*/false);
            certificate["signs_active_leaf"] = entry.signsLeaf;
            certificates.push_back(std::move(certificate));
        }
        bundle["certificates"] = std::move(certificates);

        if (ca.lastReadFailure.has_value())
        {
            const ReadFailure& failure = *ca.lastReadFailure;
            Json readFailure;
            readFailure["cause"] = describeReadFailure(failure, CaCertificateSource::kMaxBytes);
            readFailure["errno"] = failure.error;
            readFailure["consecutive"] = failure.consecutive;
            bundle["last_read_failure"] = std::move(readFailure);
        }

        document["ca_bundle"] = std::move(bundle);
        return document.dump();
    }
} // namespace remoted::http
