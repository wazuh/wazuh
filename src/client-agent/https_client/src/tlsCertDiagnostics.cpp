/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 15, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "tlsCertDiagnostics.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <cstddef>
#include <memory>

namespace
{
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>;
} // namespace

std::vector<std::string> tlsCertSanNames(X509* certificate)
{
    std::vector<std::string> names;

    if (certificate == nullptr)
    {
        return names;
    }

    // Leaves the thread's OpenSSL error queue exactly as it was found, same discipline as
    // spkiPin.cpp: this runs immediately after a failed handshake, and residue here would
    // surface as a baffling second error in unrelated code.
    ERR_set_mark();

    GeneralNamesPtr sanList {static_cast<GENERAL_NAMES*>(
                                 X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)),
                             GENERAL_NAMES_free};

    if (!sanList)
    {
        // No SAN extension at all, or one that failed to parse: neither is an error this
        // function reports -- an empty list already says "nothing to compare against".
        ERR_pop_to_mark();
        return names;
    }

    const BioPtr scratch {BIO_new(BIO_s_mem()), BIO_free};

    if (!scratch)
    {
        ERR_pop_to_mark();
        return names; // LCOV_EXCL_LINE: allocation failure only.
    }

    const int count = sk_GENERAL_NAME_num(sanList.get());

    for (int index = 0; index < count; ++index)
    {
        const GENERAL_NAME* entry = sk_GENERAL_NAME_value(sanList.get(), index);

        if (entry == nullptr || (entry->type != GEN_DNS && entry->type != GEN_IPADD))
        {
            // Only the two types a TLS client ever matches an identity against (RFC 6125):
            // a directoryName/URI/email/other entry names nobody a hostname check would
            // compare against, so it is skipped rather than padding the list.
            continue;
        }

        // GENERAL_NAME_print writes exactly what every other OpenSSL tool does
        // ("DNS:foo.example.com", "IP Address:10.0.0.1"): re-deriving that formatting by
        // hand would drift the moment OpenSSL's own wording does.
        if (GENERAL_NAME_print(scratch.get(), const_cast<GENERAL_NAME*>(entry)) <= 0)
        {
            ERR_clear_error();
            continue; // LCOV_EXCL_LINE: GENERAL_NAME_print failing on a parsed entry is not reproducible.
        }

        char* data = nullptr;
        const long length = BIO_get_mem_data(scratch.get(), &data);

        if (length > 0 && data != nullptr)
        {
            names.emplace_back(data, static_cast<std::size_t>(length));
        }

        // Clears the mem BIO's buffer without freeing it, so scratch is reused for the
        // next entry rather than reallocated per SAN.
        (void)BIO_reset(scratch.get());
    }

    ERR_pop_to_mark();
    return names;
}

std::string tlsCertTimeString(const ASN1_TIME* time)
{
    if (time == nullptr)
    {
        return {};
    }

    ERR_set_mark();

    const BioPtr bio {BIO_new(BIO_s_mem()), BIO_free};

    if (!bio || ASN1_TIME_print(bio.get(), time) <= 0)
    {
        ERR_pop_to_mark();
        return {}; // LCOV_EXCL_LINE: a malformed ASN1_TIME on an already-parsed certificate is not reproducible.
    }

    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    ERR_pop_to_mark();
    return (length > 0 && data != nullptr) ? std::string(data, static_cast<std::size_t>(length)) : std::string();
}

TlsFailureKind classifyTlsVerifyFailure(bool sawDepth0, int depth0Error, bool peerVerificationFailed)
{
    if (!sawDepth0)
    {
        return TlsFailureKind::None;
    }

    if (depth0Error == X509_V_ERR_CERT_NOT_YET_VALID)
    {
        return TlsFailureKind::CertNotYetValid;
    }

    if (depth0Error == X509_V_ERR_CERT_HAS_EXPIRED)
    {
        return TlsFailureKind::CertExpired;
    }

    if (depth0Error == X509_V_ERR_HOSTNAME_MISMATCH || depth0Error == X509_V_ERR_IP_ADDRESS_MISMATCH)
    {
        return TlsFailureKind::HostnameMismatch;
    }

    // The chain and every certificate's own validity period verified, yet libcurl still
    // failed peer verification: with SSL_VERIFYHOST enabled (curlPerformer.cpp::applyTls,
    // always on for HC_VERIFY_FULL/HC_VERIFY_SYSTEM), the only remaining check that can
    // produce CURLE_PEER_FAILED_VERIFICATION after a clean chain is libcurl's own
    // post-handshake hostname comparison -- reached by curl/OpenSSL combinations that do
    // not route that check through the verify callback above (the direct
    // X509_V_ERR_HOSTNAME_MISMATCH case just above covers the ones that do).
    if (depth0Error == X509_V_OK && peerVerificationFailed)
    {
        return TlsFailureKind::HostnameMismatch;
    }

    return TlsFailureKind::None;
}
