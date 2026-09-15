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

#ifndef _HC_TLS_CERT_DIAGNOSTICS_HPP
#define _HC_TLS_CERT_DIAGNOSTICS_HPP

#include <openssl/x509.h>

#include <string>
#include <vector>

/**
 * @brief Why a completed handshake's certificate verification failed, once
 *        TransportStatus::TlsFail has been narrowed further.
 *
 * Kept low-cardinality, the same discipline as SpkiPinError (spkiPin.hpp):
 * each value drives exactly one distinct, greppable log line at normal level
 * -- a chain/CA-trust problem must not read like a hostname mismatch, and
 * neither must read like a certificate-date failure (#39062 objective
 * requirement 6 and its notBefore/notAfter counterpart).
 */
enum class TlsFailureKind
{
    None,             ///< Not one of the two causes below. An ordinary chain/CA-trust
    ///< failure (untrusted root, wrong issuer, ...) stays a generic
    ///< TlsFail, unchanged -- this module classifies only the two
    ///< causes the issue calls out by name.
    HostnameMismatch, ///< The chain and every certificate's validity period verified;
    ///< the dialed name is not on the certificate.
    CertNotYetValid,  ///< The leaf certificate's notBefore is still in the future.
    CertExpired       ///< The leaf certificate's notAfter is already in the past.
};

/**
 * @brief The classified cause plus what an operator needs to act on it.
 *
 * Everything here is a plain string extracted from the leaf certificate
 * WHILE it was live inside the OpenSSL verify callback (curlHandle.cpp) --
 * an X509* from X509_STORE_CTX_get_current_cert() does not outlive that one
 * call, so nothing in this module ever retains a certificate pointer.
 */
struct TlsFailureDetail
{
    TlsFailureKind kind {TlsFailureKind::None};

    /// The leaf's subject alternative names, OpenSSL-formatted ("DNS:manager.example.com",
    /// "IP Address:10.0.0.1") -- see tlsCertSanNames(). Empty when the certificate carries
    /// no SAN extension at all, which is itself worth showing as-is rather than papering
    /// over: a certificate with nothing to compare a hostname against.
    std::vector<std::string> certNames;

    /// Human-readable notBefore ("openssl x509 -noout -dates" wording), populated
    /// whenever the leaf was captured -- both date kinds and HostnameMismatch alike --
    /// so a hostname-mismatch log line can be extended later without re-deriving this.
    std::string notBefore;
    /// As notBefore, for the leaf's notAfter.
    std::string notAfter;
};

/**
 * @brief The leaf certificate's subject alternative names, OpenSSL-formatted.
 *
 * Only dNSName and iPAddress entries are named: RFC 6125 has a TLS client
 * compare a dialed identity against exactly those two SAN types, so a
 * directoryName/URI/email/other entry names nobody a hostname check would
 * ever match against and is skipped rather than padding the list.
 *
 * @return Empty when @p certificate is null, carries no SAN extension, or
 *         the extension fails to parse -- none of which are errors worth
 *         surfacing on their own; the caller decides what an empty list means.
 */
std::vector<std::string> tlsCertSanNames(X509* certificate);

/// @p time formatted like "openssl x509 -noout -dates" ("Sep 15 00:00:00 2026 GMT"),
/// or empty when @p time is null or fails to print.
std::string tlsCertTimeString(const ASN1_TIME* time);

/**
 * @brief Narrows an OpenSSL chain-verification outcome into the two causes
 *        this module gives their own log line.
 *
 * Deliberately does NOT run a second, independent hostname or date check:
 * the classification below reads only facts OpenSSL/libcurl already
 * computed while making their own accept/reject decision. Re-implementing
 * that decision here, even just to classify an already-failed attempt,
 * would risk a second verifier one day disagreeing with the first --
 * remoted's tlsCertificateStatus.cpp takes the same stance for its own SAN
 * inspection, which exists to REPORT on a certificate, never to gate a
 * connection.
 *
 * @param sawDepth0 Whether the verify callback actually observed the leaf
 *        (depth 0) certificate during this attempt. False when the
 *        connection never reached a certificate at all (a pure transport
 *        failure, or verify_mode=none skipping verification entirely) -- in
 *        which case @p depth0Error is meaningless and this always returns
 *        None.
 * @param depth0Error The X509_V_ERR_* OpenSSL held at the leaf's own verify-callback
 *        invocation: whatever error occurred anywhere in the chain (propagated down
 *        to depth 0 if unresolved), or X509_V_OK if the chain and every certificate's
 *        own validity period verified cleanly.
 * @param peerVerificationFailed Whether libcurl's overall CURLcode for this attempt was
 *        CURLE_PEER_FAILED_VERIFICATION -- the one code both an OpenSSL chain/date
 *        failure AND libcurl's own separate post-handshake hostname check can produce,
 *        so it alone cannot tell them apart.
 * @return CertNotYetValid/CertExpired when @p depth0Error names that error directly.
 *         HostnameMismatch either directly (X509_V_ERR_HOSTNAME_MISMATCH /
 *         X509_V_ERR_IP_ADDRESS_MISMATCH, when this curl/OpenSSL combination routes its
 *         hostname check through the verify callback) or, when it does not, by
 *         elimination: the chain and every certificate's validity period verified
 *         (depth0Error == X509_V_OK) yet libcurl still failed peer verification, which
 *         with SSL_VERIFYHOST always enabled here (curlPerformer.cpp::applyTls, for
 *         both HC_VERIFY_FULL and HC_VERIFY_SYSTEM) leaves libcurl's own hostname check
 *         as the only remaining explanation. None otherwise -- an ordinary chain/CA-trust
 *         failure, unchanged from today's generic TlsFail.
 */
TlsFailureKind classifyTlsVerifyFailure(bool sawDepth0, int depth0Error, bool peerVerificationFailed);

#endif // _HC_TLS_CERT_DIAGNOSTICS_HPP
