/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_SPKI_PIN_HPP
#define _HC_SPKI_PIN_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief SHA-256 of a certificate's SubjectPublicKeyInfo -- the enrollment
 *        token's `pin` (RFC 7469 section 2.4).
 *
 * The digest is over the SPKI, NOT over the certificate: an SPKI digest
 * survives the CA certificate being re-encoded, cross-signed or reissued
 * from the same key pair, so a token minted today keeps working through a CA
 * renewal that keeps the key. A whole-certificate digest does not.
 *
 * This is the pin-compare half of the bootstrap CacertsClient deliberately
 * leaves to someone else (see cacertsClient.hpp): that class fetches
 * /cacerts unverified and hands the body back without judging it; this one
 * turns a PEM into a digest and compares it to a token's pin.
 *
 * SCOPE, so the boundary is not mistaken for more than it is: computing a
 * digest proves nothing on its own. These functions cannot tell whether a
 * given PEM *is* the CA that signs the manager's certificate -- only that
 * its public key hashes to a particular value. Establishing trust means
 * installing the pin-matched certificate as the SOLE anchor and running path
 * validation against it on a NEW connection, which is the caller's job.
 *
 * Nothing here throws, and nothing here leaves anything on the thread's
 * OpenSSL error queue (a real libcurl request runs immediately before these
 * calls in the bootstrap flow, and would trip over the residue).
 */

/// 32 bytes of SHA-256.
constexpr std::size_t SPKI_PIN_BYTES {32};
/// Unpadded URL-safe base64 of 32 bytes is exactly 43 characters.
constexpr std::size_t SPKI_PIN_B64_CHARS {43};
/// Lowercase hex of 32 bytes is exactly 64 characters.
constexpr std::size_t SPKI_PIN_HEX_CHARS {64};

using SpkiDigest = std::array<std::uint8_t, SPKI_PIN_BYTES>;

/// Why an SPKI digest could not be produced. Kept low-cardinality because
/// each value feeds a distinct agent log line: "the manager answered with an
/// HTML error page" must not read like "this CA uses a key type we cannot
/// parse". The bootstrap's own three abort causes (unreachable, /cacerts
/// errored, pin mismatch) are a layer above this and are the caller's to
/// distinguish.
enum class SpkiPinError
{
    None,
    NoCertificate,  ///< Empty input, unreadable file, or no CERTIFICATE PEM block at all.
    BadCertificate, ///< A CERTIFICATE block is present but does not parse as X.509.
    UnsupportedKey, ///< Parses, but the public key cannot be re-encoded as SubjectPublicKeyInfo.
    Internal,       ///< Allocation or EVP failure. Not reproducible in tests.
};

/**
 * @brief SHA-256 over the DER SubjectPublicKeyInfo of the FIRST certificate
 *        in @p pem.
 *
 * A PEM bundle is accepted and only its first certificate is hashed; use
 * spkiSha256AllFromPem() when the whole bundle matters. Text before, between
 * and after PEM blocks is skipped, and a non-CERTIFICATE block (a private
 * key, say) is stepped over rather than rejected.
 *
 * @param pem PEM text, with an EXPLICIT length. Callers crossing the C
 *        boundary must build this view with
 *        strnlen(result.body, HC_MAX_CACERTS_BODY), since
 *        hc_cacerts_result_t::body is a fixed char[] with no length field.
 *        Necessary but not sufficient: OpenSSL's PEM scanner stops at a NUL
 *        byte whatever length it was handed, so a body carrying one mid-bundle
 *        yields only the certificates before it. A legitimate PEM never
 *        contains a NUL, so a caller that pins should reject such a body
 *        outright rather than trust what parsed first.
 * @param error When non-null, always written -- SpkiPinError::None on success.
 * @return The digest, or nullopt on any failure.
 */
std::optional<SpkiDigest> spkiSha256FromPem(std::string_view pem, SpkiPinError* error = nullptr);

/**
 * @brief SHA-256 over the SubjectPublicKeyInfo of EVERY certificate in a PEM
 *        bundle, in the order they appear.
 *
 * The manager may serve a bundle rather than a bare root -- the transport
 * buffer is explicitly "sized for a small chain (leaf + one intermediate)"
 * (HC_MAX_CACERTS_BODY) -- so a caller that pins must be able to see all of
 * them rather than silently taking the first and reporting a mismatch that
 * looks like an attack.
 *
 * @param error When non-null, always written. NoCertificate when the bundle
 *        holds none; BadCertificate when a block is present but unparseable.
 * @return One digest per certificate; empty on failure.
 */
std::vector<SpkiDigest> spkiSha256AllFromPem(std::string_view pem, SpkiPinError* error = nullptr);

/// As spkiSha256FromPem(), over a single DER-encoded certificate.
/// A null pointer or zero length is NoCertificate, not a crash.
std::optional<SpkiDigest> spkiSha256FromDer(const void* der, std::size_t length,
                                            SpkiPinError* error = nullptr);

/// As spkiSha256FromPem(), reading the PEM from a file. An unreadable or
/// missing path is NoCertificate. Mirrors digest.hpp's sha256FileHex().
std::optional<SpkiDigest> spkiSha256FromPemFile(const std::string& path, SpkiPinError* error = nullptr);

/// 64 lowercase hex characters. The diagnostic form: comparable against
/// `openssl dgst -sha256` output by eye, and what --show-token prints.
std::string spkiPinHex(const SpkiDigest& digest);

/// 43 characters of unpadded URL-safe base64. The wire form: this is exactly
/// what the enrollment token's `pin` field carries.
std::string spkiPinBase64Url(const SpkiDigest& digest);

/// Outcome of checking a computed digest against a token's `pin`.
enum class SpkiPinMatch
{
    Match,        ///< The pin names this key.
    Mismatch,     ///< Well-formed pin, different key. A pinning failure -- possibly an attack.
    MalformedPin, ///< Not 43 canonical base64url characters. A token-format failure.
};

/**
 * @brief Constant-time comparison of @p digest against a token's @p pin.
 *
 * Mismatch and MalformedPin are deliberately separate: the first means "this
 * is not my manager" and deserves a loud, distinct log line; the second means
 * "this is not a valid token" and is an operator error, not an attack.
 *
 * Stricter than the installer's shell decoder, which accepts non-canonical
 * trailing bits and does not check the pin's length at all. That asymmetry is
 * intentional -- this is the layer that must fail closed -- but it means a
 * token accepted at install time can still be refused here.
 *
 * NOTHING COMPARED HERE IS SECRET. Both the digest and the pin are public
 * values (the pin ships in a token the agent holds; the certificate is
 * published). The constant-time compare is a hygiene requirement, not a
 * side-channel mitigation -- which is why it is fine that the canonicality
 * gate below is data-dependent. Do not "fix" that.
 */
SpkiPinMatch spkiPinCompare(const SpkiDigest& digest, std::string_view pin);

#endif // _HC_SPKI_PIN_HPP
