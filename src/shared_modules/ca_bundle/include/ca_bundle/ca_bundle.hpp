/*
 * Wazuh CA bundle library
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CA_BUNDLE_HPP
#define _CA_BUNDLE_HPP

/**
 * @file ca_bundle.hpp
 * @brief The CA bundle (`etc/certs/root-ca.pem`) as a value: its certificates, its publication
 *        block, and the guards that decide whether it may be vouched for.
 *
 * One library so the manager and the `wazuh-manager-certs` tool answer the questions about that
 * file with the same code instead of two implementations that drift: what certificates does it
 * carry, what content do they hash to, does the certificate the listener serves CHAIN to any of
 * them, and was it stamped by the tool. Extracted from remoted's tlsCertificateStatus.{hpp,cpp},
 * which had every one of these but the block (issue #39319).
 *
 * Pure functions over bytes and X509 objects: no file reads, no logging, no configuration. The
 * caller reads the file (remoted through its bounded, injectable reader), decides what to do with
 * the verdict, and -- only in the tool -- writes it back.
 *
 * Only <openssl/types.h> is pulled in here, so X509 stays an incomplete type for this header's
 * includers and the OpenSSL API does not leak into every consumer.
 */

#include <openssl/types.h>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ca_bundle
{
    /// Deleter kept out of line so X509 can stay incomplete for the header's includers.
    struct X509Deleter
    {
        void operator()(X509* certificate) const noexcept;
    };

    /// Owning X509 handle.
    using X509Ptr = std::unique_ptr<X509, X509Deleter>;

    /**
     * @brief The publication block `wazuh-manager-certs` stamps into the bundle, as `##` comment
     *        lines -- the only writer there is.
     *
     * `publication` is the Unix timestamp the tool assigned (the generation an agent is told
     * about); `contentSha256` is contentSha256() over the certificates the block describes, which
     * is what makes the stamp non-transferable between bundles; `updated` is the RFC 3339 time of
     * the write and `writtenBy` names the writer. The last two are for the operator reading the
     * file: nothing is decided from them.
     */
    struct PublicationBlock
    {
        std::int64_t publication {0};
        std::string contentSha256;
        std::string updated;
        std::string writtenBy;
    };

    /**
     * @brief Outcome of parsing bundle bytes: the certificates found, whether the input ended
     *        cleanly, and the publication block if the document carries one.
     *
     * `wellFormed` is false when the reader stopped on something it could not decode instead of at
     * end of input. The distinction matters for what we publish: a file we do not fully understand
     * is refused whole rather than served up to its first bad block (issue #39078, H01), so a
     * document that is not well formed comes back with no certificates at all.
     *
     * `block` absent means "not published" -- an ordinary CA file, the state every bundle is in
     * before the tool ever stamps it -- which is a different thing from a bundle whose block does
     * not describe its certificates. vouch() keeps them apart.
     */
    struct ParsedBundle
    {
        std::vector<X509Ptr> certificates;
        bool wellFormed {false};
        std::optional<PublicationBlock> block;
    };

    /**
     * @brief Read every CERTIFICATE block, and the publication block, out of PEM bytes in memory.
     *
     * Non-certificate blocks (a key, a CRL) are skipped by OpenSSL's PEM reader, so a bundle or a
     * combined file yields exactly its certificates -- and, because the caller serialises these
     * objects back instead of forwarding the bytes, nothing else can ever leave through them.
     *
     * The publication block is looked for in ANY position: before the certificates, between two of
     * them or after the last one, because `##` lines are comments to every PEM reader and an
     * operator may have appended a certificate after the stamp. The first complete block wins; a
     * `##` line that does not begin one is a comment like any other. An empty document is well
     * formed and carries nothing.
     */
    ParsedBundle parseBundle(std::string_view pem);

    /**
     * @brief PEM text containing @p certificates and nothing else.
     *
     * What `GET /cacerts` and the tool publish: a document this process built from parsed X.509
     * objects, not a file it forwarded. Certificates come out in the order given. Empty when any
     * of them cannot be serialised -- a partial document is never worth publishing.
     */
    std::string serializeCertificates(const std::vector<X509Ptr>& certificates);

    /**
     * @brief Hex SHA-256 of what @p certificates ARE, independent of how they were written down.
     *
     * The DER encoding of each certificate, sorted by those bytes, concatenated, hashed: two
     * bundles that carry the same certificates in another order, with other line wrapping or with
     * comments in between hash the same, and changing one byte of one certificate changes the hash
     * (RF-1). That is what lets the publication block be checked against the certificates it
     * claims to describe, and what makes re-stamping an unchanged bundle a no-op.
     *
     * Lowercase hex. Empty when a certificate cannot be encoded, which no block can ever match.
     */
    std::string contentSha256(const std::vector<X509Ptr>& certificates);

    /**
     * @brief `"x509-sha256:<hex>"` -- SHA-256 of @p certificate's DER encoding, for logs, registry
     *        entries and the tool's `inspect` output.
     *
     * The same string an operator gets from `openssl x509 -outform der | sha256sum`, prefixed with
     * the algorithm so a future one can be told apart. Empty for a null certificate.
     */
    std::string identityOf(const X509* certificate);

    /**
     * @brief Whether @p leaf CHAINS to one of @p cas: a real validation (`X509_STORE` with the
     *        bundle as its trust anchors, `X509_STORE_CTX`, `X509_verify_cert()`), not a signature
     *        check.
     *
     * The question `GET /cacerts` and the publication need answered is "would the PEM I am about to
     * hand out let an agent trust the certificate I am serving", and only a chain validation answers
     * it. A signature check does not: a certificate carrying the SAME public key under ANOTHER
     * subject verifies the leaf's signature while the leaf names the other one as its issuer, so it
     * never chains and no agent can use it -- and remoted would have announced it as published all
     * the same (issue #39319, C33).
     *
     * Verified with OpenSSL's DEFAULT flags -- deliberately WITHOUT `X509_V_FLAG_PARTIAL_CHAIN`, so
     * a trust anchor has to be a self-signed root. That is how the OpenSSL of an agent that
     * bootstrapped from this bundle verifies: with no trust settings of its own, only a self-signed
     * certificate of its CA file is trusted, so a bundle holding just a (non-self-signed)
     * intermediate would fail that agent's handshake and must not be announced as publishable here.
     * A self-signed leaf listed as its own CA still chains: it is its own anchor, at depth 0.
     *
     * Default flags also mean the validity WINDOW and `basicConstraints` of everything on the path
     * are checked, which is a behaviour change from the signature check this replaced: an EXPIRED
     * CA, a not-yet-valid one and a signer without `CA:TRUE` no longer count, and neither does a
     * bundle whose served leaf has itself expired. All of them are anchors an agent could not use,
     * so the stricter answer is the correct one -- but a bundle that was publishable yesterday can
     * stop being publishable today with no file having changed.
     *
     * What this does NOT check is the certificate's PURPOSE (`serverAuth` EKU): remoted's
     * chainValidates() is the operator-facing verdict that adds it, and relaxes the anchor rule with
     * `X509_V_FLAG_PARTIAL_CHAIN` at the same time, so neither verdict subsumes the other.
     * describe()'s `signsLeaf` stays the plain signature fact, for the tool's diagnostics.
     */
    bool leafChainsToAnyCa(const X509* leaf, const std::vector<X509Ptr>& cas);

    /// How many certificates a bundle may carry to be vouched for (spike #39277, D5).
    constexpr std::size_t kMaxCertificates = 6;

    /// How many bytes the serialised bundle may take to be vouched for (spike #39277, D5).
    constexpr std::size_t kMaxSerializedBytes = 8191;

    /// Why vouch() refused, in the order it evaluates them. `none` means it did not.
    ///
    /// `no_ca_signs_leaf` keeps its name from when the guard was a signature check: what it means
    /// since C33 is leafChainsToAnyCa()'s answer -- the served leaf does not CHAIN to any CA of the
    /// bundle -- which also covers an expired or non-CA signer. The spelling is what callers'
    /// switches, logs and exit codes are written against, so it was not renamed with the function.
    enum class GuardFailure
    {
        none,
        no_certificates,
        no_block,
        hash_mismatch,
        no_ca_signs_leaf,
        too_many_certificates,
        too_many_bytes
    };

    /// vouch()'s verdict: the publication to tell agents about, or 0 and the guard that refused.
    struct Vouch
    {
        std::int64_t publication {0};
        GuardFailure failure {GuardFailure::none};
    };

    /**
     * @brief Whether this bundle may be published as @p leaf's trust anchor, and under which
     *        generation (RF-2).
     *
     * Evaluates in this order and stops at the first guard that fails: `no_certificates` →
     * `no_block` → `hash_mismatch` (the block's hash against contentSha256() of the certificates
     * parsed) → `no_ca_signs_leaf` (leafChainsToAnyCa(); with @p leaf null the guard FAILS -- with
     * no served certificate to check against, nothing is vouched for) → `too_many_certificates` →
     * `too_many_bytes` (@p serializedBytes, what the caller would actually hand out).
     *
     * Only a bundle that passes all of them gets its block's publication; anything else is 0 plus
     * the cause, and 0 is what an agent reads as "this manager has no published bundle". The
     * `no_block` case is the one that means "not published yet" rather than "broken", which is
     * what separates an INFO from a WARN in the caller's logs.
     */
    Vouch vouch(const ParsedBundle& bundle, const X509* leaf, std::size_t serializedBytes);

    /**
     * @brief The block's eight `##` lines, ready to be written above the certificates.
     *
     * Only `wazuh-manager-certs` writes these: neither remoted nor any other daemon stamps a
     * bundle (RF-8). Round-trips through parseBundle().
     */
    std::string renderBlock(const PublicationBlock& block);

    /// What describe() found about one certificate of a bundle.
    struct CertificateFacts
    {
        std::string subject;
        std::string issuer;
        std::string identity;
        std::time_t notBefore {0};
        std::time_t notAfter {0};
        bool isCa {false};
        bool signsLeaf {false};
    };

    /**
     * @brief The facts an operator needs about @p certificate, for the tool's inspect/check/add.
     *
     * `signsLeaf` is the plain SIGNATURE fact for this certificate alone (`X509_verify` against its
     * public key), so a bundle's facts say which of its CAs holds the listener's signature up. It
     * is deliberately NOT leafChainsToAnyCa()'s question: a certificate can sign the leaf and not
     * be an anchor it chains to (another subject, an expired window, no `CA:TRUE`), and telling an
     * operator those two apart is the whole value of the tool's `inspect`/`check` output. Null
     * @p leaf leaves it false. Dates are UTC seconds since the epoch, negative for a
     * date before 1970 -- kept as-is, never clamped -- and 0 only when the underlying ASN.1 time
     * could not be converted at all, not as a stand-in for "before 1970" or "midnight 1970-01-01".
     * A null @p certificate gives default-constructed facts.
     */
    CertificateFacts describe(const X509* certificate, const X509* leaf);

} // namespace ca_bundle

#endif // _CA_BUNDLE_HPP
