/*
 * Wazuh manager certs tool - commands
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MANAGER_CERTS_COMMANDS_HPP
#define _MANAGER_CERTS_COMMANDS_HPP

/**
 * @file commands.hpp
 * @brief `inspect` and `check`: the two read-only commands of `wazuh-manager-certs` (issue #39319).
 *
 * Pure functions over an already-parsed bundle and the leaf certificate `main.cpp` read from disk:
 * no file reads, no configuration, no writes. That split is what lets the unit tests exercise both
 * commands in process, over throwaway PKI, without a compiled binary or a filesystem fixture for
 * every case -- `main.cpp` is the only piece that opens a file, and it does that once per run,
 * before either of these runs (`02-diseno.md` §2.6, C27).
 */

#include <ca_bundle/ca_bundle.hpp>

#include <cstddef>
#include <ostream>

namespace manager_certs
{
    /**
     * @brief Prints @p bundle's certificates and publication status to @p out, human-readable.
     *
     * One row per certificate: subject, issuer, `notAfter`, days remaining (may be negative, for an
     * already-expired certificate), identity (`ca_bundle::identityOf()`) and whether it signs
     * @p leaf. Then the bundle's own line: its publication block's `publication` field verbatim
     * when the bundle carries one (whatever it claims, even if some other guard would refuse it),
     * or `0 (unpublished)` when it carries none (a plain PEM, or one whose block did not parse) --
     * and, separately, `vouched: yes`/`vouched: no` from `ca_bundle::vouch()` against @p leaf and
     * @p bundle's own serialised size, which is the same verdict `check` reports.
     *
     * Never fails: an empty or unparsed bundle prints as zero certificates and `vouched: no`. The
     * return value is always 0, kept as `int` (rather than `void`) so `main.cpp` can dispatch every
     * command through one function-pointer shape (`runCheck()` is the one that can return 1).
     *
     * @p leaf may be null (leaf unreadable) -- `signsLeaf` reads false for every certificate then,
     * same as `ca_bundle::describe()`/`anyCaSignsLeaf()` with a null leaf.
     */
    int runInspect(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::ostream& out);

    /**
     * @brief Whether @p bundle may be vouched for as @p leaf's trust anchor, without writing
     *        anything (RF-12).
     *
     * Two guard groups, evaluated in order, stopping at the first failure of either:
     *
     * 1. `ca_bundle::vouch(bundle, leaf, serializedBytes)`'s own six guards (structure, the
     *    publication hash, leaf-signing, the two size caps). On failure, writes one line to @p err
     *    naming that guard -- `too_many_certificates` and `too_many_bytes` name the observed
     *    count/bytes against the limit (e.g. "7 certificates (max 6)", "8588 bytes (max 8191)"),
     *    the others name the failure in words (e.g. "no CA signs the served leaf").
     * 2. Only once (1) passes: every certificate of @p bundle, in order, must be a CA (`isCa`) and
     *    inside its validity window (`notBefore <= now <= notAfter`) -- properties
     *    `ca_bundle::vouch()` does not evaluate on its own (02-diseno.md §2.6). On the first
     *    certificate that fails either, writes one line to @p err naming it by
     *    `ca_bundle::identityOf()` and the concrete reason: "not a CA", "not yet valid (notBefore
     *    ...)" or "expired (notAfter ...)".
     *
     * Returns 0 and writes nothing only when every guard of both groups passes.
     *
     * @p serializedBytes is what the caller would actually hand out for @p bundle (i.e.
     * `ca_bundle::serializeCertificates(bundle.certificates).size()`), the same quantity
     * `too_many_bytes` is evaluated against.
     *
     * Never returns 2: an unreadable configuration, a missing bundle or a missing leaf are
     * environment problems `main.cpp` catches before either command runs.
     */
    int
    runCheck(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::size_t serializedBytes, std::ostream& err);

} // namespace manager_certs

#endif // _MANAGER_CERTS_COMMANDS_HPP
