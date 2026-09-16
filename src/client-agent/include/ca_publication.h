/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file ca_publication.h
 * @brief The publication recorded alongside the agent's CA bundle.
 *
 * The manager stamps every version of its CA bundle with a publication: a monotonic 64-bit
 * integer (a Unix timestamp), advertised as `ca_generation` on every /control notify and
 * returned as the Wazuh-CA-Generation header with the bundle itself. The agent adopts a bundle
 * only in the direction of a higher publication, so it has to remember which one it is holding
 * across restarts -- without that it would either accept anything (a lagging node could walk it
 * back to an older bundle) or accept nothing (it could never update again).
 *
 * Recorded in the trust store itself rather than beside it, as explanatory text before the first
 * -----BEGIN CERTIFICATE-----, which RFC 7468 section 2 permits:
 *
 *     ## wazuh-ca-bundle
 *     ## generation: 1789000012
 *     -----BEGIN CERTIFICATE-----
 *     ...
 *
 * One file means one write, so the pair can never be torn: an install is a single atomic rename
 * and a crash leaves either the old bundle with its publication or the new bundle with its own,
 * never one of each. It also keeps the trust store a plain PEM -- OpenSSL's own readers skip
 * text before the first encapsulation boundary, so both w_x509_load_all_pem() and libcurl's
 * CURLOPT_CAINFO read such a file exactly as they read a bare bundle.
 *
 * This shape is the agent's own business: #39321 fixes what travels on the wire (the notify
 * field and the response header) and leaves the local store to the agent. Reusing the block the
 * manager writes in #39319 would be tidy but is not required by anything.
 */
#ifndef CA_PUBLICATION_H
#define CA_PUBLICATION_H

#include <stdint.h>

/* No publication is recorded: a fresh install, a store placed by hand or by configuration
 * management, or one written by an agent predating this feature. The bundle is still used for
 * TLS exactly as before; the agent re-anchors on the next notify that carries a publication. */
#define W_CA_PUBLICATION_UNKNOWN ((int64_t) -1)

/**
 * @brief Reads the publication recorded in the PEM trust store at @p path.
 *
 * Only the text before the first encapsulation boundary is examined, so this costs a few lines
 * rather than a parse of the certificates.
 *
 * @param path Path of the trust store.
 * @return The recorded publication (> 0), or W_CA_PUBLICATION_UNKNOWN when the file is missing,
 *         unreadable, carries no publication line, or carries one that is not a positive integer
 *         this agent can represent. A malformed line is deliberately indistinguishable from an
 *         absent one: both mean "this store's publication is not known", and both are answered
 *         by re-anchoring on the next advertised one rather than by refusing to start.
 */
int64_t w_ca_publication_read(const char *path);

/**
 * @brief Renders the block that records @p generation, ready to be written ahead of the
 *        certificates.
 *
 * @param generation The publication to record; must be > 0.
 * @param out Receives the block, newline-terminated.
 * @param out_size Size of @p out.
 * @return 0 on success, -1 when @p generation is not a valid publication or @p out is too small.
 */
int w_ca_publication_render(int64_t generation, char *out, size_t out_size);

#endif /* CA_PUBLICATION_H */
