/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_CONFIG_HPP
#define _REMOTED_HTTP_SERVER_CONFIG_HPP

#include "IHttpServer.hpp"
#include "remoted_module.h"

#include <string>
#include <string_view>

namespace remoted::http
{

    /**
     * @brief Translate the module's C-ABI config into an HttpServerConfig.
     *
     * Every field resolves as **caller value (C-ABI struct) -> built-in default** --
     * there is no environment-variable fallback for anything here. Most fields
     * (io/worker threads, timeouts, URL/header/body limits, buffer size, pipelining,
     * concurrent accepts) are populated by remoted from the `remoted.http_*` internal
     * options (already range-validated on the C side, see
     * `remoted_module_https_config()` in secure.c) before this function ever runs, so a
     * positive value here just means "an internal option was set"; <=0 means "not set,
     * use the built-in default". Bind address, port, max body size, the
     * certificate/private key paths, the mTLS settings (ca, ciphers,
     * verification_mode), and dual_stack are regular `<remote><https>` settings that
     * remoted copies straight from the parsed config (see w_remoted_build_module_config()
     * in secure.c):
     *   - certificate/private key/ca default to `etc/certs/remoted.pem`, `etc/certs/remoted-key.pem`,
     *     and `etc/certs/root-ca.pem`.
     *   - ciphers defaults to `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`.
     *   - verification_mode's C-ABI UNSET sentinel (-1, "operator never configured it") resolves
     *     to disabled, distinct from an explicit `none` (0) -- both end up as
     *     ClientVerificationMode::None here, since this struct has no separate "unset" state.
     *   - dual_stack defaults to Unset (its C-ABI default already matches), and only applies to
     *     an IPv6 bind address.
     *   - global_prefix is copied VERBATIM (empty buffer -> "" == "/" == no prefix, today's
     *     behavior); its canonicalization (trailing-slash strip, identity collapse) happens in
     *     RestinioHttpServer::start() via normalizeGlobalPrefix() below -- never here -- and its
     *     grammar was already validated fatally by the C parser (w_remoted_parse_https()).
     * The in-flight byte budget and max parallel connections are set directly by remoted in
     * secure.c (deliberately not an internal option), independent of
     * `remoted_module_https_config()`.
     *
     * @param config Configuration handed by remoted.
     * @return Resolved HttpServerConfig.
     */
    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config);

    /**
     * @brief Canonicalize a global endpoint prefix (HttpServerConfig::globalPrefix).
     *
     * "" and "/" (and any all-'/' value) mean "no prefix" and normalize to "". Anything else
     * normalizes to `/seg[/seg...]`: a leading '/' is ensured, every trailing '/' is stripped
     * (so route concatenation can never produce "//"). Exported here -- rather than kept as a
     * transport-local helper -- so the weird-value table is unit-testable without sockets;
     * the ONE runtime call site is RestinioHttpServer::start().
     *
     * @throws std::invalid_argument for a byte outside [A-Za-z0-9._~/-] (RFC 3986 unreserved
     *         plus '/'; notably no '%': the prefix is compared byte-exactly against the wire,
     *         never percent-decoded) or for an empty interior segment ("//").
     */
    std::string normalizeGlobalPrefix(std::string_view raw);

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CONFIG_HPP
