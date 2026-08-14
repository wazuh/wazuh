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
     * The in-flight byte budget and max parallel connections are set directly by remoted in
     * secure.c (deliberately not an internal option), independent of
     * `remoted_module_https_config()`.
     *
     * @param config Configuration handed by remoted.
     * @return Resolved HttpServerConfig.
     */
    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config);

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CONFIG_HPP
