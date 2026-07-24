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
     * certificate/private key paths, and the mTLS settings (ca, ciphers,
     * verification_mode) are regular `<remote><https>` settings that remoted copies
     * straight from the parsed config (see HandleSecure() in secure.c); an unset/empty
     * value here means the operator did not configure that `<https>` option, and it
     * resolves to its built-in default (verification_mode defaults to disabled). The
     * in-flight byte budget and max parallel connections are set directly by remoted in
     * secure.c (deliberately not an internal option), independent of
     * `remoted_module_https_config()`.
     *
     * @param config Configuration handed by remoted.
     * @return Resolved HttpServerConfig.
     */
    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config);

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CONFIG_HPP
