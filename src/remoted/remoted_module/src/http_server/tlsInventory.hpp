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

#ifndef _REMOTED_HTTP_SERVER_TLS_INVENTORY_HPP
#define _REMOTED_HTTP_SERVER_TLS_INVENTORY_HPP

/**
 * @file tlsInventory.hpp
 * @brief What `GET /tls` on the admin socket answers with (issue #39320): the certificate the
 *        listener is serving, as loaded, and the CA bundle as read for this very request -- one
 *        struct the transport fills (IHttpServer::tlsInventory()) and one function that renders it.
 *
 * The two halves age differently, and the document says so. The leaf lives in the SSL_CTX from
 * start() until the next start(), so `listener` carries `loaded_at` and replacing the file on disk
 * changes nothing until remoted restarts. The CA half comes from the same CaCertificateSource
 * `GET /cacerts` answers from, read on this request, so replacing the bundle shows in the next
 * request -- and while the file cannot be read, the CA fields describe the last good read and
 * `last_read_failure` says so. Three verdicts travel with the bundle and answer three different
 * questions: per certificate `signs_active_leaf` (a plain signature), bundle-level
 * `matches_active_leaf` (does the leaf CHAIN to it -- what `GET /cacerts` decides its 503 from) and
 * `chain_valid` (the operator-facing validation, partial chains and the server purpose included).
 * `publication` follows the wire contract of `ca_generation`: null without a servable bundle, 0
 * served but unvouched, else the vouched timestamp. No thresholds and no `warning`/`critical`
 * verdicts: the consumer (the Dashboard, a runbook) decides what "soon" means.
 *
 * Rendering is a pure function of the inventory and a clock so the exact document -- every key,
 * both spellings of every timestamp, the fields that appear only on failure -- is unit-tested
 * without a socket. The admin route in remotedModuleFacade.hpp only adds the 503 for a listener
 * that is not up.
 */

#include "caCertificateSource.hpp"
#include "certificateDescriptor.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace remoted::http
{
    /// The certificate the listener serves: fixed from the start() that loaded it until the next one.
    struct TlsListener
    {
        CertificateDescriptor certificate;
        std::chrono::system_clock::time_point loadedAt; ///< When start() loaded it into the SSL_CTX.
        std::string certificatePath;                    ///< HttpServerConfig::certificatePath, as configured.
    };

    /// Everything `GET /tls` publishes, from one IHttpServer::tlsInventory() call.
    struct TlsInventory
    {
        std::optional<TlsListener> listener; ///< nullopt while the listener is not accepting: the route answers 503.
        std::string caCertificatePath;       ///< HttpServerConfig::caCertificatePath, as configured.
        CaCertificateSnapshot ca;            ///< One snapshot(): what `GET /cacerts` would hand out right now.
    };

    /**
     * @brief The `GET /tls` document for @p inventory as of @p now, serialised.
     *
     * `evaluated_at` is @p now; every `*_ts` is epoch seconds and its sibling the same instant as
     * RFC 3339 UTC; `seconds_until_expiry` is `not_after_ts - now`, negative once expired.
     * `chain_error` appears only when `chain_valid` is false and `last_read_failure` only while the
     * bundle cannot be read; `listener` is omitted when the inventory has none (the route never
     * renders that case: it answers 503 instead).
     */
    std::string renderTlsInventory(const TlsInventory& inventory, std::chrono::system_clock::time_point now);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_TLS_INVENTORY_HPP
