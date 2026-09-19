/*
 * Wazuh manager certs tool - the master fetch, over libcurl
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MANAGER_CERTS_MASTER_TRANSPORT_HPP
#define _MANAGER_CERTS_MASTER_TRANSPORT_HPP

/**
 * @file masterTransport.hpp
 * @brief The one HTTPS GET `--from-master` makes, with every option that decides what it trusts
 *        pinned and CHECKED (`anexos/e8/tls-transporte.md` §1-6, C39a/b/c).
 *
 * Private to the module, like writeLock.hpp: the public surface is the MasterTransport seam of
 * manager_certs/commands.hpp, and nothing outside this module -- or its tests -- names libcurl.
 *
 * The transport is hardened against ONE failure mode above all others: silent degradation of the
 * trust decision. `CURLOPT_CAINFO_BLOB` whose `setopt` fails leaves `custom_cablob` set but no blob
 * stored, and Curl_ssl_easy_config_complete() then falls back to this build's compiled-in CA bundle
 * (src/external/curl/lib/vtls/vtls.c:316, `CURL_CA_BUNDLE`), so a fleet's trust anchor would
 * silently become whatever the host's package manager put in /etc -- the bypass CA-33 forbids. That
 * is why every security-relevant `setopt` return is inspected and why a single failure ends the run
 * BEFORE curl_easy_perform() is ever called.
 */

#include "manager_certs/commands.hpp"

#include <curl/curl.h>

#include <functional>

namespace manager_certs
{
    /**
     * @brief The libcurl calls the real transport makes, injectable.
     *
     * Same seam idiom, and the same reason, as IoPort and LockIo (C36): a test cannot make
     * `curl_easy_setopt(CURLOPT_CAINFO_BLOB)` fail on a real handle, cannot ask a real server for a
     * 302 with a valid body, and cannot observe from outside that `CURLOPT_CAPATH` was cleared --
     * and those are exactly the paths where the connection quietly stops being verified against the
     * local bundle. With a fake port a case asserts on the OPTIONS THEMSELVES (which option, which
     * value, in which order, and that nothing was sent after a refusal), which is a fact about the
     * handle rather than a grep over the source (C39h, objection 13).
     *
     * Every empty field means "call the real one", so production passes a default-constructed
     * CurlPort and nothing branches.
     */
    struct CurlPort
    {
        /// `curl_global_init()` + `curl_easy_init()`; nullptr means libcurl could not start.
        std::function<CURL*()> init {};
        std::function<CURLcode(CURL* handle, CURLoption option, long value)> setLong {};
        /// Strings, blobs and the two `*DATA` pointers.
        std::function<CURLcode(CURL* handle, CURLoption option, const void* value)> setPointer {};
        /// `CURLOPT_WRITEFUNCTION`/`CURLOPT_HEADERFUNCTION`, which share one signature.
        std::function<CURLcode(CURL* handle, CURLoption option, curl_write_callback value)> setCallback {};
        std::function<CURLcode(CURL* handle)> perform {};
        std::function<CURLcode(CURL* handle, CURLINFO info, long* value)> getLong {};
        std::function<void(CURL* handle)> cleanup {};
    };

    /**
     * @brief The real transport: libcurl 8.20 (src/external/curl/include/curl/curlver.h:35), with
     *        the local bundle as its only trust anchor.
     *
     * What it pins, in this order, each return value checked (`tls-transporte.md` §1-5): the URL,
     * `CAINFO_BLOB` (the local bundle), `CAPATH` cleared -- an independent trust source that the
     * blob does NOT replace, loaded all the same by ossl_load_trust_anchors()
     * (src/external/curl/lib/vtls/openssl.c:3036) --, `SSL_VERIFYPEER` 1, `SSL_VERIFYHOST` 2,
     * `PROXY` emptied so no inherited `https_proxy` can answer with headers of its own,
     * `FOLLOWLOCATION` 0, the timeout, and the two callbacks. Then, and only for a `CURLE_OK`
     * transfer, `CURLINFO_RESPONSE_CODE` must be 200: libcurl does not fail on a 302, a 206 or a
     * 500, and the body of one of those must never be looked at (C39b).
     *
     * The body is capped BEFORE each chunk is appended (C39c): a chunk that would cross
     * MasterFetch::maxBodyBytes is dropped whole and the transfer aborted, so not one byte past the
     * cap is ever kept.
     */
    MasterTransport curlMasterTransport(CurlPort port = {});

} // namespace manager_certs

#endif // _MANAGER_CERTS_MASTER_TRANSPORT_HPP
