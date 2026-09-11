/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CURL_PERFORMER_HPP
#define _HC_CURL_PERFORMER_HPP

#include "iCurlHandle.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

/**
 * @brief Maps an HttpRequestSpec onto option calls of an injected
 *        ICurlHandle: base URL, method, body (memory or streamed file),
 *        timeouts, and the TLS matrix (with redirects off and NOSIGNAL on,
 *        always). Fully unit-tested against MockCurlHandle.
 */
class CurlPerformer final : public IHttpPerformer
{
    public:
        /// Convenience overload for production and for tests that do not care
        /// about verify_mode=system's Linux trust-anchor resolution: uses a
        /// real FsProbe internally.
        CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory);

        /// @param fsProbe Used ONLY during construction (never stored) to resolve
        ///        verify_mode=system's trust anchor once, up front -- not on every
        ///        perform(), which would probe the filesystem on every request.
        ///        Irrelevant for every other verify_mode.
        CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory, const IFsProbe& fsProbe);

        HttpResponse perform(const HttpRequestSpec& spec) override;

    private:
        bool configureBody(ICurlHandle& handle, const HttpRequestSpec& spec,
                           std::FILE** fileOut) const;
        bool configureResponseSink(ICurlHandle& handle, const HttpRequestSpec& spec,
                                   HttpResponse& response, std::FILE** fileOut) const;
        /// @return false if capturing Retry-After or wiring the abort flag was
        ///         rejected by the handle; the caller must not proceed to
        ///         perform() in that case.
        bool configureRequest(ICurlHandle& handle, const HttpRequestSpec& spec,
                              HttpResponse& response) const;

        /// @return false as soon as one option is rejected; the caller must not
        ///         perform the request, because a TLS option that did not apply
        ///         silently weakens the connection.
        bool applyTls(ICurlHandle& handle) const;
        bool applyTrustAnchors(ICurlHandle& handle) const;
        bool applyClientCertificate(ICurlHandle& handle) const;
        bool applyCiphers(ICurlHandle& handle) const;

        /// Sets an option whose failure aborts the request, and says which one.
        bool setMandatoryOption(ICurlHandle& handle, CurlOption option, long value) const;
        bool setMandatoryOption(ICurlHandle& handle, CurlOption option, const std::string& value) const;

        // By value: callers routinely build a ModuleConfig as a temporary
        // (e.g. makeConfig()-style test helpers); a reference member would
        // dangle the moment that temporary's full expression ends.
        ModuleConfig m_config;
        CurlHandleFactory m_factory;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_CURL_PERFORMER_HPP
