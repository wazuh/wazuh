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

/**
 * @brief Maps an HttpRequestSpec onto option calls of an injected
 *        ICurlHandle: base URL, method, body (memory or streamed file),
 *        timeouts, and the TLS matrix (with redirects off and NOSIGNAL on,
 *        always). Fully unit-tested against MockCurlHandle.
 */
class CurlPerformer final : public IHttpPerformer
{
    public:
        CurlPerformer(const ModuleConfig& config, CurlHandleFactory factory);

        HttpResponse perform(const HttpRequestSpec& spec) override;

    private:
        bool configureBody(ICurlHandle& handle, const HttpRequestSpec& spec,
                           std::FILE** fileOut) const;
        bool configureResponseSink(ICurlHandle& handle, const HttpRequestSpec& spec,
                                   HttpResponse& response, std::FILE** fileOut) const;
        void configureRequest(ICurlHandle& handle, const HttpRequestSpec& spec,
                              HttpResponse& response) const;
        void applyTls(ICurlHandle& handle) const;

        const ModuleConfig& m_config;
        CurlHandleFactory m_factory;
};

#endif // _HC_CURL_PERFORMER_HPP
