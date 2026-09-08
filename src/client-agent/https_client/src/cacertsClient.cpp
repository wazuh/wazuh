/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cacertsClient.hpp"

#include <utility>

CacertsClient::CacertsClient(const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe,
                             LogFn logFn)
    : m_config(config)
    , m_performer(performer)
    , m_fsProbe(fsProbe)
    , m_logFn(std::move(logFn))
{
}

HttpResponse CacertsClient::fetch()
{
    if (!m_config.validateTransport(m_fsProbe, m_logFn))
    {
        HttpResponse response;
        response.status = TransportStatus::TlsFail;
        return response;
    }

    HttpRequestSpec spec;
    // Literal, unprefixed target: see the class doc comment's "ASSUMPTION"
    // paragraph on why this does not go through prefixedTarget() like every
    // other endpoint.
    spec.target = "/cacerts";
    spec.method = HttpMethod::Get;
    spec.timeoutMs = m_config.requestTimeoutMs;

    return m_performer.perform(spec);
}
