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

#include "requestTarget.hpp"

#include <utility>

CacertsClient::CacertsClient(const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe,
                             LogFn logFn, bool unverifiedByDesign)
    : m_config(config)
    , m_performer(performer)
    , m_fsProbe(fsProbe)
    , m_logFn(std::move(logFn))
    , m_unverifiedByDesign(unverifiedByDesign)
{
}

HttpResponse CacertsClient::fetch(const std::atomic<bool>* abortFlag)
{
    if (!m_config.validateTransport(m_fsProbe, m_logFn, m_unverifiedByDesign))
    {
        HttpResponse response;
        response.status = TransportStatus::TlsFail;
        return response;
    }

    HttpRequestSpec spec;
    spec.target = prefixedTarget(m_config.serverEndpoint, "/cacerts");
    spec.method = HttpMethod::Get;
    spec.timeoutMs = m_config.requestTimeoutMs;
    spec.abortFlag = abortFlag;
    // Bounded at the transport, not just judged afterwards. The manager caps a publishable
    // bundle at 6 certificates and 8191 serialised bytes, so nothing legitimate reaches this --
    // but without it the whole body is buffered into this agent's address space before anything
    // looks at its size, with a hostile or faulty manager choosing how much and when. A body
    // that fills the cap exactly still arrives whole, so the consumer can say so precisely
    // instead of reporting an opaque transport error.
    spec.maxResponseBytes = HC_MAX_CACERTS_BODY;

    return m_performer.perform(spec);
}
