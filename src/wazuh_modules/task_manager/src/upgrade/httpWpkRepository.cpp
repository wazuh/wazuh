/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "httpWpkRepository.hpp"

#include "os_cert_bundle.h"

#include <HTTPRequest.hpp>
#include <IURLRequest.hpp>
#include <secureCommunication.hpp>

#include <atomic>
#include <utility>

namespace
{
    /**
     * @brief The cancellation flag handed to the library, with PROCESS lifetime.
     *
     * It has to outlive everything, and a member would not. cURLMultiHandler stores this reference
     * at construction, and cURLHandlerCache -- a singleton keyed only on (thread id, handler type),
     * shared with vulnerability_scanner and indexer_connector -- keeps that handler and reuses it
     * without rebinding. A flag with any shorter life would be read after its owner was gone, by
     * requests belonging to other modules.
     *
     * Function-local rather than a namespace-scope object so it is constructed on first use and
     * never destroyed, which also makes a stop/start cycle of the module safe: start() resets it.
     */
    std::atomic<bool>& shouldRunFlag()
    {
        static std::atomic<bool> flag {true};
        return flag;
    }
} // namespace

namespace task_manager::upgrade
{
    HttpWpkRepository::HttpWpkRepository()
        : HttpWpkRepository {Options {}}
    {
    }

    HttpWpkRepository::HttpWpkRepository(Options options)
        : m_options {std::move(options)}
    {
        // A previous module lifecycle may have stopped it; this one is starting.
        shouldRunFlag().store(true);

        if (!m_options.caBundlePath.empty())
        {
            m_caBundle = m_options.caBundlePath;
        }
        else if (const char* found {os_find_ca_bundle(nullptr)}; found != nullptr)
        {
            // os_cert_bundle.c is compiled straight into this shared object rather than linked from
            // libwazuh -- its own header records that it is dependency-free for exactly this reason,
            // and the https_client module already does the same. Sharing it keeps ONE list of
            // candidate paths in the tree rather than a second copy that drifts.
            m_caBundle = found;
        }
    }

    bool HttpWpkRepository::hasCaBundle() const
    {
        return !m_caBundle.empty();
    }

    void HttpWpkRepository::requestStop()
    {
        shouldRunFlag().store(false);
    }

    RepoResult HttpWpkRepository::fetchVersions(const std::string& url, std::string& body)
    {
        RepoResult result;

        if (m_caBundle.empty())
        {
            // Refused rather than sent unverified. See the header: the digest this file carries is
            // the only thing standing between us and an attacker-supplied WPK.
            return result;
        }

        const auto secure {SecureCommunication::builder().caRootCertificate(m_caBundle)};
        const HttpURL target {url};

        std::string received;
        bool failed {false};

        HTTPRequest::instance().get(
            RequestParameters {.url = target, .secureCommunication = secure},
            PostRequestParameters {
                .onSuccess = [&received](const std::string& response) { received = response; },
                .onError =
                    [&failed, &result](const std::string&, const long responseCode, const std::string&)
                {
                    failed = true;
                    result.httpStatus = static_cast<int>(responseCode);
                }},
            ConfigurationParameters {.timeout = static_cast<long>(m_options.versionsTimeout.count()),
                                     .handlerType = CurlHandlerTypeEnum::MULTI,
                                     .shouldRun = shouldRunFlag()});

        if (!failed)
        {
            result.ok = true;
            result.httpStatus = 200;
            body = std::move(received);
        }
        else if (!shouldRunFlag().load())
        {
            // The library reports a cancelled transfer as an ordinary failure, so the flag is what
            // distinguishes "shutting down" from "the repository is broken" -- and the caller must
            // not spend a retry, or log an error, for the former.
            result.aborted = true;
        }

        return result;
    }

    RepoResult HttpWpkRepository::download(const std::string& url, const std::string& destPath, const StopToken& stop)
    {
        RepoResult result;

        if (stop.stopRequested() || !shouldRunFlag().load())
        {
            result.aborted = true;
            return result;
        }

        if (m_caBundle.empty())
        {
            return result;
        }

        const auto secure {SecureCommunication::builder().caRootCertificate(m_caBundle)};
        const HttpURL target {url};

        bool failed {false};

        // download() writes straight to outputFile and reports nothing on success, so "no error was
        // raised" is the success signal. WpkCache hands it a STAGING path, never the served one.
        HTTPRequest::instance().download(
            RequestParameters {.url = target, .secureCommunication = secure},
            PostRequestParameters {
                .onError =
                    [&failed, &result](const std::string&, const long responseCode, const std::string&)
                {
                    failed = true;
                    result.httpStatus = static_cast<int>(responseCode);
                },
                .outputFile = destPath},
            ConfigurationParameters {.timeout = static_cast<long>(m_options.downloadTimeout.count()),
                                     .handlerType = CurlHandlerTypeEnum::MULTI,
                                     .shouldRun = shouldRunFlag()});

        if (!failed)
        {
            result.ok = true;
            result.httpStatus = 200;
        }
        else if (!shouldRunFlag().load() || stop.stopRequested())
        {
            result.aborted = true;
        }

        return result;
    }
} // namespace task_manager::upgrade
