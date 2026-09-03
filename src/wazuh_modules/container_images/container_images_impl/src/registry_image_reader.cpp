/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registry_image_reader.hpp"

#include "agent_credential_store.hpp"
#include "auth_challenge.hpp"
#include "byte_stream.hpp"
#include "ca_bundle.hpp"
#include "ci_logging_helper.hpp"
#include "layer_composer.hpp"
#include "oci_metadata.hpp"
#include "registry_byte_stream.hpp"
#include "registry_reference.hpp"

#include <chrono>
#include <exception>
#include <thread>
#include <utility>

namespace
{
    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    /// @brief True when @p url names exactly @p host as its authority.
    ///
    /// Parsed rather than searched for: a substring test would accept
    /// "https://ghcr.io@elsewhere.example/token", whose authority is elsewhere.example.
    bool isRealmHostAllowed(const std::string& url, const std::string& host)
    {
        const std::string prefix {"https://"};

        if (url.compare(0, prefix.size(), prefix) != 0)
        {
            return false;
        }

        const auto authorityEnd {url.find_first_of("/?#", prefix.size())};
        const auto authority {url.substr(prefix.size(), authorityEnd - prefix.size())};

        // Anything before an '@' is userinfo, and the host is what follows it. A realm
        // carrying userinfo is not something a registry sends, so it is refused outright
        // rather than parsed past.
        if (authority.find('@') != std::string::npos)
        {
            return false;
        }

        // A port is allowed only if it is the default one, which is to say absent.
        return authority == host;
    }

    /// @brief The media types a manifest request is willing to receive.
    std::string acceptHeader()
    {
        return std::string {"Accept: "} + containerimages::oci::MEDIA_TYPE_OCI_INDEX + ", " +
               containerimages::oci::MEDIA_TYPE_DOCKER_LIST + ", " +
               containerimages::oci::MEDIA_TYPE_OCI_MANIFEST + ", " +
               containerimages::oci::MEDIA_TYPE_DOCKER_MANIFEST;
    }
} // namespace

namespace containerimages
{
    RegistryImageReader::RegistryImageReader(std::string location,
                                             std::string knownConfigDigest,
                                             ReaderContext context)
        : m_location {std::move(location)}
        , m_knownConfigDigest {std::move(knownConfigDigest)}
        , m_context {context}
        , m_retryPolicy {context.config != nullptr ? context.config->limits.maxAttempts : 4,
                         std::chrono::milliseconds {context.config != nullptr
                                                        ? context.config->limits.retryBaseDelayMs
                                                        : 1000}}
    {
    }

    void RegistryImageReader::setTransport(std::unique_ptr<IRegistryTransport> transport)
    {
        m_transport = std::move(transport);
        m_transportInjected = m_transport != nullptr;
    }

    std::string RegistryImageReader::sourceType() const
    {
        return referenceTypeName(ReferenceType::Registry);
    }

    bool RegistryImageReader::request(const std::string& url,
                                      const bool authorized,
                                      HttpResponse& response,
                                      std::string& error)
    {
        std::vector<std::string> headers {acceptHeader()};

        if (authorized && !m_token.empty())
        {
            headers.push_back("Authorization: Bearer " + m_token);
        }

        for (int attempt = 1;; ++attempt)
        {
            const auto answered {m_transport->get(url, headers, response, error)};

            if (answered && response.status >= 200 && response.status <= 299)
            {
                return true;
            }

            // A 401 is not a failure here: it carries the challenge the caller needs.
            if (answered && response.status == 401)
            {
                return true;
            }

            const auto status {answered ? response.status : TRANSPORT_FAILURE};
            const auto decision {m_retryPolicy.evaluate(status, response.header("retry-after"), attempt)};

            if (!decision.retry)
            {
                if (error.empty())
                {
                    error = "the registry answered " + std::to_string(response.status);
                }

                return false;
            }

            logDebug("Reference '" + m_location + "': the registry answered " + std::to_string(status) +
                     ", retrying in " + std::to_string(decision.delay.count()) + " ms.");

            // Slept in slices with the stop request checked between them. One sleep of
            // the whole delay would hold the module thread for up to the ceiling of the
            // back-off, and every module shares one shutdown budget.
            if (!waitOrStop(decision.delay))
            {
                error = "the module was asked to stop";
                return false;
            }
        }
    }

    bool RegistryImageReader::waitOrStop(const std::chrono::milliseconds delay) const
    {
        constexpr std::chrono::milliseconds SLICE {200};

        for (auto waited = std::chrono::milliseconds {0}; waited < delay; waited += SLICE)
        {
            if (m_context.stopRequested != nullptr && m_context.stopRequested->load())
            {
                return false;
            }

            std::this_thread::sleep_for(std::min(SLICE, delay - waited));
        }

        return true;
    }

    bool RegistryImageReader::authenticate(const std::string& challengeHeader, std::string& error)
    {
        AuthChallenge challenge;

        if (!parseAuthChallenge(challengeHeader, challenge) || !challenge.isBearer())
        {
            error = "the registry asked for an authentication method this module cannot answer";
            return false;
        }

        const auto url {tokenRequestUrl(challenge, m_reference.pullScope())};

        if (url.empty())
        {
            error = "the registry named a token endpoint that is not an https address";
            return false;
        }

        // The realm arrives in a response header, and the credential is about to be sent
        // to whatever host it names. Pinned to the reference's own registry so a realm of
        // "https://ghcr.io@elsewhere.example/token", which is a valid https URL pointing
        // at elsewhere.example, cannot collect the credential. Only reachable at all
        // through a certificate the agent trusts, which is exactly what an interception
        // CA in the configured bundle provides.
        if (!isRealmHostAllowed(url, m_reference.registry))
        {
            error = "the registry named a token endpoint outside " + m_reference.registry;
            return false;
        }

        const auto* configured {m_context.config != nullptr
                                    ? m_context.config->credentialsFor(m_reference.registry)
                                    : nullptr};

        HttpResponse response;

        if (configured != nullptr && m_context.credentials != nullptr)
        {
            const auto user {m_context.credentials->get(CREDENTIAL_FAMILY, configured->userKey)};
            const auto passkey {m_context.credentials->get(CREDENTIAL_FAMILY, configured->passkeyKey)};

            if (!user.has_value() || !passkey.has_value())
            {
                // Named without the value, always. The keys are configuration, the values
                // are not, and a log line that echoed one would defeat the store.
                error = "the credential configured for " + m_reference.registry +
                        " is missing from the agent credential store";
                return false;
            }

            if (!m_transport->getWithBasicAuth(url, {}, user->value(), *passkey, response, error))
            {
                return false;
            }
        }
        else
        {
            logDebug("No credential is configured for " + m_reference.registry +
                     ", requesting an anonymous token.");

            if (!m_transport->get(url, {}, response, error))
            {
                return false;
            }
        }

        if (response.status < 200 || response.status > 299)
        {
            error = "the registry refused to issue a token, answering " + std::to_string(response.status);
            return false;
        }

        m_token = oci::stringField(oci::parseJson(response.body), "token");

        if (m_token.empty())
        {
            // Some registries name it differently, and one that names it neither way has
            // not given us anything to authenticate with.
            m_token = oci::stringField(oci::parseJson(response.body), "access_token");
        }

        if (m_token.empty())
        {
            error = "the registry issued no token";
            return false;
        }

        return true;
    }

    bool RegistryImageReader::fetchManifest(const std::string& identifier,
                                            nlohmann::json& document,
                                            std::string& error)
    {
        const auto url {"https://" + m_reference.registry + "/v2/" + m_reference.repository + "/manifests/" +
                        identifier};

        HttpResponse response;

        if (!request(url, true, response, error))
        {
            return false;
        }

        if (response.status == 401)
        {
            if (!authenticate(response.header("www-authenticate"), error))
            {
                return false;
            }

            if (!request(url, true, response, error))
            {
                return false;
            }

            if (response.status == 401)
            {
                error = "the registry rejected the credential";
                return false;
            }
        }

        document = oci::parseJson(response.body);

        if (document.empty())
        {
            error = "the registry returned a manifest that could not be parsed";
            return false;
        }

        return true;
    }

    bool RegistryImageReader::readLayers(const nlohmann::json& manifest,
                                         ImageReferenceRecord& record,
                                         std::string& error)
    {
        const auto& limits {m_context.config->limits};
        const auto layers = oci::arrayField(manifest, "layers");

        LayerComposer composer;

        for (const auto& layer : layers)
        {
            if (!layer.is_object())
            {
                continue;
            }

            const auto digest {oci::stringField(layer, "digest")};

            if (!oci::isSafeDigest(digest))
            {
                error = "the manifest names a layer with a malformed digest";
                return false;
            }

            // What is left of this image's allowance, so one oversized layer cannot be
            // read just because it is the first.
            const auto remaining {limits.maxImageBytes > m_imageBytes ? limits.maxImageBytes - m_imageBytes : 0};

            if (remaining == 0)
            {
                error = "the image exceeded its " + std::to_string(limits.maxImageBytes) + " byte allowance";
                return false;
            }

            const auto url {"https://" + m_reference.registry + "/v2/" + m_reference.repository + "/blobs/" +
                            digest};

            std::vector<std::string> headers;

            if (!m_token.empty())
            {
                headers.push_back("Authorization: Bearer " + m_token);
            }

            // A layer is retried like a metadata request is. A transfer that failed part
            // way cannot be resumed, so the attempt starts the layer again; a partially
            // consumed snapshot is discarded with the stream that produced it.
            LayerSnapshot snapshot;

            for (int attempt = 1;; ++attempt)
            {
                RegistryByteStream blob {m_transportConfig, url, headers, remaining, m_context.stopRequested};
                LayerByteStream decompressed {blob};

                snapshot = readLayerSnapshot(decompressed);

                m_imageBytes += blob.bytesDelivered();

                if (m_context.scanBytes != nullptr)
                {
                    *m_context.scanBytes += blob.bytesDelivered();
                }

                if (!blob.failed())
                {
                    break;
                }

                // A token that expired part way through a large image is answered by
                // asking for another one, once, rather than by failing the reference.
                if (blob.status() == 401 && !m_tokenRefreshed)
                {
                    m_tokenRefreshed = true;

                    HttpResponse challenge;
                    std::string ignored;

                    if (m_transport->get(url, {}, challenge, ignored) && challenge.status == 401 &&
                        authenticate(challenge.header("www-authenticate"), ignored))
                    {
                        headers.clear();
                        headers.push_back("Authorization: Bearer " + m_token);
                        continue;
                    }
                }

                const auto decision {m_retryPolicy.evaluate(blob.status(), {}, attempt)};

                if (!decision.retry)
                {
                    // A layer that could not be retrieved makes the composed inventory a
                    // guess, and a guess stored as the complete state deletes whatever the
                    // reference really holds. Reported as a failed read instead.
                    error = "layer " + digest.substr(0, 19) + " could not be retrieved: " + blob.error();
                    return false;
                }

                if (!waitOrStop(decision.delay))
                {
                    error = "the module was asked to stop";
                    return false;
                }
            }

            if (!snapshot.complete)
            {
                error = "layer " + digest.substr(0, 19) + " is malformed";
                return false;
            }

            composer.apply(snapshot);
        }

        for (const auto& format : composer.unsupportedFormats())
        {
            logWarn("Reference '" + m_location + "' holds a " + format +
                    " package database, which is recognized but not supported yet.");
        }

        record.packages = composer.packages();

        return true;
    }

    ImageReadResult RegistryImageReader::discover()
    {
        // Nothing below may escape. This runs on the module thread, and an exception here
        // unwinds the whole scan loop, exactly as the archive reader documents.
        try
        {
            std::string error;

            if (!parseRegistryReference(m_location, m_reference, error))
            {
                logWarn("Reference '" + m_location + "' cannot be used: " + error + ".");
                return ImageReadResult::failed();
            }

            if (m_context.config == nullptr)
            {
                logWarn("Reference '" + m_location + "' has no configuration to read.");
                return ImageReadResult::failed();
            }

            const auto& limits {m_context.config->limits};

            if (m_context.scanBytes != nullptr && *m_context.scanBytes >= limits.maxScanBytes)
            {
                // Checked before the reference is started rather than during it, so the
                // scan stops taking on new work instead of abandoning an image halfway.
                logWarn("Reference '" + m_location + "' was not scanned: this scan already reached its " +
                        std::to_string(limits.maxScanBytes) + " byte allowance.");
                return ImageReadResult::failed();
            }

            const auto bundle {resolveCaBundle(m_context.config->caBundle)};

            if (!bundle.found())
            {
                logWarn("Reference '" + m_location + "' cannot be verified: " + bundle.reason + ".");
                return ImageReadResult::failed();
            }

            m_transportConfig.caBundle = bundle.path;
            m_transportConfig.connectTimeoutMs = limits.connectTimeoutMs;
            m_transportConfig.requestTimeoutMs = limits.requestTimeoutMs;
            m_transportConfig.blobTimeoutMs = limits.blobTimeoutMs;

            // An injected transport is left in place: a test supplies one and must not
            // have it replaced by a real one the moment discover() runs.
            if (!m_transportInjected)
            {
                m_transport = std::make_unique<CurlRegistryTransport>(m_transportConfig);
            }

            nlohmann::json document;

            if (!fetchManifest(m_reference.identifier(), document, error))
            {
                logWarn("Reference '" + m_location + "' could not be resolved: " + error + ".");
                return ImageReadResult::failed();
            }

            PlatformManifest selected;

            if (!selectPlatformManifest(document, detectTargetPlatform(), selected, error))
            {
                logWarn("Reference '" + m_location + "' was not inventoried: " + error + ".");
                return ImageReadResult::failed();
            }

            if (!selected.digest.empty() && !fetchManifest(selected.digest, document, error))
            {
                logWarn("Reference '" + m_location + "' could not be resolved: " + error + ".");
                return ImageReadResult::failed();
            }

            const auto configNode {document.find("config")};

            if (configNode == document.end() || !configNode->is_object())
            {
                logWarn("Reference '" + m_location + "' names no image configuration.");
                return ImageReadResult::failed();
            }

            const auto configDigest {oci::stringField(*configNode, "digest")};

            if (!oci::isSafeDigest(configDigest))
            {
                logWarn("Reference '" + m_location + "' names a malformed image configuration digest.");
                return ImageReadResult::failed();
            }

            if (!m_knownConfigDigest.empty() && configDigest == m_knownConfigDigest)
            {
                // The configuration digest identifies the image contents, so an image
                // still reporting the stored digest cannot hold different packages. Two
                // small metadata requests have been made and no layer has been touched.
                logDebug("Reference '" + m_location + "' still reports " + configDigest +
                         ", so no image contents were retrieved.");
                return ImageReadResult::unchanged();
            }

            ImageReferenceRecord record;
            record.source = {sourceType(), m_location};
            record.tag = m_reference.pinnedByDigest() ? m_reference.digest : m_reference.tag;
            record.configDigest = configDigest;
            record.manifestDigest = selected.digest;

            // The configuration blob is the authority on the platform, which is why it is
            // read even for a reference that named its platform in an index entry.
            const auto configUrl {"https://" + m_reference.registry + "/v2/" + m_reference.repository +
                                  "/blobs/" + configDigest};

            HttpResponse configResponse;

            if (request(configUrl, true, configResponse, error) && configResponse.status >= 200 &&
                configResponse.status <= 299)
            {
                oci::applyConfigMetadata(oci::parseJson(configResponse.body), record);
            }
            else if (!selected.digest.empty())
            {
                // Not fatal for a reference selected out of an index: its platform was
                // already matched there, so an unreadable configuration blob costs
                // metadata rather than correctness.
                logDebug("Reference '" + m_location + "': the image configuration could not be read, so its "
                         "platform metadata is taken from the manifest entry.");
                record.os = selected.platform.os;
                record.architecture = selected.platform.architecture;
                record.variant = selected.platform.variant;
            }
            else
            {
                // A reference that pointed straight at a manifest has no index entry to
                // fall back on, so nothing has confirmed its platform and nothing can.
                logWarn("Reference '" + m_location +
                        "' was not inventoried: its image configuration could not be read, so its platform "
                        "cannot be confirmed.");
                return ImageReadResult::failed();
            }

            // A reference that named a manifest directly was accepted without a platform
            // comparison, because only the configuration blob carries one. This is where
            // that check happens: without it a single-platform image built for another
            // architecture is inventoried as though it were the agent's own.
            if (selected.digest.empty())
            {
                const Platform imagePlatform {record.os, record.architecture, record.variant};
                const auto agentPlatform {detectTargetPlatform()};

                if (!platformMatches(imagePlatform, agentPlatform))
                {
                    logWarn("Reference '" + m_location + "' was not inventoried: no image variant matches " +
                            agentPlatform.describe() + ", the reference offers " + imagePlatform.describe() + ".");
                    return ImageReadResult::failed();
                }
            }

            if (!readLayers(document, record, error))
            {
                logWarn("Reference '" + m_location + "' could not be read: " + error + ".");
                return ImageReadResult::failed();
            }

            logDebug("Reference '" + m_location + "' yielded " + std::to_string(record.packages.size()) +
                     " package(s) from " + std::to_string(m_imageBytes) + " streamed byte(s).");

            std::vector<ImageReferenceRecord> records;
            records.push_back(std::move(record));

            return ImageReadResult::success(std::move(records));
        }
        catch (const std::exception& exception)
        {
            logWarn("Reference '" + m_location + "' could not be read: " + exception.what() + ".");
            return ImageReadResult::failed();
        }
        catch (...)
        {
            logWarn("Reference '" + m_location + "' could not be read.");
            return ImageReadResult::failed();
        }
    }
} // namespace containerimages
