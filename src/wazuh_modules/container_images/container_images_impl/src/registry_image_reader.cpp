/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
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
#include "registry_errors.hpp"
#include "registry_reference.hpp"

#include "hashHelper.h"
#include "wazuhCommon.hpp"

#include <atomic>
#include <chrono>
#include <exception>
#include <optional>
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

    /// @brief The sha256 digest of @p content, in the `sha256:<hex>` form a registry uses.
    std::string sha256Digest(const std::string& content)
    {
        Utils::HashData hash {Utils::HashType::Sha256};
        hash.update(content.data(), content.size());
        const auto digest {hash.hash()};

        return "sha256:" + wazuh::hex_encode(digest.data(), digest.size());
    }

    /// @brief Ends a stream as soon as a stop is requested.
    ///
    /// The transfer polls the stop flag only when the decompressor runs out of compressed
    /// bytes, which a layer that expands a lot does rarely. Polled here as well, on every
    /// read of the decompressed bytes, so a stop does not wait for the layer to finish.
    class StoppableByteStream final : public containerimages::IByteStream
    {
        public:
            StoppableByteStream(containerimages::IByteStream& source, const std::atomic<bool>* stopRequested)
                : m_source {source}
                , m_stopRequested {stopRequested}
            {
            }

            std::size_t read(char* buffer, const std::size_t size) override
            {
                if (m_stopRequested != nullptr && m_stopRequested->load())
                {
                    return 0;
                }

                return m_source.read(buffer, size);
            }

        private:
            containerimages::IByteStream& m_source;
            const std::atomic<bool>* m_stopRequested;
    };

    /// @brief @p text as a sentence: one full stop at the end, whether or not it already had one.
    ///
    /// A reason that comes from a registry or from AWS is often a sentence already, and a
    /// log line built from it must not end in two periods.
    std::string sentence(const std::string& text)
    {
        if (!text.empty() && (text.back() == '.' || text.back() == '!' || text.back() == '?'))
        {
            return text;
        }

        return text + ".";
    }

    /// @brief Clears the credential-bearing request headers it was given when it goes out of scope.
    struct HeaderScrubber
    {
        std::vector<std::string>& headers;

        ~HeaderScrubber()
        {
            for (auto& header : headers)
            {
                containerimages::scrubString(header);
            }
        }
    };

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

    void RegistryImageReader::setBlobStreamFactory(BlobStreamFactory factory)
    {
        m_blobStreamFactory = std::move(factory);
    }

    std::string RegistryImageReader::sourceType() const
    {
        return referenceTypeName(ReferenceType::Registry);
    }

    bool RegistryImageReader::send(const Attempt& attempt, HttpResponse& response, std::string& error)
    {
        for (int attemptNumber = 1;; ++attemptNumber)
        {
            error.clear();

            const auto answered {attempt(response, error)};

            if (answered && response.status >= 200 && response.status <= 299)
            {
                return true;
            }

            // A 401 is not a failure here: it carries the challenge the caller needs.
            if (answered && response.status == 401)
            {
                return true;
            }

            // No response, and one that would fail the same way again: the retries would
            // only spend their back-off on the same answer.
            if (!answered && !response.retryable)
            {
                return false;
            }

            const auto status {answered ? response.status : TRANSPORT_FAILURE};
            const auto decision {m_retryPolicy.evaluate(status, response.header("retry-after"), attemptNumber)};

            if (!decision.retry)
            {
                if (error.empty())
                {
                    error = "the registry answered " + std::to_string(response.status);

                    // The reason a private ECR registry gives is what the user can act on.
                    if (answered && m_reference.profile.kind != RegistryKind::Ghcr)
                    {
                        error += reasonSuffix(response.body);
                    }
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

    bool RegistryImageReader::request(const std::string& url,
                                      const bool authorized,
                                      HttpResponse& response,
                                      std::string& error)
    {
        std::vector<std::string> headers {acceptHeader()};
        const HeaderScrubber scrubber {headers};

        if (authorized && !m_token.empty())
        {
            headers.push_back(authorizationHeader());
        }

        return send([this, &url, &headers](HttpResponse & attemptResponse, std::string & attemptError)
        {
            return m_transport->get(url, headers, attemptResponse, attemptError);
        },
        response,
        error);
    }

    std::unique_ptr<IBlobStream> RegistryImageReader::openBlob(const std::string& url,
                                                               const std::vector<std::string>& headers,
                                                               const std::uint64_t maxBytes) const
    {
        if (m_blobStreamFactory)
        {
            return m_blobStreamFactory(m_transportConfig, url, headers, maxBytes, m_context.stopRequested);
        }

        return std::make_unique<RegistryByteStream>(m_transportConfig, url, headers, maxBytes, m_context.stopRequested);
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

        // Only GHCR exchanges a stored credential for its token. Public ECR issues its token
        // to anyone, and private ECR does not use this path at all.
        const auto* configured {m_context.config != nullptr && m_reference.profile.kind == RegistryKind::Ghcr
                                    ? m_context.config->credentialsFor(m_reference.registry)
                                    : nullptr};

        std::optional<Secret> user;
        std::optional<Secret> passkey;

        if (configured != nullptr && m_context.credentials != nullptr && !m_credentialRefused)
        {
            user = m_context.credentials->get(CREDENTIAL_FAMILY, configured->userKey);
            passkey = m_context.credentials->get(CREDENTIAL_FAMILY, configured->passkeyKey);

            if (!user.has_value() || !passkey.has_value())
            {
                // Named without the value, always. The keys are configuration, the values
                // are not, and a log line that echoed one would defeat the store.
                error = "the credential configured for " + m_reference.registry +
                        " is missing from the agent credential store";
                return false;
            }
        }
        else if (!m_credentialRefused)
        {
            logDebug("No credential is configured for " + m_reference.registry +
                     ", requesting an anonymous token.");
        }

        m_credentialSent = passkey.has_value();

        HttpResponse response;

        // Retried like any other request: the token endpoint is the first request of every
        // scan against a private repository, and a 429 or a reset there is as transient as
        // anywhere else.
        const Attempt exchange {[this, &url, &user, &passkey](HttpResponse & reply, std::string & failure)
        {
            if (passkey.has_value())
            {
                return m_transport->getWithBasicAuth(url, {}, user->value(), *passkey, reply, failure);
            }

            return m_transport->get(url, {}, reply, failure);
        }};

        const auto exchanged {send(exchange, response, error)};

        // The registry refusing the credential itself, as a 401 answer or as a 403 that
        // ended the retries, as opposed to a transport failure or throttling. Only this
        // is answered with an anonymous attempt, by the caller.
        if (passkey.has_value() && ((exchanged && response.status == 401) || (!exchanged && response.status == 403)))
        {
            m_credentialRefused = true;
        }

        if (!exchanged)
        {
            error = "the token request failed: " + error;
            return false;
        }

        if (response.status < 200 || response.status > 299)
        {
            error = "the registry refused to issue a token, answering " + std::to_string(response.status);
            return false;
        }

        auto token {oci::stringField(oci::parseJson(response.body), "token")};

        if (token.empty())
        {
            // Some registries name it differently, and one that names it neither way has
            // not given us anything to authenticate with.
            token = oci::stringField(oci::parseJson(response.body), "access_token");
        }

        if (token.empty())
        {
            error = "the registry issued no token";
            return false;
        }

        m_token = Secret {std::move(token)};

        return true;
    }

    std::string RegistryImageReader::reasonSuffix(const std::string& body) const
    {
        const auto reason {registryErrorReason(body)};

        if (reason.empty())
        {
            return {};
        }

        // Withheld when it contains the token held or either half of the AWS credential,
        // which a registry has no reason to echo and a log has every reason not to carry.
        if (!m_token.empty() && reason.find(m_token.value()) != std::string::npos)
        {
            return {};
        }

        for (const auto& guarded : m_guard)
        {
            if (!guarded.empty() && reason.find(guarded.value()) != std::string::npos)
            {
                return {};
            }
        }

        return ": " + reason;
    }

    std::string RegistryImageReader::authorizationHeader() const
    {
        if (m_token.empty())
        {
            return {};
        }

        return std::string {"Authorization: "} + (m_reference.profile.usesBasicToken() ? "Basic " : "Bearer ") +
               m_token.value();
    }

    bool RegistryImageReader::acquireEcrToken(std::string& error)
    {
        const auto* configured {m_context.config != nullptr ? m_context.config->credentialsFor(m_reference.registry)
                                                            : nullptr};

        if (configured == nullptr || m_context.credentials == nullptr)
        {
            error = "no credential is configured for " + m_reference.registry +
                    ", which needs a <registry> entry with access_key_id_keystore_key and "
                    "secret_access_key_keystore_key";
            return false;
        }

        const auto accessKeyId {m_context.credentials->get(CREDENTIAL_FAMILY, configured->userKey)};
        const auto secretAccessKey {m_context.credentials->get(CREDENTIAL_FAMILY, configured->passkeyKey)};

        if (!accessKeyId.has_value() || !secretAccessKey.has_value())
        {
            // Named without the value, always, as for any credential.
            error = "the credential configured for " + m_reference.registry +
                    " is missing from the agent credential store";
            return false;
        }

        // Kept so no reason a registry sends can carry either value into a log line.
        m_guard.clear();
        m_guard.emplace_back(accessKeyId->value());
        m_guard.emplace_back(secretAccessKey->value());

        // A configured region wins over the one in the host name. The two differing is
        // worth one line, since the token is then requested from a region the registry
        // does not live in. Neither region is a secret.
        auto region {m_reference.profile.region};
        m_regionOverridden = false;

        if (!configured->region.empty())
        {
            if (configured->region != region)
            {
                m_regionOverridden = true;
                logDebug("Reference '" + m_location + "': the configured region '" + configured->region +
                         "' overrides the region '" + region + "' of " + m_reference.registry + ".");
            }

            region = configured->region;
            m_configuredRegion = configured->region;
        }

        m_ecrTokenKey = RegistryTokenCache::makeKey(m_reference.registry,
                                                    configured->userKey,
                                                    configured->passkeyKey,
                                                    region);

        if (m_context.tokenCache != nullptr)
        {
            if (auto cached {m_context.tokenCache->lookup(m_ecrTokenKey)})
            {
                logDebug("Reference '" + m_location + "': reusing the registry token held for " +
                         m_reference.registry + ".");
                m_token = std::move(*cached);
                return true;
            }
        }

        IEcrTokenSource* source {m_context.ecrTokenSource};

        if (source == nullptr)
        {
            if (!m_ownedTokenSource)
            {
                m_ownedTokenSource = EcrTokenClient::overCurl(m_transportConfig);
            }

            source = m_ownedTokenSource.get();
        }

        for (int attempt = 1;; ++attempt)
        {
            if (m_context.stopRequested != nullptr && m_context.stopRequested->load())
            {
                error = "the module was asked to stop";
                return false;
            }

            logDebug("Reference '" + m_location + "': requesting a registry token for " + m_reference.registry +
                     " from AWS in " + region + ".");

            auto result {source->fetch(region, m_reference.profile.dnsSuffix, *accessKeyId, *secretAccessKey)};

            if (result.ok)
            {
                if (m_context.tokenCache != nullptr)
                {
                    m_context.tokenCache->store(m_ecrTokenKey, Secret {result.token.value()}, result.expiresAt);
                }

                m_token = std::move(result.token);
                return true;
            }

            // A call that was refused, or never made, in a way that repeats itself is tried
            // once: a certificate that does not verify or a URL that is not usable fails the
            // same way every time. Throttling and server errors are retried, waiting for what
            // AWS asks for when it says.
            const auto decision {result.retryable ? m_retryPolicy.evaluate(result.status, result.retryAfter, attempt)
                                                  : RetryDecision {}};

            if (!decision.retry)
            {
                error = "AWS did not issue a registry token: " + result.reason;

                // A 4xx other than throttling is AWS refusing the credential, or the request
                // made with it, and every reference of the registry would hear the same: a
                // signed call each, and a log line each, for a mistyped secret. Remembered for
                // the rest of the scan under the host. A server error, throttling and a call
                // that was never answered say nothing about the credential and are not kept.
                if (result.status >= 400 && result.status < 500 && result.status != 429)
                {
                    rememberEcrRefusal(m_reference.registry, error);
                }

                return false;
            }

            logDebug("Reference '" + m_location + "': " + result.reason + ", retrying in " +
                     std::to_string(decision.delay.count()) + " ms.");

            if (!waitOrStop(decision.delay))
            {
                error = "the module was asked to stop";
                return false;
            }
        }
    }

    bool RegistryImageReader::tokenIsRefused(const long status, const std::string& body)
    {
        if (status == 401)
        {
            return true;
        }

        if (status != 400 && status != 403)
        {
            return false;
        }

        // A 400 or a 403 is also what a credential that is valid and not allowed gets, and
        // what the content host answers after a redirect. Only a body that names the token
        // identifies it. With no body at hand, the manifest is asked for again with the
        // token held, which is cheap and has a body to read.
        if (!body.empty())
        {
            return registryRefusesTheToken(body);
        }

        if (m_probeUrl.empty())
        {
            return false;
        }

        std::vector<std::string> headers {acceptHeader(), authorizationHeader()};
        const HeaderScrubber scrubber {headers};
        HttpResponse probe;
        std::string ignored;

        if (!m_transport->get(m_probeUrl, headers, probe, ignored))
        {
            return false;
        }

        return probe.status == 401 ||
               ((probe.status == 400 || probe.status == 403) && registryRefusesTheToken(probe.body));
    }

    bool RegistryImageReader::renewAuthorization(const std::string& url,
                                                 const long status,
                                                 const std::string& body,
                                                 std::string& error)
    {
        if (m_tokenRefreshed)
        {
            return false;
        }

        // A token is dropped, and AWS signed for again, only when the registry says the
        // token is what it refused. A missing permission would be refused again by the next
        // token, and every reference of the registry would pay for a second signed call.
        if (m_reference.profile.usesBasicToken() ? !tokenIsRefused(status, body)
                                                 : !m_reference.profile.rejectsAuthorization(status))
        {
            return false;
        }

        // The token was asked for in a region other than the registry's, because the
        // configuration said so, and the registry refused it. A second token from the same
        // region would be refused the same way, so no second signed call is made, and the
        // reason says what to correct. Neither region is a secret.
        if (m_reference.profile.usesBasicToken() && m_regionOverridden)
        {
            m_tokenRefreshed = true;
            m_regionRefusal = "the registry refused the token requested in the configured region '" +
                              m_configuredRegion + "', and the registry host is in '" + m_reference.profile.region +
                              "'. The configured <region> overrides the host's, so it has to be the registry's "
                              "region. The token was not renewed";
            return false;
        }

        m_tokenRefreshed = true;

        if (m_reference.profile.usesBasicToken())
        {
            // The shared token is dropped with the reader's own, so the next reference of
            // this registry does not start from a token the registry has just refused.
            if (m_context.tokenCache != nullptr)
            {
                m_context.tokenCache->invalidate(m_ecrTokenKey);
            }

            m_token = Secret {};

            return acquireEcrToken(error);
        }

        HttpResponse challenge;

        const auto challenged {send([this, &url](HttpResponse & attemptResponse, std::string & attemptError)
        {
            return m_transport->get(url, {}, attemptResponse, attemptError);
        },
        challenge,
        error)};

        return challenged && challenge.status == 401 && authenticate(challenge.header("www-authenticate"), error);
    }

    bool RegistryImageReader::readAnonymously(const std::string& url,
                                              const std::string& challengeHeader,
                                              bool rememberScope,
                                              HttpResponse& response,
                                              std::string& error)
    {
        // Only GHCR serves some references anonymously and others to the credential. A
        // private Amazon ECR registry has no anonymous path, and a refused credential there
        // is the answer: its error stands and nothing is asked without it.
        if (!m_reference.profile.allowsAnonymousFallback())
        {
            return false;
        }

        // The error the refused credential produced is what the user can act on, so it is
        // the one reported when the anonymous attempt does not work either.
        const auto credentialError {error};
        std::string anonymousError;

        // authenticate() no longer sends the credential now that it was refused.
        if (authenticate(challengeHeader, anonymousError) && request(url, true, response, anonymousError) &&
                response.status >= 200 && response.status <= 299)
        {
            const auto* configured {m_context.config->credentialsFor(m_reference.registry)};

            // The reason is kept with the organization only when the token endpoint refused
            // the credential: a private reference that follows it in this scan no longer sends
            // it and can still say why. A refusal at a manifest speaks for this repository, so
            // the next reference sends the credential again. Not kept per host: a registry can
            // refuse per organization, and one refusal must not take the credential away from
            // the others.
            if (rememberScope && m_context.refusedCredentialScopes != nullptr)
            {
                m_context.refusedCredentialScopes->emplace(m_reference.refusalScope(), credentialError);
            }

            const auto firstReport {m_context.reportedRefusalHosts == nullptr ||
                                    m_context.reportedRefusalHosts->insert(m_reference.registry).second};

            if (firstReport)
            {
                logWarn("The credential configured for " + m_reference.registry + " (keys '" +
                        configured->userKey + "' and '" + configured->passkeyKey +
                        "') was refused by the registry. References on " + m_reference.registry +
                        " that need no credential are being read anonymously.");
            }

            return true;
        }

        m_token = Secret {};
        error = credentialError;

        return false;
    }

    bool RegistryImageReader::requestPrivateEcr(const std::string& url, HttpResponse& response, std::string& error)
    {
        auto answered {request(url, true, response, error)};

        // A private ECR registry refuses a stale token with 400, 401 or 403, depending on
        // how it was refused. The token is replaced once and the request repeated, when the
        // registry says the token is what it refused.
        if (answered ? response.status == 401 : m_reference.profile.rejectsAuthorization(response.status))
        {
            std::string renewError;

            if (renewAuthorization(url, response.status, response.body, renewError))
            {
                error.clear();
                answered = request(url, true, response, error);
            }
            else if (!m_regionRefusal.empty())
            {
                error = m_regionRefusal;
                rememberEcrRefusal(m_reference.refusalScope(), error);
                return false;
            }
            else if (!renewError.empty())
            {
                error = "the registry refused the credential, and a new one could not be obtained: " + renewError;
                return false;
            }
        }

        if (answered && response.status == 401)
        {
            // The credential is what the registry refused, and there is nothing to fall back
            // on: readAnonymously says no for a registry with no anonymous path, and this error
            // stands.
            error = "the registry rejected the credential" + reasonSuffix(response.body);
            m_credentialRefused = true;

            if (readAnonymously(url, response.header("www-authenticate"), false, response, error))
            {
                return true;
            }

            rememberEcrRefusal(m_reference.refusalScope(), error);
            return false;
        }

        if (!answered)
        {
            // A refusal of this credential for this repository, as opposed to a failure of the
            // network or of the registry, is remembered for the rest of the scan.
            if (response.status == 401 || response.status == 403 ||
                (response.status == 400 && registryDenies(response.body)))
            {
                rememberEcrRefusal(m_reference.refusalScope(), error);
            }

            return false;
        }

        return true;
    }

    void RegistryImageReader::rememberEcrRefusal(const std::string& scope, const std::string& reason)
    {
        // A refusal at the registry is keyed by the account host and the repository: an IAM
        // policy answers per repository, so one refusal says nothing about the others of the
        // same account. A refusal by AWS of the credential itself is keyed by the host, since
        // it says the same for every repository of the account. The reason is what the next
        // reference reports without asking again, and the memory ends with the scan.
        if (m_context.refusedCredentialScopes != nullptr && !reason.empty())
        {
            m_context.refusedCredentialScopes->emplace(scope, reason);
        }
    }

    bool RegistryImageReader::fetchManifest(const std::string& identifier,
                                            nlohmann::json& document,
                                            std::string& digest,
                                            std::string& error)
    {
        const auto url {"https://" + m_reference.registry + "/v2/" + m_reference.repository + "/manifests/" +
                        identifier};

        m_probeUrl = url;

        HttpResponse response;

        // A private ECR registry authenticates with a token that is obtained before the
        // first request, and refuses with 400, 401 or 403 rather than with a challenge.
        if (m_reference.profile.usesBasicToken())
        {
            if (!requestPrivateEcr(url, response, error))
            {
                return false;
            }
        }
        else if (!request(url, true, response, error))
        {
            return false;
        }

        if (response.status == 401 && !m_reference.profile.usesBasicToken())
        {
            const auto challengeHeader {response.header("www-authenticate")};

            if (!authenticate(challengeHeader, error))
            {
                // A credential the registry refused does not stop a public reference on the
                // same host, so it is tried once without it. Not again for a host that
                // already refused it in this scan: the anonymous attempt just failed.
                if (!m_credentialRefused || !m_hostRefusal.empty() ||
                        !readAnonymously(url, challengeHeader, true, response, error))
                {
                    return false;
                }
            }
            else
            {
                const auto answered {request(url, true, response, error)};
                const bool unauthorized = answered && response.status == 401;
                const bool forbidden = !answered && response.status == 403;

                if (unauthorized)
                {
                    error = m_credentialSent ? "the registry rejected the credential"
                            : "the registry requires a credential for this reference";
                }

                // A token issued for the credential that the manifest then refuses, as a
                // token without the scope the repository needs does. Handled like a
                // refusal at the token request.
                if ((unauthorized || forbidden) && m_credentialSent)
                {
                    m_credentialRefused = true;

                    if (!readAnonymously(url, challengeHeader, false, response, error))
                    {
                        return false;
                    }
                }
                else if (!answered || unauthorized)
                {
                    // A private reference whose credential was refused earlier in
                    // this scan for its organization is refused here for want of it, and the reason worth giving
                    // is the one the registry gave then.
                    if (!m_hostRefusal.empty() && (unauthorized || forbidden))
                    {
                        error = m_hostRefusal;
                    }

                    return false;
                }
            }
        }

        document = oci::parseJson(response.body);

        if (document.empty())
        {
            error = "the registry returned a manifest that could not be parsed";
            return false;
        }

        // What the registry says it served, else the digest the request named, else the
        // digest of the bytes as served. Metadata only, never part of an identity.
        digest = response.header("docker-content-digest");

        if (!oci::isSafeDigest(digest))
        {
            digest = oci::isSafeDigest(identifier) ? identifier : sha256Digest(response.body);
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

            const auto url {"https://" + m_reference.registry + "/v2/" + m_reference.repository + "/blobs/" +
                            digest};

            std::vector<std::string> headers;
            const HeaderScrubber scrubber {headers};

            if (!m_token.empty())
            {
                headers.push_back(authorizationHeader());
            }

            // A layer is retried like a metadata request is. A transfer that failed part
            // way cannot be resumed, so the attempt starts the layer again; a partially
            // consumed snapshot is discarded with the stream that produced it.
            LayerSnapshot snapshot;
            std::string failedCause;
            std::string renewError;
            bool skipped {false};

            // The size the manifest declares, which is what the transfer will deliver.
            // Zero when the manifest does not say, which leaves the ceiling to decide.
            const auto sizeNode {layer.find("size")};
            std::uint64_t layerSize {0};

            if (sizeNode != layer.end() && sizeNode->is_number_unsigned())
            {
                layerSize = sizeNode->get<std::uint64_t>();
            }

            for (int attempt = 1;; ++attempt)
            {
                // What is left of this image's allowance now, so one oversized layer cannot
                // be read just because it is the first, and the bytes a failed attempt
                // delivered are not allowed again to the next one.
                const auto remaining {limits.maxImageBytes > m_imageBytes ? limits.maxImageBytes - m_imageBytes : 0};

                if (attempt > 1 && (remaining == 0 || layerSize > remaining))
                {
                    // Another attempt could only end on the ceiling. What the user can act
                    // on is why the layer failed, not the allowance the failure left behind.
                    logDebug("Reference '" + m_location + "': layer " + digest.substr(0, 19) + " is not retried, " +
                             std::to_string(remaining) + " byte(s) of the image allowance are left.");
                    error = "layer " + digest.substr(0, 19) + " could not be retrieved: " + failedCause;
                    return false;
                }

                if (remaining == 0)
                {
                    error = "the image exceeded its " + std::to_string(limits.maxImageBytes) + " byte allowance";
                    return false;
                }

                if (layerSize > remaining)
                {
                    error = "layer " + digest.substr(0, 19) + " is " + std::to_string(layerSize) +
                            " bytes and the image has " + std::to_string(remaining) + " of its " +
                            std::to_string(limits.maxImageBytes) + " byte allowance left";
                    return false;
                }

                const auto blob {openBlob(url, headers, remaining)};
                LayerByteStream decompressed {*blob};
                const auto supported {isCompressionSupported(decompressed.compression())};

                // Bounded like the archive reader bounds a layer: the byte ceiling counts
                // compressed bytes, so a small blob can still expand without limit.
                StoppableByteStream stoppable {decompressed, m_context.stopRequested};
                BoundedByteStream bounded {stoppable, limits.maxLayerDecompressedBytes};

                if (supported)
                {
                    snapshot = readLayerSnapshot(bounded);
                }

                m_imageBytes += blob->bytesDelivered();

                if (m_context.scanBytes != nullptr)
                {
                    *m_context.scanBytes += blob->bytesDelivered();
                }

                if (!supported)
                {
                    logWarn("NOT IMPLEMENTED: layer '" + digest.substr(0, 19) + "' of '" + m_location + "' is " +
                            compressionName(decompressed.compression()) +
                            " compressed, which is recognized but not supported yet. Skipping it.");
                    skipped = true;
                    break;
                }

                // Reaching the limit ends the read like a truncated layer does, which a layer
                // of exactly that size does too. Only bytes still left past it tell them apart.
                char beyond {};

                if (bounded.remaining() == 0 && stoppable.read(&beyond, 1) > 0)
                {
                    error = "layer " + digest.substr(0, 19) + " expands to more than " +
                            std::to_string(limits.maxLayerDecompressedBytes) + " decompressed bytes, which is the limit";
                    return false;
                }

                // Whatever the snapshot says: a stop that cuts the layer between two tar
                // entries reads as its end, and a truncated layer stored as complete deletes
                // every package after the cut.
                if (m_context.stopRequested != nullptr && m_context.stopRequested->load())
                {
                    error = "the module was asked to stop";
                    return false;
                }

                if (!blob->failed())
                {
                    break;
                }

                failedCause = blob->error();

                // A token that expired part way through a large image is answered by
                // asking for another one, once, rather than by failing the reference. For
                // a private ECR registry only when the registry says the token is what it
                // refused: see renewAuthorization.
                if (renewAuthorization(url, blob->status(), {}, renewError))
                {
                    for (auto& header : headers)
                    {
                        scrubString(header);
                    }

                    headers.clear();
                    headers.push_back(authorizationHeader());
                    continue;
                }

                // This side ending the transfer, by a stop request, the idle bound or the
                // byte ceiling, is final: another attempt would only reach the same limit.
                RetryDecision decision;

                if (!blob->abortedLocally())
                {
                    // Once headers have arrived, the status is that of the response that
                    // started the transfer, 200 or a redirect's 3xx, and says nothing
                    // about why the body then failed. A reset, a TLS error and a stall
                    // are transport failures like any other.
                    const auto status {blob->status() < 400 ? TRANSPORT_FAILURE : blob->status()};

                    decision = m_retryPolicy.evaluate(status, blob->retryAfter(), attempt);
                }

                if (!decision.retry)
                {
                    // A layer that could not be retrieved makes the composed inventory a
                    // guess, and a guess stored as the complete state deletes whatever the
                    // reference really holds. Reported as a failed read instead.
                    error = "layer " + digest.substr(0, 19) + " could not be retrieved: " + blob->error();

                    if (m_reference.profile.usesBasicToken())
                    {
                        if (!m_regionRefusal.empty())
                        {
                            error += ", and " + m_regionRefusal;
                        }
                        else if (!renewError.empty())
                        {
                            error += ", and renewing the credential failed: " + renewError;
                        }
                    }

                    return false;
                }

                logDebug("Reference '" + m_location + "': layer " + digest.substr(0, 19) + " failed (" +
                         blob->error() + "), retrying in " + std::to_string(decision.delay.count()) + " ms.");

                if (!waitOrStop(decision.delay))
                {
                    error = "the module was asked to stop";
                    return false;
                }
            }

            if (skipped)
            {
                continue;
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
#ifdef WIN32
            // Refused before anything else, so no request is made that could never
            // inventory anything, and the reason is not mistaken for a certificate problem.
            logWarn("Reference '" + m_location + "' cannot be read: remote references are not supported on "
                    "Windows agents.");
            return ImageReadResult::failed();
#endif

            std::string error;

            if (!parseRegistryReference(m_location, m_reference, error))
            {
                logWarn("Reference '" + m_location + "' cannot be used: " + sentence(error));
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

            if (m_context.refusedCredentialScopes != nullptr)
            {
                // For a private ECR registry the credential refused by AWS is remembered under the
                // host, and a refusal at one repository under the repository.
                auto refused {m_context.refusedCredentialScopes->end()};
                auto refusedScope {m_reference.refusalScope()};

                if (m_reference.profile.usesBasicToken())
                {
                    refused = m_context.refusedCredentialScopes->find(m_reference.registry);
                    refusedScope = m_reference.registry;
                }

                if (refused == m_context.refusedCredentialScopes->end())
                {
                    refusedScope = m_reference.refusalScope();
                    refused = m_context.refusedCredentialScopes->find(refusedScope);
                }

                if (refused != m_context.refusedCredentialScopes->end())
                {
                    // Refused earlier in this scan: asking again would cost two token requests
                    // per reference to hear the same answer.
                    m_credentialRefused = true;
                    m_hostRefusal = refused->second;

                    if (m_reference.profile.usesBasicToken())
                    {
                        // Private ECR has no anonymous path to go to instead, so the reason the
                        // registry gave is the answer, and nothing is requested.
                        auto reason {m_hostRefusal};

                        // The reason may already be a sentence, and another follows it.
                        while (!reason.empty() && reason.back() == '.')
                        {
                            reason.pop_back();
                        }

                        logWarn("Reference '" + m_location + "' could not be resolved: " +
                                sentence(reason + ". An earlier reference of " + refusedScope +
                                         " was refused in this scan, so nothing was requested"));
                        return ImageReadResult::failed();
                    }

                    logDebug("Reference '" + m_location + "': the credential for " + m_reference.refusalScope() +
                             " was refused earlier in this scan, so it is not sent.");
                }
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
            m_transportConfig.blobIdleTimeoutMs = limits.blobIdleTimeoutMs;

            // An injected transport is left in place: a test supplies one and must not
            // have it replaced by a real one the moment discover() runs.
            if (!m_transportInjected)
            {
                m_transport = std::make_unique<CurlRegistryTransport>(m_transportConfig);
            }

            // A private ECR registry accepts nothing without a token that only a signed call
            // to AWS can obtain, so it is obtained first rather than after a request that
            // is certain to be refused. With no entry, or a credential the store does not
            // hold, the reference fails here, and no anonymous request is made.
            if (m_reference.profile.usesBasicToken() && !acquireEcrToken(error))
            {
                logWarn("Reference '" + m_location + "' could not be resolved: " + sentence(error));
                return ImageReadResult::failed();
            }

            nlohmann::json document;
            std::string manifestDigest;

            if (!fetchManifest(m_reference.identifier(), document, manifestDigest, error))
            {
                logWarn("Reference '" + m_location + "' could not be resolved: " + sentence(error));
                return ImageReadResult::failed();
            }

            PlatformManifest selected;

            if (!selectPlatformManifest(document, detectTargetPlatform(), selected, error))
            {
                logWarn("Reference '" + m_location + "' was not inventoried: " + sentence(error));
                return ImageReadResult::failed();
            }

            std::string selectedDigest;

            if (!selected.digest.empty() && !fetchManifest(selected.digest, document, selectedDigest, error))
            {
                logWarn("Reference '" + m_location + "' could not be resolved: " + sentence(error));
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
            record.tag = m_reference.fullName();

            if (!m_reference.tag.empty())
            {
                record.tags.push_back(m_reference.taggedName());
            }

            record.configDigest = configDigest;
            // The entry of an index names its manifest. A reference that pointed straight at
            // one has no entry, and the manifest it fetched is the one.
            record.manifestDigest = selected.digest.empty() ? manifestDigest : selected.digest;

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
                logWarn("Reference '" + m_location + "' could not be read: " + sentence(error));
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
            logWarn("Reference '" + m_location + "' could not be read: " + sentence(exception.what()));
            return ImageReadResult::failed();
        }
        catch (...)
        {
            logWarn("Reference '" + m_location + "' could not be read.");
            return ImageReadResult::failed();
        }
    }
} // namespace containerimages
