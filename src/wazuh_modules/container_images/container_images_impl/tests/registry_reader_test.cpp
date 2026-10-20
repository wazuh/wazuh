/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_images_config.hpp"
#include "credential_provider.hpp"
#include "registry_byte_stream.hpp"
#include "registry_image_reader.hpp"
#include "registry_transport.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace containerimages;

namespace
{
    /// @brief A scripted transport: answers by URL, and records what it was asked.
    ///
    /// This is what the injection seam exists for. The registry conversation is the part
    /// of the reader worth testing and the part that cannot reach a registry from a unit
    /// test, so every answer below is scripted and every request is observable.
    class ScriptedTransport final : public IRegistryTransport
    {
        public:
            struct Call
            {
                std::string url;
                std::vector<std::string> headers;
                bool basic {false};
                std::string user;
                std::string password;
            };

            /// Answers keyed by a substring of the URL, first match wins.
            std::vector<std::pair<std::string, HttpResponse>> answers;

            /// Answers that change from one request to the next, consulted before
            /// @ref answers. The last one repeats. A status of 0 stands for no response.
            struct Sequence
            {
                std::string fragment;
                std::vector<HttpResponse> responses;
                std::size_t next {0};
            };

            std::vector<Sequence> sequences;
            std::vector<Call> calls;
            bool refuse {false}; ///< When set, no response is produced at all.

            bool get(const std::string& url,
                     const std::vector<std::string>& headers,
                     HttpResponse& response,
                     std::string& error) override
            {
                calls.push_back({url, headers, false, {}, {}});

                return answer(url, response, error);
            }

            bool getWithBasicAuth(const std::string& url,
                                  const std::vector<std::string>& headers,
                                  const std::string& user,
                                  const Secret& password,
                                  HttpResponse& response,
                                  std::string& error) override
            {
                calls.push_back({url, headers, true, user, password.value()});

                return answer(url, response, error);
            }

            /// @brief How many requests mentioned @p fragment.
            std::size_t countMatching(const std::string& fragment) const
            {
                std::size_t total {0};

                for (const auto& call : calls)
                {
                    if (call.url.find(fragment) != std::string::npos)
                    {
                        ++total;
                    }
                }

                return total;
            }

        private:
            bool answer(const std::string& url, HttpResponse& response, std::string& error)
            {
                if (refuse)
                {
                    error = "scripted transport failure";
                    return false;
                }

                for (auto& sequence : sequences)
                {
                    if (url.find(sequence.fragment) != std::string::npos)
                    {
                        response = sequence.responses[std::min(sequence.next, sequence.responses.size() - 1)];
                        ++sequence.next;

                        if (response.status == 0)
                        {
                            error = "scripted transport failure";
                            return false;
                        }

                        return true;
                    }
                }

                for (const auto& entry : answers)
                {
                    if (url.find(entry.first) != std::string::npos)
                    {
                        response = entry.second;
                        return true;
                    }
                }

                response = {};
                response.status = 404;

                return true;
            }
    };

    /// @brief What became of one scripted layer transfer.
    struct BlobOutcome
    {
        bool failed {false};
        long status {200};
        std::string error {"scripted transfer failure"};
        std::uint64_t delivered {0}; ///< What bytesDelivered() reports, whatever was actually read.
        bool abortedLocally {false};
        std::string retryAfter;
    };

    /// @brief A layer blob that needs no network: an empty tar, or a scripted failure.
    class ScriptedBlob final : public IBlobStream
    {
        public:
            explicit ScriptedBlob(BlobOutcome outcome)
                : m_outcome {std::move(outcome)}
            {
            }

            std::size_t read(char* buffer, const std::size_t size) override
            {
                // A failed transfer reads as empty, as the real one does.
                if (m_outcome.failed || m_sent >= TAR_END_OF_ARCHIVE)
                {
                    return 0;
                }

                const auto count {std::min(size, TAR_END_OF_ARCHIVE - m_sent)};
                std::fill_n(buffer, count, '\0');
                m_sent += count;

                return count;
            }

            bool failed() const override
            {
                return m_outcome.failed;
            }

            const std::string& error() const override
            {
                return m_outcome.error;
            }

            long status() const override
            {
                return m_outcome.status;
            }

            std::uint64_t bytesDelivered() const override
            {
                return m_outcome.delivered;
            }

            bool abortedLocally() const override
            {
                return m_outcome.abortedLocally;
            }

            const std::string& retryAfter() const override
            {
                return m_outcome.retryAfter;
            }

        private:
            /// Two zero blocks, which is what ends a tar archive.
            static constexpr std::size_t TAR_END_OF_ARCHIVE {1024};

            BlobOutcome m_outcome;
            std::size_t m_sent {0};
    };

    /// @brief A credential provider with a fixed answer.
    class StubCredentials final : public ICredentialProvider
    {
        public:
            std::map<std::string, std::string> values;

            std::optional<Secret> get(const std::string& family, const std::string& key) const override
            {
                const auto entry {values.find(family + "/" + key)};

                if (entry == values.end())
                {
                    return std::nullopt;
                }

                return Secret {entry->second};
            }
    };

    HttpResponse challenge()
    {
        HttpResponse response;
        response.status = 401;
        response.headers["www-authenticate"] =
            R"(Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:owner/app:pull")";

        return response;
    }

    HttpResponse json(const long status, const std::string& body)
    {
        HttpResponse response;
        response.status = status;
        response.body = body;

        return response;
    }

    /// @brief The platform the suite is running on, which is what the reader will match.
    ///
    /// Built rather than hardcoded: an index of `linux/amd64` only matches on an amd64
    /// Linux builder, and this suite also runs on macOS and on arm64. Hardcoding it makes
    /// the tests assert where they happened to run rather than what the reader does.
    Platform hostPlatform()
    {
        return detectTargetPlatform();
    }

    /// @brief A platform the host is certainly not, for the negative cases.
    ///
    /// Differs by architecture, because the operating system is now always the
    /// container's and so is never what distinguishes a foreign image.
    Platform foreignPlatform()
    {
        const auto host {hostPlatform()};

        return {CONTAINER_OS, host.architecture == "s390x" ? "ppc64le" : "s390x", {}};
    }

    std::string platformJson(const Platform& platform)
    {
        auto entry {R"({"os":")" + platform.os + R"(","architecture":")" + platform.architecture + R"(")"};

        if (!platform.variant.empty())
        {
            entry += R"(,"variant":")" + platform.variant + R"(")";
        }

        return entry + "}";
    }

    /// @brief An index offering the host's platform first and a foreign one after it.
    std::string index()
    {
        return R"({"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaa1111",
             "platform":)" + platformJson(hostPlatform()) + R"(},
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbb2222",
             "platform":)" + platformJson(foreignPlatform()) + R"(}]})";
    }

    constexpr auto MANIFEST = R"({"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"digest":"sha256:cccc3333"},"layers":[]})";

    /// @brief A configuration blob describing the host's own platform.
    std::string configBlob()
    {
        return platformJson(hostPlatform());
    }

    /// @brief A configuration blob describing a platform the host is not.
    std::string foreignConfigBlob()
    {
        return platformJson(foreignPlatform());
    }

} // namespace

class RegistryReaderTest : public ::testing::Test
{
    protected:
        void TearDown() override
        {
            std::filesystem::remove_all(m_directory);
        }

        void SetUp() override
        {
            // A file this test owns, not a system path. The certificate resolution only
            // checks that the bundle exists, and /etc/ssl/certs/ca-certificates.crt does
            // not exist on macOS, where the reference then failed before it ever reached
            // the registry conversation these cases are about.
            m_directory = std::filesystem::temp_directory_path() /
                          ("ci_reader_" + std::string {::testing::UnitTest::GetInstance()
                                                           ->current_test_info()
                                                           ->name()});
            std::filesystem::create_directories(m_directory);
            m_caBundle = m_directory / "ca.pem";
            std::ofstream {m_caBundle} << "not a real certificate, only a file that exists\n";

            m_config.caBundle = m_caBundle.string();

            // The retry path is exercised, not waited on. The schedule itself is covered
            // by RetryPolicyTest against explicit attempt numbers.
            m_config.limits.retryBaseDelayMs = 1;
            m_transport = new ScriptedTransport();
        }

        /// @brief Build a reader over the scripted transport.
        ///
        /// The caller must keep the returned reader alive for as long as it inspects
        /// @ref m_transport: the reader owns the transport once it is injected, so a
        /// discarded reader takes the recorded calls with it.
        std::unique_ptr<RegistryImageReader> reader(const std::string& location,
                                                    const std::string& knownDigest = {})
        {
            const ReaderContext context {&m_config, &m_credentials, &m_scanBytes, nullptr};
            auto instance {std::make_unique<RegistryImageReader>(location, knownDigest, context)};
            instance->setTransport(std::unique_ptr<IRegistryTransport>(m_transport));

            return instance;
        }

        /// @brief The happy path: challenge, token, index, manifest, config.
        void scriptASuccessfulResolution()
        {
            m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
            m_transport->answers.push_back({"/manifests/1.0", json(200, index())});
            m_transport->answers.push_back({"/manifests/sha256:aaaa1111", json(200, MANIFEST)});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});
        }

        std::filesystem::path m_directory;
        std::filesystem::path m_caBundle;
        ContainerImagesConfig m_config;
        StubCredentials m_credentials;
        std::uint64_t m_scanBytes {0};
        ScriptedTransport* m_transport {nullptr}; ///< Owned by the reader once injected.
};

TEST_F(RegistryReaderTest, AnUnauthenticatedChallengeIsAnsweredWithAnAnonymousToken)
{
    // No credential is configured for the registry, so the token request must carry no
    // Basic credentials at all: that is what a public repository needs.
    m_transport->answers.push_back({"/manifests/1.0", challenge()});
    scriptASuccessfulResolution();

    // The 401 answer is consulted first, then replaced by the scripted success.
    m_transport->answers.insert(m_transport->answers.begin(), {"/manifests/1.0", challenge()});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    instance->discover();

    ASSERT_GE(m_transport->countMatching("/token"), 1u);

    for (const auto& call : m_transport->calls)
    {
        if (call.url.find("/token") != std::string::npos)
        {
            EXPECT_FALSE(call.basic) << "an anonymous token request must not carry credentials";
        }
    }
}

TEST_F(RegistryReaderTest, AConfiguredCredentialIsSentToTheTokenEndpoint)
{
    m_config.registryAuth.push_back({"ghcr.io", "ghcr_user", "ghcr_token"});
    m_credentials.values["container_images/ghcr_user"] = "owner";
    m_credentials.values["container_images/ghcr_token"] = "a-secret-token";

    m_transport->answers.push_back({"/manifests/1.0", challenge()});
    scriptASuccessfulResolution();
    m_transport->answers.insert(m_transport->answers.begin(), {"/manifests/1.0", challenge()});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    instance->discover();

    auto sawBasic {false};

    for (const auto& call : m_transport->calls)
    {
        if (call.url.find("/token") != std::string::npos && call.basic)
        {
            sawBasic = true;
            EXPECT_EQ(call.user, "owner");
            EXPECT_EQ(call.password, "a-secret-token");
        }
    }

    EXPECT_TRUE(sawBasic) << "the configured credential was never used";
}

TEST_F(RegistryReaderTest, AConfiguredCredentialMissingFromTheStoreFailsTheReference)
{
    // Configured but absent. The reference must fail rather than fall back to an
    // anonymous token, which would turn a credential problem into a confusing 404.
    m_config.registryAuth.push_back({"ghcr.io", "ghcr_user", "ghcr_token"});

    m_transport->answers.push_back({"/manifests/1.0", challenge()});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryReaderTest, ATokenEndpointOutsideTheRegistryIsRefused)
{
    // The realm arrives in a response header and decides where the credential goes. A
    // realm whose authority is not the reference's registry must not receive it.
    m_config.registryAuth.push_back({"ghcr.io", "ghcr_user", "ghcr_token"});
    m_credentials.values["container_images/ghcr_user"] = "owner";
    m_credentials.values["container_images/ghcr_token"] = "a-secret-token";

    auto hostile {challenge()};
    hostile.headers["www-authenticate"] = R"(Bearer realm="https://ghcr.io@attacker.example/token",service="ghcr.io")";
    m_transport->answers.push_back({"/manifests/1.0", hostile});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    for (const auto& call : m_transport->calls)
    {
        EXPECT_EQ(call.url.find("attacker.example"), std::string::npos)
            << "a credential request reached " << call.url;
        EXPECT_FALSE(call.basic) << "credentials were sent to " << call.url;
    }
}

TEST_F(RegistryReaderTest, AnUnchangedDigestRetrievesNoImageContents)
{
    scriptASuccessfulResolution();

    const auto instance = reader("ghcr.io/owner/app:1.0", "sha256:cccc3333");
    const auto result {instance->discover()};

    EXPECT_EQ(result.status, ReadStatus::Unchanged);
    EXPECT_TRUE(result.records.empty());

    // The acceptance criterion, asserted rather than inferred: the manifests are read to
    // learn the digest, and no blob is requested at all.
    EXPECT_EQ(m_transport->countMatching("/blobs/"), 0u);
    EXPECT_EQ(m_scanBytes, 0u);
}

TEST_F(RegistryReaderTest, AChangedDigestIsNotTreatedAsUnchanged)
{
    scriptASuccessfulResolution();

    const auto instance = reader("ghcr.io/owner/app:1.0", "sha256:somethingelse");
    const auto result {instance->discover()};

    EXPECT_NE(result.status, ReadStatus::Unchanged);
}

TEST_F(RegistryReaderTest, ThePlatformVariantMatchingTheAgentIsResolved)
{
    scriptASuccessfulResolution();

    const auto instance = reader("ghcr.io/owner/app:1.0");
    instance->discover();

    // amd64 is what this suite runs on, so the arm64 manifest must never be fetched.
    EXPECT_EQ(m_transport->countMatching("/manifests/sha256:aaaa1111"), 1u);
    EXPECT_EQ(m_transport->countMatching("/manifests/sha256:bbbb2222"), 0u);
}

TEST_F(RegistryReaderTest, AnIndexWithNoMatchingVariantFailsWithoutFetchingAnything)
{
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back(
        {"/manifests/1.0",
         json(200, R"({"manifests":[{"digest":"sha256:bbbb2222","platform":)" +
                   platformJson(foreignPlatform()) + R"(}]})")});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_transport->countMatching("/blobs/"), 0u);
}

TEST_F(RegistryReaderTest, ASingleManifestForAnotherPlatformIsRefused)
{
    // The gap a review found: a bare manifest carries no platform, so the check has to
    // happen against the configuration blob. Without it an arm64-only image is
    // inventoried on an amd64 agent and recorded as though it were native.
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/manifests/1.0", json(200, MANIFEST)});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, foreignConfigBlob())});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryReaderTest, ASingleManifestForTheAgentPlatformIsAccepted)
{
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/manifests/1.0", json(200, MANIFEST)});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    const auto result {instance->discover()};

    // No layers in the scripted manifest, so this succeeds with an empty package set.
    EXPECT_EQ(result.status, ReadStatus::Success);
}

TEST_F(RegistryReaderTest, ASingleManifestWithAnUnreadableConfigurationIsRefused)
{
    // Nothing else can confirm the platform, so it is not inventoried on a guess.
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/manifests/1.0", json(200, MANIFEST)});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(500, "")});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryReaderTest, AnUnparseableManifestFailsTheReference)
{
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/manifests/1.0", json(200, "{not json")});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryReaderTest, ATransportThatProducesNoResponseFailsTheReference)
{
    m_transport->refuse = true;

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryReaderTest, ARepeatedRejectionOfTheCredentialIsReportedNotRetriedForever)
{
    // Every manifest request answers 401. The reader must give up rather than loop.
    m_config.registryAuth.push_back({"ghcr.io", "ghcr_user", "ghcr_token"});
    m_credentials.values["container_images/ghcr_user"] = "owner";
    m_credentials.values["container_images/ghcr_token"] = "a-secret-token";

    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/manifests/", challenge()});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryReaderTest, TheScanByteCeilingStopsTheReferenceBeforeItStarts)
{
    m_config.limits.maxScanBytes = 1024;
    m_scanBytes = 2048;

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    // Refused before any request, so the scan does not spend a round trip discovering
    // that it has no allowance left.
    EXPECT_TRUE(m_transport->calls.empty());
}

TEST_F(RegistryReaderTest, AnUnsupportedRegistryNeverReachesTheTransport)
{
    const auto instance = reader("docker.io/library/alpine:latest");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_transport->calls.empty());
}

TEST_F(RegistryReaderTest, AMissingCertificateBundleFailsBeforeAnyRequest)
{
    m_config.caBundle = "/etc/ssl/certs/does-not-exist-38587.crt";

    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_transport->calls.empty());
}

TEST_F(RegistryReaderTest, TheSourceTypeIsTheConfigurationEntryName)
{
    const auto instance = reader("ghcr.io/owner/app:1.0");
    EXPECT_EQ(instance->sourceType(), "ref");
}

// The token exchange is a request like any other: the first one of every scan against a
// private repository, and as exposed to throttling and resets as a manifest request.
class RegistryTokenRetryTest : public RegistryReaderTest
{
    protected:
        void SetUp() override
        {
            RegistryReaderTest::SetUp();

            m_config.registryAuth.push_back({"ghcr.io", "ghcr_user", "ghcr_token"});
            m_credentials.values["container_images/ghcr_user"] = "owner";
            m_credentials.values["container_images/ghcr_token"] = "a-secret-token";

            // Challenged once, then served.
            m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});
        }

        std::size_t basicTokenCalls() const
        {
            return static_cast<std::size_t>(std::count_if(m_transport->calls.begin(),
                                                          m_transport->calls.end(),
                                                          [](const ScriptedTransport::Call & call)
            {
                return call.basic && call.url.find("/token") != std::string::npos;
            }));
        }
};

TEST_F(RegistryTokenRetryTest, AThrottledTokenEndpointIsRetried)
{
    m_transport->sequences.push_back({"/token", {json(429, ""), json(200, R"({"token":"scripted-token"})")}, 0});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(basicTokenCalls(), 2u);
}

TEST_F(RegistryTokenRetryTest, ATokenRequestThatProducesNoResponseIsRetried)
{
    m_transport->sequences.push_back({"/token", {json(0, ""), json(200, R"({"token":"scripted-token"})")}, 0});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(basicTokenCalls(), 2u);
}

TEST_F(RegistryTokenRetryTest, AnAnonymousTokenRequestIsRetriedToo)
{
    m_config.registryAuth.clear();
    m_transport->sequences.push_back({"/token", {json(503, ""), json(200, R"({"token":"scripted-token"})")}, 0});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_transport->countMatching("/token"), 2u);
}

TEST_F(RegistryTokenRetryTest, ATokenEndpointThatStaysUnavailableGivesUpAfterTheConfiguredAttempts)
{
    m_transport->answers.push_back({"/token", json(503, "")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(basicTokenCalls(), static_cast<std::size_t>(m_config.limits.maxAttempts));
}

TEST_F(RegistryTokenRetryTest, ARejectedCredentialIsNotRetried)
{
    // Repeating a wrong password gains nothing, and against a registry that locks an
    // account out it costs something.
    m_transport->answers.push_back({"/token", json(401, "")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(basicTokenCalls(), 1u);
}

// What a layer does when its transfer fails. The transfer is stood in for by a scripted
// blob, since the real one needs a registry, and what is asserted is the reader's decision:
// whether another attempt is made, with what allowance, and after how long.
class RegistryLayerRetryTest : public RegistryReaderTest
{
    protected:
        static constexpr auto MANIFEST_WITH_A_LAYER = R"({"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"digest":"sha256:cccc3333"},"layers":[{"digest":"sha256:dddd4444"}]})";

        void SetUp() override
        {
            RegistryReaderTest::SetUp();

            m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
            m_transport->answers.push_back({"/manifests/1.0", json(200, MANIFEST_WITH_A_LAYER)});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});
        }

        /// @brief A reader whose layer attempts end as @p outcomes, the last one repeating.
        std::unique_ptr<RegistryImageReader> layerReader(std::vector<BlobOutcome> outcomes)
        {
            m_outcomes = std::move(outcomes);

            auto instance {reader("ghcr.io/owner/app:1.0")};
            instance->setBlobStreamFactory([this](const TransportConfig&,
                                                  const std::string&,
                                                  const std::vector<std::string>& headers,
                                                  const std::uint64_t maxBytes,
                                                  const std::atomic<bool>*)
            {
                m_attemptHeaders.push_back(headers);
                m_attemptLimits.push_back(maxBytes);

                const auto index {std::min(m_attemptLimits.size(), m_outcomes.size()) - 1};

                return std::unique_ptr<IBlobStream> {std::make_unique<ScriptedBlob>(m_outcomes[index])};
            });

            return instance;
        }

        static BlobOutcome failure(const long status, const std::uint64_t delivered = 0)
        {
            BlobOutcome outcome;
            outcome.failed = true;
            outcome.status = status;
            outcome.delivered = delivered;

            return outcome;
        }

        std::vector<BlobOutcome> m_outcomes;
        std::vector<std::vector<std::string>> m_attemptHeaders;
        std::vector<std::uint64_t> m_attemptLimits;
};

TEST_F(RegistryLayerRetryTest, ALayerThatFailsAfterItsHeadersArrivedIsRetried)
{
    // The status is 200 by the time a body byte can fail: a reset, a TLS error and a
    // stall all arrive here, and none of them says the request was wrong.
    const auto instance = layerReader({failure(200), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_attemptLimits.size(), 2u);
}

TEST_F(RegistryLayerRetryTest, ALayerWhoseRedirectTargetFailedIsRetried)
{
    // The registry answered 307 and the content host could not be reached, so the last
    // status seen is the redirect's.
    const auto instance = layerReader({failure(307), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_attemptLimits.size(), 2u);
}

TEST_F(RegistryLayerRetryTest, ALayerThatNeverGotAResponseIsRetried)
{
    const auto instance = layerReader({failure(0), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_attemptLimits.size(), 2u);
}

TEST_F(RegistryLayerRetryTest, AnUnavailableRegistryIsRetriedForALayer)
{
    const auto instance = layerReader({failure(503), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_attemptLimits.size(), 2u);
}

TEST_F(RegistryLayerRetryTest, ALayerTheRegistryRefusesIsNotRetried)
{
    const auto instance = layerReader({failure(404), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_attemptLimits.size(), 1u);
}

TEST_F(RegistryLayerRetryTest, ATransferEndedByThisSideIsNotRetried)
{
    // A stop request, the idle bound and the byte ceiling each end the transfer here, and
    // another attempt would only reach the same limit again.
    auto aborted {failure(200)};
    aborted.abortedLocally = true;

    const auto instance = layerReader({aborted, BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_attemptLimits.size(), 1u);
}

TEST_F(RegistryLayerRetryTest, ALayerThatKeepsFailingGivesUpAfterTheConfiguredAttempts)
{
    const auto instance = layerReader({failure(200)});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_attemptLimits.size(), static_cast<std::size_t>(m_config.limits.maxAttempts));
}

TEST_F(RegistryLayerRetryTest, TheRetryAfterOfALayerIsHonoured)
{
    // The back-off is one millisecond in this suite, so waiting for the second the
    // registry asked for can only come from the header.
    auto throttled {failure(429)};
    throttled.retryAfter = "1";

    const auto start {std::chrono::steady_clock::now()};
    const auto instance = layerReader({throttled, BlobOutcome {}});
    const auto result {instance->discover()};
    const auto elapsed {std::chrono::steady_clock::now() - start};

    EXPECT_EQ(result.status, ReadStatus::Success);
    EXPECT_GE(elapsed, std::chrono::milliseconds {900});
}

TEST_F(RegistryLayerRetryTest, EachAttemptIsAllowedOnlyWhatTheEarlierOnesLeftOfTheImage)
{
    // Every attempt delivers bytes before it fails. Allowing each the whole ceiling again
    // would pull a multiple of it for one image.
    m_config.limits.maxImageBytes = 100;

    const auto instance = layerReader({failure(200, 60), failure(200, 40), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    ASSERT_EQ(m_attemptLimits.size(), 2u);
    EXPECT_EQ(m_attemptLimits[0], 100u);
    EXPECT_EQ(m_attemptLimits[1], 40u);

    // The failed attempts were paid for, in the image and in the scan.
    EXPECT_EQ(m_scanBytes, 100u);
}

TEST_F(RegistryLayerRetryTest, AnExpiredTokenIsRefreshedOnceAndTheLayerIsAskedForAgain)
{
    m_transport->answers.insert(m_transport->answers.begin(), {"/blobs/sha256:dddd4444", challenge()});

    const auto instance = layerReader({failure(401), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    ASSERT_EQ(m_attemptHeaders.size(), 2u);
    EXPECT_TRUE(m_attemptHeaders[0].empty());
    ASSERT_EQ(m_attemptHeaders[1].size(), 1u);
    EXPECT_EQ(m_attemptHeaders[1][0], "Authorization: Bearer scripted-token");
    EXPECT_EQ(m_transport->countMatching("/token"), 1u);
}

TEST_F(RegistryLayerRetryTest, ARefreshThatIsAnsweredByAThrottledEndpointIsRetried)
{
    m_transport->answers.insert(m_transport->answers.begin(), {"/blobs/sha256:dddd4444", challenge()});
    m_transport->sequences.push_back({"/token", {json(429, ""), json(200, R"({"token":"scripted-token"})")}, 0});

    const auto instance = layerReader({failure(401), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_transport->countMatching("/token"), 2u);
}

TEST_F(RegistryLayerRetryTest, ARefreshIsAttemptedOnlyOncePerReference)
{
    m_transport->answers.insert(m_transport->answers.begin(), {"/blobs/sha256:dddd4444", challenge()});

    const auto instance = layerReader({failure(401)});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_transport->countMatching("/token"), 1u);
}
