/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "aws_sigv4.hpp"
#include "ci_logging_helper.hpp"
#include "container_images_config.hpp"
#include "credential_provider.hpp"
#include "ecr_token_client.hpp"
#include "image_fixtures.hpp"
#include "registry_byte_stream.hpp"
#include "registry_image_reader.hpp"
#include "registry_token_cache.hpp"
#include "registry_transport.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
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

            /// Answers given once, in order, after @ref sequences and before @ref answers. Lets
            /// a test script a refusal followed by a success for the same URL.
            std::map<std::string, std::deque<HttpResponse>> queued;

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

                for (auto& entry : queued)
                {
                    if (!entry.second.empty() && url.find(entry.first) != std::string::npos)
                    {
                        response = entry.second.front();
                        entry.second.pop_front();
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
        std::string content;         ///< What the blob serves, an empty tar when left empty.
        std::function<void()> onEnd; ///< Called once the last byte of @ref content was served.
        std::size_t atOffset {0};    ///< Where @ref onOffset fires, counted in bytes of @ref content.
        std::function<void()> onOffset; ///< Called once, when the bytes served reach @ref atOffset.
    };

    /// @brief A layer blob that needs no network: an empty tar, a scripted body or a scripted failure.
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
                if (m_outcome.failed)
                {
                    return 0;
                }

                if (!m_outcome.content.empty())
                {
                    const auto left {m_outcome.content.size() - m_sent};
                    const auto served {std::min(size, left)};

                    std::copy_n(m_outcome.content.data() + m_sent, served, buffer);
                    m_sent += served;

                    if (m_outcome.onOffset && m_sent >= m_outcome.atOffset)
                    {
                        const auto fire {std::move(m_outcome.onOffset)};
                        m_outcome.onOffset = nullptr;
                        fire();
                    }

                    if (served > 0 && m_sent == m_outcome.content.size() && m_outcome.onEnd)
                    {
                        m_outcome.onEnd();
                    }

                    return served;
                }

                if (m_sent >= TAR_END_OF_ARCHIVE)
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

    /// @brief No response, and one that would fail the same way on every attempt.
    HttpResponse permanentFailure()
    {
        HttpResponse response;
        response.status = 0;
        response.retryable = false;

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
            const ReaderContext context {&m_config, &m_credentials, &m_scanBytes, &m_stop, &m_refusedScopes, &m_reportedHosts};
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
        std::map<std::string, std::string> m_refusedScopes; ///< The registry and organization pairs one scan shares across its references.
        std::set<std::string> m_reportedHosts; ///< The hosts whose refusal the scan already reported.
        std::atomic<bool> m_stop {false};
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

// The name a remote image is stored under. It is the whole reference, so it does not
// depend on the source that read the image and does not collide across repositories.
class RegistryImageNameTest : public RegistryReaderTest
{
    protected:
        static constexpr auto DIGEST = "sha256:2f3a4b5c6d7e8f9001122334455667788";

        /// @brief The record @p location produced, on a registry that serves it publicly.
        ImageReferenceRecord discovered(const std::string& location)
        {
            // The first matching answer wins, so the platform manifest comes before the
            // index that every other manifest request is answered with.
            m_transport->answers.push_back({"/manifests/sha256:aaaa1111", json(200, MANIFEST)});
            m_transport->answers.push_back({"/manifests/", json(200, index())});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

            const auto instance = reader(location);
            auto result {instance->discover()};

            EXPECT_EQ(result.status, ReadStatus::Success) << location;
            EXPECT_EQ(result.records.size(), 1u) << location;

            if (result.records.empty())
            {
                return {};
            }

            return result.records.front();
        }
};

TEST_F(RegistryImageNameTest, ATaggedReferenceIsNamedByItsRepositoryAndTag)
{
    const auto record {discovered("ghcr.io/owner/app:1.0")};

    EXPECT_EQ(record.tag, "ghcr.io/owner/app:1.0");
    EXPECT_EQ(record.tags, std::vector<std::string>({"ghcr.io/owner/app:1.0"}));
}

TEST_F(RegistryImageNameTest, ARepositoryAndATagThatAreNotWrittenOutAreStillNamed)
{
    // No tag written, so latest is assumed, and it is the name the image is stored under.
    const auto record {discovered("ghcr.io/owner/app")};

    EXPECT_EQ(record.tag, "ghcr.io/owner/app:latest");
    EXPECT_EQ(record.tags, std::vector<std::string>({"ghcr.io/owner/app:latest"}));
}

TEST_F(RegistryImageNameTest, TheSameTagInTwoRepositoriesIsTwoNames)
{
    const auto first {discovered("ghcr.io/owner/app:latest")};

    m_transport = new ScriptedTransport();
    const auto second {discovered("ghcr.io/other/tool:latest")};

    EXPECT_NE(first.tag, second.tag);
    EXPECT_EQ(first.tag, "ghcr.io/owner/app:latest");
    EXPECT_EQ(second.tag, "ghcr.io/other/tool:latest");
}

TEST_F(RegistryImageNameTest, ATagBesideADigestIsKeptInTheName)
{
    const auto record {discovered(std::string {"ghcr.io/owner/app:1.4@"} + DIGEST)};

    EXPECT_EQ(record.tag, std::string {"ghcr.io/owner/app:1.4@"} + DIGEST);
    EXPECT_EQ(record.tags, std::vector<std::string>({"ghcr.io/owner/app:1.4"}));
}

TEST_F(RegistryImageNameTest, ADigestOnItsOwnIsNamedByItsRepositoryAndDigest)
{
    const auto record {discovered(std::string {"ghcr.io/owner/app@"} + DIGEST)};

    EXPECT_EQ(record.tag, std::string {"ghcr.io/owner/app@"} + DIGEST);
    EXPECT_TRUE(record.tags.empty());
}

// The manifest digest is metadata, and an image read by its manifest has no index entry to
// take it from.
class RegistryManifestDigestTest : public RegistryReaderTest
{
    protected:
        /// A compact manifest, so the digest of its bytes is stated rather than computed here.
        static constexpr auto BARE_MANIFEST =
            R"({"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:cccc3333"},"layers":[]})";
        static constexpr auto BARE_MANIFEST_SHA256 =
            "sha256:b4bf1501963ec03e3ffcb408df4129ea9db23229c847d077be1f55e206850118";

        ImageReferenceRecord discovered(const std::string& location, HttpResponse manifest)
        {
            m_transport->answers.push_back({"/manifests/", std::move(manifest)});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

            const auto instance = reader(location);
            auto result {instance->discover()};

            EXPECT_EQ(result.status, ReadStatus::Success) << location;
            EXPECT_EQ(result.records.size(), 1u) << location;

            if (result.records.empty())
            {
                return {};
            }

            return result.records.front();
        }
};

TEST_F(RegistryManifestDigestTest, AReferenceResolvedThroughAnIndexCarriesTheDigestOfItsEntry)
{
    m_transport->answers.push_back({"/manifests/sha256:aaaa1111", json(200, MANIFEST)});
    m_transport->answers.push_back({"/manifests/", json(200, index())});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto instance = reader("ghcr.io/owner/app:1.0");
    const auto result {instance->discover()};

    ASSERT_EQ(result.records.size(), 1u);
    EXPECT_EQ(result.records.front().manifestDigest, "sha256:aaaa1111");
}

TEST_F(RegistryManifestDigestTest, ASingleManifestCarriesTheDigestTheRegistryReports)
{
    auto manifest {json(200, BARE_MANIFEST)};
    manifest.headers["docker-content-digest"] = "sha256:5e5e5e5e";

    EXPECT_EQ(discovered("ghcr.io/owner/app:1.0", manifest).manifestDigest, "sha256:5e5e5e5e");
}

TEST_F(RegistryManifestDigestTest, TheDigestAReferenceIsPinnedToIsUsedWhenTheRegistryReportsNone)
{
    const std::string pinned {"sha256:2f3a4b5c6d7e8f9001122334455667788"};

    EXPECT_EQ(discovered("ghcr.io/owner/app@" + pinned, json(200, BARE_MANIFEST)).manifestDigest, pinned);
}

TEST_F(RegistryManifestDigestTest, TheHeaderWinsOverTheDigestAReferenceIsPinnedTo)
{
    auto manifest {json(200, BARE_MANIFEST)};
    manifest.headers["docker-content-digest"] = "sha256:5e5e5e5e";

    EXPECT_EQ(discovered("ghcr.io/owner/app@sha256:2f3a4b5c6d7e8f9001122334455667788", manifest).manifestDigest,
              "sha256:5e5e5e5e");
}

TEST_F(RegistryManifestDigestTest, ATaggedSingleManifestWithNoHeaderIsHashedAsServed)
{
    EXPECT_EQ(discovered("ghcr.io/owner/app:1.0", json(200, BARE_MANIFEST)).manifestDigest, BARE_MANIFEST_SHA256);
}

TEST_F(RegistryManifestDigestTest, AHeaderThatIsNotADigestIsIgnored)
{
    auto manifest {json(200, BARE_MANIFEST)};
    manifest.headers["docker-content-digest"] = "not a digest";

    EXPECT_EQ(discovered("ghcr.io/owner/app:1.0", manifest).manifestDigest, BARE_MANIFEST_SHA256);
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

// A failure that repeats the same way, as a certificate that does not verify or a response
// over the size limit, is attempted once: the retries would only spend their back-off.
TEST_F(RegistryTokenRetryTest, ATokenRequestThatFailsTheSameWayEveryTimeIsAttemptedOnce)
{
    m_transport->sequences.push_back({"/token", {permanentFailure(), json(200, R"({"token":"scripted-token"})")}, 0});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(basicTokenCalls(), 1u);
}

TEST_F(RegistryReaderTest, AManifestRequestThatFailsTheSameWayEveryTimeIsAttemptedOnce)
{
    m_transport->sequences.push_back({"/manifests/1.0", {permanentFailure(), json(200, MANIFEST)}, 0});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_transport->countMatching("/manifests/"), 1u);
}

TEST_F(RegistryReaderTest, AManifestRequestThatFailsOnTheNetworkIsStillRetried)
{
    m_transport->sequences.push_back({"/manifests/1.0", {json(0, ""), json(200, MANIFEST)}, 0});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_transport->countMatching("/manifests/"), 2u);
}

// A credential the registry refuses at the token request must not cost the public
// references on the same host. The reference is read once without it, and the user is told.
class RegistryCredentialFallbackTest : public RegistryReaderTest
{
    protected:
        static constexpr auto USER = "scripted-user-name";
        static constexpr auto PASSKEY = "scripted-secret-value";

        void SetUp() override
        {
            RegistryReaderTest::SetUp();

            m_config.registryAuth.push_back({"ghcr.io", "ghcr_user", "ghcr_token"});
            m_credentials.values["container_images/ghcr_user"] = USER;
            m_credentials.values["container_images/ghcr_token"] = PASSKEY;

            LoggingHelper::setLogCallback([this](const modules_log_level_t level, const char* message)
            {
                if (level == LOG_WARNING)
                {
                    m_warnings.push_back(message);
                }
            });
        }

        void TearDown() override
        {
            LoggingHelper::setLogCallback({});
            RegistryReaderTest::TearDown();
        }

        /// @brief A public reference: challenged, then served. The token endpoint answers
        /// @p credentialedAnswer to the credentialed request and a token to the anonymous one.
        void scriptPublicReference(const HttpResponse& credentialedAnswer)
        {
            m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
            m_transport->sequences.push_back(
            {"/token", {credentialedAnswer, json(200, R"({"token":"anonymous-token"})")}, 0});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});
        }

        /// @brief A private reference: every manifest request is challenged, and the
        /// anonymous token, though issued, does not open it.
        void scriptPrivateReference(const HttpResponse& credentialedAnswer)
        {
            m_transport->answers.push_back({"/manifests/1.0", challenge()});
            m_transport->sequences.push_back(
            {"/token", {credentialedAnswer, json(200, R"({"token":"anonymous-token"})")}, 0});
        }

        /// @brief A public reference on a host that refused the credential earlier in the scan:
        /// no credential is presented, so the anonymous token is the only one asked for.
        void scriptPublicReferenceWithoutCredential()
        {
            m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
            m_transport->answers.push_back({"/token", json(200, R"({"token":"anonymous-token"})")});
            m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});
        }

        std::size_t credentialedTokenCalls() const
        {
            return static_cast<std::size_t>(std::count_if(m_transport->calls.begin(),
                                                          m_transport->calls.end(),
                                                          [](const ScriptedTransport::Call & call)
            {
                return call.basic && call.url.find("/token") != std::string::npos;
            }));
        }

        std::size_t anonymousTokenCalls() const
        {
            return static_cast<std::size_t>(std::count_if(m_transport->calls.begin(),
                                                          m_transport->calls.end(),
                                                          [](const ScriptedTransport::Call & call)
            {
                return !call.basic && call.url.find("/token") != std::string::npos;
            }));
        }

        std::size_t warningsMentioning(const std::string& fragment) const
        {
            return static_cast<std::size_t>(std::count_if(m_warnings.begin(),
                                                          m_warnings.end(),
                                                          [&fragment](const std::string & line)
            {
                return line.find(fragment) != std::string::npos;
            }));
        }

        std::vector<std::string> m_warnings;
};

TEST_F(RegistryCredentialFallbackTest, ARefusedCredentialStillInventoriesAPublicReference)
{
    scriptPublicReference(json(403, ""));

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(anonymousTokenCalls(), 1u);
    EXPECT_EQ(m_warnings.size(), 1u);
    EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 1u);
    EXPECT_EQ(warningsMentioning("read anonymously"), 1u);
}

TEST_F(RegistryCredentialFallbackTest, ACredentialAnsweredWithA401IsHandledLikeA403)
{
    scriptPublicReference(json(401, ""));

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(anonymousTokenCalls(), 1u);
    EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 1u);
}

TEST_F(RegistryCredentialFallbackTest, TheWarningNamesTheKeysAndNeverTheirValues)
{
    scriptPublicReference(json(403, ""));

    const auto instance = reader("ghcr.io/owner/app:1.0");
    instance->discover();

    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("ghcr_user"), std::string::npos);
    EXPECT_NE(m_warnings.front().find("ghcr_token"), std::string::npos);
    EXPECT_EQ(m_warnings.front().find(USER), std::string::npos);
    EXPECT_EQ(m_warnings.front().find(PASSKEY), std::string::npos);
}

TEST_F(RegistryCredentialFallbackTest, APrivateReferenceKeepsTheOriginalCredentialError)
{
    // The anonymous token is issued but does not open the repository, so the fallback
    // fails too and the user is shown what they can fix: the credential.
    scriptPrivateReference(json(403, ""));

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(anonymousTokenCalls(), 1u);
    ASSERT_EQ(m_warnings.size(), 1u) << "one line per failed reference, and no refusal notice";
    EXPECT_NE(m_warnings.front().find("could not be resolved: the token request failed: the registry answered 403."),
              std::string::npos)
            << m_warnings.front();
}

TEST_F(RegistryCredentialFallbackTest, AnAnonymousTokenRequestThatIsRefusedTooKeepsTheOriginalError)
{
    m_transport->answers.push_back({"/manifests/1.0", challenge()});
    m_transport->answers.push_back({"/token", json(403, "")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("could not be resolved: the token request failed: the registry answered 403."),
              std::string::npos)
            << m_warnings.front();
}

TEST_F(RegistryCredentialFallbackTest, ARefusedCredentialAnsweredWithA401KeepsItsOwnError)
{
    scriptPrivateReference(json(401, ""));

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("the registry refused to issue a token, answering 401."),
              std::string::npos)
            << m_warnings.front();
}

TEST_F(RegistryCredentialFallbackTest, AValidCredentialMakesNoAnonymousRequest)
{
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(anonymousTokenCalls(), 0u);
    EXPECT_TRUE(m_warnings.empty());
}

TEST_F(RegistryCredentialFallbackTest, ACredentialMissingFromTheStoreIsNotReplacedByAnAnonymousRequest)
{
    m_credentials.values.clear();
    m_transport->answers.push_back({"/manifests/1.0", challenge()});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_transport->countMatching("/token"), 0u);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("is missing from the agent credential store"), std::string::npos);
}

TEST_F(RegistryCredentialFallbackTest, ATransportFailureOrThrottlingIsNotAnAnonymousCase)
{
    // Neither says anything about the credential, so no anonymous request is made.
    m_transport->sequences.push_back({"/manifests/1.0", {challenge()}, 0});
    m_transport->answers.push_back({"/token", json(503, "")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(anonymousTokenCalls(), 0u);
}

// A token can be issued for the credential and the manifest still refused, as it is for a
// token without the scope the repository needs. That is a refusal of the credential too.
TEST_F(RegistryCredentialFallbackTest, AManifestRefusedAfterATokenWasIssuedStillInventoriesAPublicReference)
{
    const std::vector<long> refusals {403, 401};

    for (const auto refusal : refusals)
    {
        m_warnings.clear();
        m_transport = new ScriptedTransport();
        m_refusedScopes.clear();
        m_reportedHosts.clear();

        m_transport->sequences.push_back(
        {"/manifests/1.0", {challenge(), json(refusal, ""), json(200, MANIFEST)}, 0});
        m_transport->sequences.push_back(
        {"/token", {json(200, R"({"token":"scoped-token"})"), json(200, R"({"token":"anonymous-token"})")}, 0});
        m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

        const auto instance = reader("ghcr.io/owner/app:1.0");

        EXPECT_EQ(instance->discover().status, ReadStatus::Success) << refusal;
        EXPECT_EQ(anonymousTokenCalls(), 1u) << refusal;
        EXPECT_EQ(m_transport->countMatching("/token"), 2u) << refusal;
        EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 1u) << refusal;
        EXPECT_EQ(m_warnings.size(), 1u) << refusal;
    }
}

TEST_F(RegistryCredentialFallbackTest, TheAnonymousRetryAfterAManifestRefusalCarriesNoCredential)
{
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(403, ""), json(200, MANIFEST)}, 0});
    m_transport->sequences.push_back(
    {"/token", {json(200, R"({"token":"scoped-token"})"), json(200, R"({"token":"anonymous-token"})")}, 0});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    ASSERT_EQ(instance->discover().status, ReadStatus::Success);

    std::vector<std::string> manifestAuthorizations;

    for (const auto& call : m_transport->calls)
    {
        if (call.url.find("/manifests/") != std::string::npos && call.headers.size() > 1)
        {
            manifestAuthorizations.push_back(call.headers[1]);
        }
    }

    EXPECT_EQ(manifestAuthorizations,
              std::vector<std::string>({"Authorization: Bearer scoped-token", "Authorization: Bearer anonymous-token"}));
}

TEST_F(RegistryCredentialFallbackTest, APrivateReferenceRefusedAtTheManifestKeepsTheOriginalError)
{
    // The anonymous token is issued too and the manifest is refused again, so the user is
    // shown the refusal of the credential, which is the one they can act on.
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(403, "")}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scoped-token"})")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(anonymousTokenCalls(), 1u);
    ASSERT_EQ(m_warnings.size(), 1u) << "one line per failed reference, and no refusal notice";
    EXPECT_NE(m_warnings.front().find("could not be resolved: the registry answered 403."), std::string::npos)
            << m_warnings.front();
}

TEST_F(RegistryCredentialFallbackTest, APrivateReferenceRefusedWith401AtTheManifestKeepsItsOwnError)
{
    m_transport->sequences.push_back({"/manifests/1.0", {challenge()}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scoped-token"})")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(anonymousTokenCalls(), 1u);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("could not be resolved: the registry rejected the credential."),
              std::string::npos)
            << m_warnings.front();
}

TEST_F(RegistryCredentialFallbackTest, AnAnonymousRequestRefusedWith401AtTheManifestSaysACredentialIsRequired)
{
    // Nothing was sent, so the registry cannot have rejected a credential.
    m_config.registryAuth.clear();
    m_transport->sequences.push_back({"/manifests/1.0", {challenge()}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"anonymous-token"})")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("could not be resolved: the registry requires a credential for this reference."),
              std::string::npos)
            << m_warnings.front();
    EXPECT_EQ(m_warnings.front().find("rejected the credential"), std::string::npos) << m_warnings.front();
}

TEST_F(RegistryCredentialFallbackTest, AManifestRefusedForAnAnonymousTokenIsNotAnotherFallback)
{
    // No credential is configured, so there is nothing that was refused to take back.
    m_config.registryAuth.clear();
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(403, "")}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"anonymous-token"})")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_transport->countMatching("/token"), 1u);
    EXPECT_EQ(m_transport->countMatching("/manifests/"), 2u);
    ASSERT_EQ(m_warnings.size(), 1u);
}

TEST_F(RegistryCredentialFallbackTest, AManifestThatIsThrottledOrUnreachableIsNotAnAnonymousCase)
{
    // Neither says anything about the credential, however late in the conversation.
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(503, "")}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scoped-token"})")});

    const auto instance = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_transport->countMatching("/token"), 1u);
    EXPECT_EQ(anonymousTokenCalls(), 0u);
}

TEST_F(RegistryCredentialFallbackTest, TheRefusalIsReportedOncePerScanAndHost)
{
    scriptPublicReference(json(403, ""));

    {
        const auto first = reader("ghcr.io/owner/app:1.0");
        EXPECT_EQ(first->discover().status, ReadStatus::Success);
    }

    // A second reference on the same host, in the same scan.
    m_transport = new ScriptedTransport();
    scriptPublicReferenceWithoutCredential();

    const auto second = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(second->discover().status, ReadStatus::Success);
    EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 1u);

    // The next scan starts with a clean slate and says it again.
    m_refusedScopes.clear();
    m_reportedHosts.clear();
    m_transport = new ScriptedTransport();
    scriptPublicReference(json(403, ""));

    const auto third = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(third->discover().status, ReadStatus::Success);
    EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 2u);
}

TEST_F(RegistryCredentialFallbackTest, ARefusedCredentialIsNotSentAgainToTheOrganizationInTheSameScan)
{
    // Three public references under one organization. Only the first one pays for the
    // refusal, with one credentialed token request. The others ask for their anonymous token only.
    constexpr std::size_t REFERENCES {3};
    std::size_t credentialed {0};
    std::size_t anonymous {0};

    for (std::size_t index = 0; index < REFERENCES; ++index)
    {
        m_transport = new ScriptedTransport();

        if (index == 0)
        {
            scriptPublicReference(json(403, ""));
        }
        else
        {
            scriptPublicReferenceWithoutCredential();
        }

        const auto instance = reader("ghcr.io/owner/app" + std::to_string(index) + ":1.0");

        EXPECT_EQ(instance->discover().status, ReadStatus::Success) << index;
        credentialed += credentialedTokenCalls();
        anonymous += anonymousTokenCalls();
    }

    EXPECT_EQ(credentialed, 1u);
    EXPECT_EQ(anonymous, REFERENCES);
    EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 1u);
    ASSERT_EQ(m_refusedScopes.size(), 1u);
    EXPECT_EQ(m_refusedScopes.begin()->first, "ghcr.io/owner");
}

TEST_F(RegistryCredentialFallbackTest, ARefusalForOneOrganizationDoesNotStopTheCredentialForAnotherOnTheSameHost)
{
    scriptPublicReference(json(403, ""));

    {
        const auto first = reader("ghcr.io/orga/public:1.0");
        ASSERT_EQ(first->discover().status, ReadStatus::Success);
    }

    ASSERT_EQ(m_refusedScopes.size(), 1u);
    EXPECT_EQ(m_refusedScopes.begin()->first, "ghcr.io/orga");

    // A private reference under another organization of the same host still sends it.
    m_warnings.clear();
    m_transport = new ScriptedTransport();
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"private-token"})")});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto second = reader("ghcr.io/orgb/private:1.0");

    EXPECT_EQ(second->discover().status, ReadStatus::Success);
    EXPECT_EQ(credentialedTokenCalls(), 1u);
    EXPECT_EQ(anonymousTokenCalls(), 0u);
    EXPECT_TRUE(m_warnings.empty());
}

TEST_F(RegistryCredentialFallbackTest, ThePresentedCredentialIsRememberedPerScanOnly)
{
    scriptPublicReference(json(403, ""));

    {
        const auto first = reader("ghcr.io/owner/app:1.0");
        EXPECT_EQ(first->discover().status, ReadStatus::Success);
    }

    // The next scan starts with nothing refused, so the credential is presented again.
    m_refusedScopes.clear();
    m_reportedHosts.clear();
    m_transport = new ScriptedTransport();
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto second = reader("ghcr.io/owner/app:1.0");

    EXPECT_EQ(second->discover().status, ReadStatus::Success);
    ASSERT_EQ(credentialedTokenCalls(), 1u);

    for (const auto& call : m_transport->calls)
    {
        if (call.url.find("/token") != std::string::npos)
        {
            EXPECT_EQ(call.user, USER);
        }

        if (call.url.find("/manifests/") != std::string::npos && call.headers.size() > 1)
        {
            EXPECT_EQ(call.headers[1], "Authorization: Bearer scripted-token");
        }
    }
}

TEST_F(RegistryCredentialFallbackTest, APrivateReferenceAfterARefusalReportsTheOriginalReasonWithoutSendingTheCredential)
{
    scriptPublicReference(json(403, ""));

    {
        const auto first = reader("ghcr.io/owner/app:1.0");
        ASSERT_EQ(first->discover().status, ReadStatus::Success);
    }

    // A private reference on the same host: the anonymous token is issued and does not open
    // it, as on a first reference, and what the user is told is what the registry said of
    // the credential.
    m_warnings.clear();
    m_transport = new ScriptedTransport();
    scriptPrivateReference(json(200, R"({"token":"anonymous-token"})"));

    const auto second = reader("ghcr.io/owner/private:1.0");

    EXPECT_EQ(second->discover().status, ReadStatus::Failed);
    EXPECT_EQ(credentialedTokenCalls(), 0u);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("could not be resolved: the token request failed: the registry answered 403."),
              std::string::npos)
            << m_warnings.front();
}

// A refusal at a manifest speaks for one repository, not for the credential, so it is not
// remembered: a PAT that is not authorized for one organization still reads the others.
TEST_F(RegistryCredentialFallbackTest, ARefusalAtTheManifestDoesNotStopThePrivateReferenceThatFollows)
{
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(403, ""), json(200, MANIFEST)}, 0});
    m_transport->sequences.push_back(
    {"/token", {json(200, R"({"token":"scoped-token"})"), json(200, R"({"token":"anonymous-token"})")}, 0});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    {
        const auto first = reader("ghcr.io/orgx/public:1.0");
        ASSERT_EQ(first->discover().status, ReadStatus::Success);
    }

    EXPECT_TRUE(m_refusedScopes.empty());

    // The same credential reads the private repository of another owner.
    m_warnings.clear();
    m_transport = new ScriptedTransport();
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(200, MANIFEST)}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"private-token"})")});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto second = reader("ghcr.io/me/private:1.0");

    EXPECT_EQ(second->discover().status, ReadStatus::Success);
    EXPECT_EQ(credentialedTokenCalls(), 1u);
    EXPECT_EQ(anonymousTokenCalls(), 0u);
    EXPECT_TRUE(m_warnings.empty());

    bool bearerSeen {false};

    for (const auto& call : m_transport->calls)
    {
        if (call.url.find("/manifests/") != std::string::npos && call.headers.size() > 1)
        {
            bearerSeen = bearerSeen || call.headers[1] == "Authorization: Bearer private-token";
        }
    }

    EXPECT_TRUE(bearerSeen);
}

TEST_F(RegistryCredentialFallbackTest, ARefusalAtTheManifestIsReportedOncePerScanAndHostAndNotRemembered)
{
    constexpr std::size_t REFERENCES {3};
    std::size_t credentialed {0};

    for (std::size_t index = 0; index < REFERENCES; ++index)
    {
        m_transport = new ScriptedTransport();
        m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(403, ""), json(200, MANIFEST)}, 0});
        m_transport->sequences.push_back(
        {"/token", {json(200, R"({"token":"scoped-token"})"), json(200, R"({"token":"anonymous-token"})")}, 0});
        m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

        const auto instance = reader("ghcr.io/orgx/public:1.0");

        EXPECT_EQ(instance->discover().status, ReadStatus::Success) << index;
        credentialed += credentialedTokenCalls();
    }

    EXPECT_EQ(credentialed, REFERENCES) << "each reference still sends the credential once";
    EXPECT_EQ(warningsMentioning("The credential configured for ghcr.io"), 1u);
}

TEST_F(RegistryCredentialFallbackTest, APrivateReferenceAfterAManifestRefusalKeepsItsOwnError)
{
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(401, ""), json(200, MANIFEST)}, 0});
    m_transport->sequences.push_back(
    {"/token", {json(200, R"({"token":"scoped-token"})"), json(200, R"({"token":"anonymous-token"})")}, 0});
    m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    {
        const auto first = reader("ghcr.io/owner/app:1.0");
        ASSERT_EQ(first->discover().status, ReadStatus::Success);
    }

    m_warnings.clear();
    m_transport = new ScriptedTransport();
    m_transport->sequences.push_back({"/manifests/1.0", {challenge(), json(403, "")}, 0});
    m_transport->answers.push_back({"/token", json(200, R"({"token":"anonymous-token"})")});

    const auto second = reader("ghcr.io/owner/private:1.0");

    EXPECT_EQ(second->discover().status, ReadStatus::Failed);
    EXPECT_EQ(credentialedTokenCalls(), 1u);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("could not be resolved: the registry answered 403."), std::string::npos)
            << m_warnings.front();
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

// A layer larger than what is left of the image's allowance cannot be read whatever the
// transfer does, so it is refused on the strength of the size the manifest declares.
class RegistryLayerSizeTest : public RegistryLayerRetryTest
{
    protected:
        /// @brief Serve a manifest whose layers are @p layers, a JSON array body.
        void declareLayers(const std::string& layers)
        {
            const auto manifest {R"({"mediaType":"application/vnd.oci.image.manifest.v1+json",
                "config":{"digest":"sha256:cccc3333"},"layers":)" + layers + "}"};

            m_transport->answers.insert(m_transport->answers.begin(), {"/manifests/1.0", json(200, manifest)});
        }

        void declareLayerSize(const std::uint64_t size)
        {
            declareLayers(R"([{"digest":"sha256:dddd4444","size":)" + std::to_string(size) + "}]");
        }

        std::vector<std::string> m_warnings;

        void SetUp() override
        {
            RegistryLayerRetryTest::SetUp();

            LoggingHelper::setLogCallback([this](const modules_log_level_t level, const char* message)
            {
                if (level == LOG_WARNING)
                {
                    m_warnings.push_back(message);
                }
            });
        }

        void TearDown() override
        {
            LoggingHelper::setLogCallback({});
            RegistryLayerRetryTest::TearDown();
        }
};

TEST_F(RegistryLayerSizeTest, ALayerLargerThanTheImageAllowanceIsNeverTransferred)
{
    m_config.limits.maxImageBytes = 100;
    declareLayerSize(150);

    const auto instance = layerReader({BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_attemptLimits.empty());
    EXPECT_EQ(m_scanBytes, 0u);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("layer sha256:dddd4444 is 150 bytes and the image has 100 of its 100 byte "
                                      "allowance left"),
              std::string::npos)
            << m_warnings.front();
}

TEST_F(RegistryLayerSizeTest, ALayerThatFitsExactlyIsTransferred)
{
    m_config.limits.maxImageBytes = 100;
    declareLayerSize(100);

    const auto instance = layerReader({BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_attemptLimits.size(), 1u);
}

TEST_F(RegistryLayerSizeTest, ALayerWithNoDeclaredSizeIsLeftToTheCeiling)
{
    m_config.limits.maxImageBytes = 100;

    const auto instance = layerReader({BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_attemptLimits.size(), 1u);
}

TEST_F(RegistryLayerSizeTest, ARetryThatCannotFitIsNotStartedAndNamesTheCauseOfTheFailure)
{
    // The first attempt delivers 60 of 100 bytes and fails; the 60-byte layer cannot be
    // read again from the 40 that are left, so the failure is the one reported, not the limit.
    m_config.limits.maxImageBytes = 100;
    declareLayerSize(60);

    auto failed {failure(200, 60)};
    failed.error = "the connection was reset";

    const auto instance = layerReader({failed, BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_attemptLimits.size(), 1u);
    ASSERT_EQ(m_warnings.size(), 1u);
    EXPECT_NE(m_warnings.front().find("layer sha256:dddd4444 could not be retrieved: the connection was reset"),
              std::string::npos)
            << m_warnings.front();
    EXPECT_EQ(m_warnings.front().find("allowance"), std::string::npos) << m_warnings.front();
}

TEST_F(RegistryLayerSizeTest, ARetryThatStillFitsIsStarted)
{
    m_config.limits.maxImageBytes = 100;
    declareLayerSize(40);

    const auto instance = layerReader({failure(200, 30), BlobOutcome {}});

    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    ASSERT_EQ(m_attemptLimits.size(), 2u);
    EXPECT_EQ(m_attemptLimits[1], 70u);
}

TEST_F(RegistryLayerSizeTest, ASecondLayerIsCheckedAgainstWhatTheFirstLeft)
{
    m_config.limits.maxImageBytes = 100;

    declareLayers(R"([{"digest":"sha256:dddd4444","size":60},{"digest":"sha256:eeee5555","size":60}])");

    BlobOutcome first;
    first.delivered = 60;

    const auto instance = layerReader({first});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_attemptLimits.size(), 1u) << "the second layer must not be requested";
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

// What is done with the bytes of a layer once they have arrived. The compressed size is
// bounded by the image allowance, and the decompressed size is bounded separately: a small
// blob can expand into far more than anything the module could need to read.
class RegistryLayerContentTest : public RegistryLayerRetryTest
{
    protected:
        static constexpr auto MANIFEST_WITH_TWO_LAYERS = R"({"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"digest":"sha256:cccc3333"},"layers":[{"digest":"sha256:dddd4444"},{"digest":"sha256:eeee5555"}]})";

        void SetUp() override
        {
            RegistryLayerRetryTest::SetUp();

            LoggingHelper::setLogCallback([this](const modules_log_level_t level, const char* message)
            {
                if (level == LOG_WARNING)
                {
                    m_warnings.push_back(message);
                }
            });
        }

        void TearDown() override
        {
            LoggingHelper::setLogCallback({});
            RegistryLayerRetryTest::TearDown();
        }

        /// @brief A layer outcome that serves @p content.
        static BlobOutcome serving(const std::string& content)
        {
            BlobOutcome outcome;
            outcome.content = content;
            outcome.delivered = content.size();

            return outcome;
        }

        /// @brief A layer holding one regular file of @p size zero bytes, which is all a
        /// decompression bomb needs: a header that promises content, then the content.
        static std::string tarOfZeros(const std::size_t size)
        {
            return imagefixtures::tarMember("bomb", std::string(size, '\0')) + imagefixtures::tarEnd();
        }

        static std::string layerWithOnePackage()
        {
            return imagefixtures::tarMember("var/lib/dpkg/status", imagefixtures::dpkgStanza("bash", "5.2.15")) +
                   imagefixtures::tarEnd();
        }

        std::size_t warningsMentioning(const std::string& fragment) const
        {
            return static_cast<std::size_t>(std::count_if(m_warnings.begin(),
                                                          m_warnings.end(),
                                                          [&fragment](const std::string & line)
            {
                return line.find(fragment) != std::string::npos;
            }));
        }

        std::vector<std::string> m_warnings;
};

TEST_F(RegistryLayerContentTest, ALayerThatExpandsPastTheLimitFailsTheReference)
{
    m_config.limits.maxLayerDecompressedBytes = 64 * 1024;

    const auto bomb {tarOfZeros(1024 * 1024)};

    const std::vector<std::string> blobs {imagefixtures::gzip(bomb), imagefixtures::zstd(bomb)};

    for (const auto& blob : blobs)
    {
        m_warnings.clear();
        m_transport = new ScriptedTransport();
        m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
        m_transport->answers.push_back({"/manifests/1.0", json(200, MANIFEST_WITH_A_LAYER)});
        m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

        // A compressed blob far below any allowance, so only the decompressed bound can stop it.
        EXPECT_LT(blob.size(), 16u * 1024u);

        const auto instance = layerReader({serving(blob)});
        const auto result {instance->discover()};

        EXPECT_EQ(result.status, ReadStatus::Failed);
        EXPECT_TRUE(result.records.empty()) << "no inventory is produced for a failed reference";
        EXPECT_EQ(m_attemptLimits.size() % 2, 1u) << "the layer was not retried";
        ASSERT_EQ(m_warnings.size(), 1u);
        EXPECT_NE(m_warnings.front().find("layer sha256:dddd4444 expands to more than 65536 decompressed bytes"),
                  std::string::npos)
                << m_warnings.front();
        m_attemptLimits.clear();
    }
}

TEST_F(RegistryLayerContentTest, ALayerThatIsExactlyTheLimitIsInventoried)
{
    const auto layer {layerWithOnePackage()};
    m_config.limits.maxLayerDecompressedBytes = layer.size();

    const auto instance = layerReader({serving(imagefixtures::gzip(layer))});
    const auto result {instance->discover()};

    ASSERT_EQ(result.status, ReadStatus::Success);
    ASSERT_EQ(result.records.size(), 1u);
    EXPECT_EQ(result.records.front().packages.size(), 1u);
}

TEST_F(RegistryLayerContentTest, ALayerOneByteOverTheLimitFailsTheReference)
{
    // The limit falls one byte short of the end of the file the layer holds, so the layer has
    // bytes left past it that the parser needed.
    const auto layer {layerWithOnePackage()};
    m_config.limits.maxLayerDecompressedBytes = layer.size() - imagefixtures::tarEnd().size() - 1;

    const auto instance = layerReader({serving(imagefixtures::gzip(layer))});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
}

TEST_F(RegistryLayerContentTest, ALayerUnderTheProductionLimitIsInventoried)
{
    const auto instance = layerReader({serving(imagefixtures::gzip(layerWithOnePackage()))});
    const auto result {instance->discover()};

    EXPECT_EQ(m_config.limits.maxLayerDecompressedBytes, MAX_LAYER_DECOMPRESSED_SIZE);
    EXPECT_EQ(MAX_LAYER_DECOMPRESSED_SIZE, 8ULL * 1024 * 1024 * 1024);
    ASSERT_EQ(result.status, ReadStatus::Success);
    ASSERT_EQ(result.records.size(), 1u);
    EXPECT_EQ(result.records.front().packages.size(), 1u);
}

TEST_F(RegistryLayerContentTest, AStopDuringALongDecompressedReadEndsTheReferenceAtOnce)
{
    // The blob is delivered whole by its first refill, so the compressed input never runs
    // out while the layer expands, and the transfer's own stop check is never reached.
    auto blob {serving(imagefixtures::gzip(tarOfZeros(16 * 1024 * 1024)))};
    blob.onEnd = [this]
    {
        m_stop = true;
    };

    const auto instance = layerReader({blob});
    const auto result {instance->discover()};

    EXPECT_EQ(result.status, ReadStatus::Failed);
    EXPECT_EQ(warningsMentioning("could not be read: the module was asked to stop."), 1u);
}

TEST_F(RegistryLayerContentTest, AStopBetweenTwoTarEntriesOfTheLastLayerFailsTheReference)
{
    // The stop lands exactly where the first entry ends. The cut reads as the end of the
    // layer, which then looks complete with only the entries before it, so the reference
    // is failed on the stop alone.
    const auto first {imagefixtures::tarMember("var/lib/dpkg/status", imagefixtures::dpkgStanza("bash", "5.2.15"))};
    const auto layer {first + imagefixtures::tarMember("etc/hostname", "host\n") + imagefixtures::tarEnd()};

    auto blob {serving(layer)};
    blob.atOffset = first.size();
    blob.onOffset = [this]
    {
        m_stop = true;
    };

    const auto instance = layerReader({blob});
    const auto result {instance->discover()};

    EXPECT_EQ(result.status, ReadStatus::Failed);
    EXPECT_TRUE(result.records.empty()) << "no inventory is produced for a stopped reference";
    EXPECT_EQ(warningsMentioning("could not be read: the module was asked to stop."), 1u);
}

TEST_F(RegistryLayerContentTest, AStopThatLandsAsTheLayerEndsFailsTheReference)
{
    // The stop lands as the closing block of the layer is read, so nothing was cut and the
    // layer is complete. The reference is failed all the same: a stop is never followed by
    // a stored result.
    const auto member {imagefixtures::tarMember("var/lib/dpkg/status", imagefixtures::dpkgStanza("bash", "5.2.15"))};

    auto blob {serving(member + imagefixtures::tarEnd())};
    blob.atOffset = member.size() + imagefixtures::TAR_BLOCK;
    blob.onOffset = [this]
    {
        m_stop = true;
    };

    const auto instance = layerReader({blob});

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_EQ(warningsMentioning("could not be read: the module was asked to stop."), 1u);
}

TEST_F(RegistryLayerContentTest, AnUnsupportedCompressionIsReportedAndTheLayerSkipped)
{
    // An xz signature followed by what could be anything: not read as tar, not read as empty.
    const auto xz {std::string {"\xfd\x37\x7a\x58\x5a\x00", 6} + " compressed bytes this reader cannot expand"};

    m_transport->answers[1].second = json(200, MANIFEST_WITH_TWO_LAYERS);

    const auto instance = layerReader({serving(xz), serving(imagefixtures::gzip(layerWithOnePackage()))});
    const auto result {instance->discover()};

    // The archive reader skips such a layer and goes on, and so does this one.
    ASSERT_EQ(result.status, ReadStatus::Success);
    ASSERT_EQ(result.records.size(), 1u);
    EXPECT_EQ(result.records.front().packages.size(), 1u);
    EXPECT_EQ(m_attemptLimits.size(), 2u);
    ASSERT_EQ(warningsMentioning("NOT IMPLEMENTED: layer 'sha256:dddd4444'"), 1u);
    EXPECT_EQ(warningsMentioning("is xz compressed"), 1u);
}

TEST_F(RegistryLayerContentTest, EachUnsupportedCompressionIsNamed)
{
    const std::vector<std::pair<std::string, std::string>> blobs
    {
        {std::string {"\x42\x5a\x68", 3} + "91AY&SY", "bzip2"},
        {std::string {"\x04\x22\x4d\x18", 4} + " frame", "lz4"},
    };

    for (const auto& [content, name] : blobs)
    {
        m_warnings.clear();
        m_transport = new ScriptedTransport();
        m_transport->answers.push_back({"/token", json(200, R"({"token":"scripted-token"})")});
        m_transport->answers.push_back({"/manifests/1.0", json(200, MANIFEST_WITH_A_LAYER)});
        m_transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

        const auto instance = layerReader({serving(content)});

        EXPECT_EQ(instance->discover().status, ReadStatus::Success) << name;
        EXPECT_EQ(warningsMentioning("is " + name + " compressed"), 1u) << name;
    }
}

// ---------------------------------------------------------------------------------------
// Amazon ECR
// ---------------------------------------------------------------------------------------

namespace
{
    constexpr auto ECR_HOST = "123456789012.dkr.ecr.us-east-1.amazonaws.com";
    constexpr auto ECR_REFERENCE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-backend:1.0";
    constexpr auto PUBLIC_REFERENCE = "public.ecr.aws/docker/library/alpine:1.0";

    // Verbatim from the probe of a private registry given a made-up Basic token.
    constexpr auto DENIED_BODY = R"({"errors":[{"code":"DENIED","message":"Your Authorization Token is invalid."}]})";

    /// @brief A token source with scripted answers that records what it was asked.
    class StubTokenSource final : public IEcrTokenSource
    {
        public:
            struct Call
            {
                std::string region;
                std::string dnsSuffix;
                std::string accessKeyId;
                std::string secretAccessKey;
            };

            std::vector<Call> calls;
            std::deque<EcrTokenResult> results; ///< Consumed in order. Afterwards a fresh token each call.
            std::chrono::system_clock::time_point* now {nullptr};
            std::function<void()> onFetch; ///< Called at the start of every call.

            EcrTokenResult fetch(const std::string& region,
                                 const std::string& dnsSuffix,
                                 const Secret& accessKeyId,
                                 const Secret& secretAccessKey) override
            {
                calls.push_back({region, dnsSuffix, accessKeyId.value(), secretAccessKey.value()});

                if (onFetch)
                {
                    onFetch();
                }

                if (!results.empty())
                {
                    auto result {std::move(results.front())};
                    results.pop_front();

                    return result;
                }

                EcrTokenResult result;
                result.ok = true;
                result.token = Secret {"ecr-token-" + std::to_string(calls.size())};
                result.expiresAt = (now != nullptr ? *now : std::chrono::system_clock::now()) + std::chrono::hours {12};

                return result;
            }
    };

    EcrTokenResult failure(const long status, const std::string& reason)
    {
        EcrTokenResult result;
        result.status = status;
        result.reason = reason;

        return result;
    }

    std::string base64(const std::string& text)
    {
        constexpr auto ALPHABET {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
        std::string encoded;
        std::size_t index {0};

        for (; index + 2 < text.size(); index += 3)
        {
            const auto chunk {(static_cast<unsigned char>(text[index]) << 16) |
                              (static_cast<unsigned char>(text[index + 1]) << 8) |
                              static_cast<unsigned char>(text[index + 2])};
            encoded += {ALPHABET[(chunk >> 18) & 63], ALPHABET[(chunk >> 12) & 63], ALPHABET[(chunk >> 6) & 63],
                        ALPHABET[chunk & 63]};
        }

        if (index + 1 == text.size())
        {
            const auto chunk {static_cast<unsigned char>(text[index]) << 16};
            encoded += {ALPHABET[(chunk >> 18) & 63], ALPHABET[(chunk >> 12) & 63], '=', '='};
        }
        else if (index + 2 == text.size())
        {
            const auto chunk {(static_cast<unsigned char>(text[index]) << 16) |
                              (static_cast<unsigned char>(text[index + 1]) << 8)};
            encoded += {ALPHABET[(chunk >> 18) & 63], ALPHABET[(chunk >> 12) & 63], ALPHABET[(chunk >> 6) & 63], '='};
        }

        return encoded;
    }

    std::string hex(const std::string& bytes)
    {
        constexpr auto DIGITS {"0123456789abcdef"};
        std::string result;

        for (const auto character : bytes)
        {
            result += DIGITS[(static_cast<unsigned char>(character) >> 4) & 15];
            result += DIGITS[static_cast<unsigned char>(character) & 15];
        }

        return result;
    }
} // namespace

class EcrReaderTest : public RegistryReaderTest
{
    protected:
        EcrReaderTest()
            : m_cache {[this] { return m_now; }, std::chrono::minutes {10}}
        {
        }

        void SetUp() override
        {
            RegistryReaderTest::SetUp();

            // The base fixture hands out one transport for a reader to own. These tests
            // build several, so the spare is held here until a reader takes it.
            m_spare.reset(m_transport);

            m_source.now = &m_now;
            m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", {}});
            m_credentials.values["container_images/ecr_key_id"] = "AKIDEXAMPLE";
            m_credentials.values["container_images/ecr_secret"] = "example-secret-access-key";

            LoggingHelper::setLogCallback([this](const modules_log_level_t level, const char* line)
            {
                m_logs.push_back({level, line});
            });
        }

        void TearDown() override
        {
            if (HasFailure())
            {
                for (const auto& entry : m_logs)
                {
                    std::cerr << "[module log " << entry.first << "] " << entry.second << "\n";
                }
            }

            LoggingHelper::setLogCallback([](const modules_log_level_t, const char*) {});
            RegistryReaderTest::TearDown();
        }

        /// @brief The transport script of an image that resolves, with no token endpoint.
        void scriptResolution(ScriptedTransport& transport)
        {
            transport.answers.push_back({"/manifests/1.0", json(200, index())});
            transport.answers.push_back({"/manifests/sha256:aaaa1111", json(200, MANIFEST)});
            transport.answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});
        }

        /// @brief A reader over @p transport that shares this fixture's cache and token source.
        std::unique_ptr<RegistryImageReader> ecrReader(const std::string& location,
                                                       ScriptedTransport* transport,
                                                       IEcrTokenSource* source = nullptr)
        {
            ReaderContext context {&m_config,
                                   &m_credentials,
                                   &m_scanBytes,
                                   &m_stop,
                                   m_shareRefusals ? &m_refusedScopes : nullptr,
                                   &m_reportedHosts};
            context.tokenCache = &m_cache;
            context.ecrTokenSource = source != nullptr ? source : &m_source;

            auto instance {std::make_unique<RegistryImageReader>(location, std::string {}, context)};

            if (transport == m_spare.get())
            {
                m_spare.release();
            }

            instance->setTransport(std::unique_ptr<IRegistryTransport>(transport));

            return instance;
        }

        std::string cacheKey(const std::string& region = "us-east-1") const
        {
            return RegistryTokenCache::makeKey(ECR_HOST, "ecr_key_id", "ecr_secret", region);
        }

        bool logged(const std::string& fragment) const
        {
            for (const auto& entry : m_logs)
            {
                if (entry.second.find(fragment) != std::string::npos)
                {
                    return true;
                }
            }

            return false;
        }

        std::size_t countLogged(const std::string& fragment) const
        {
            std::size_t total {0};

            for (const auto& entry : m_logs)
            {
                if (entry.second.find(fragment) != std::string::npos)
                {
                    ++total;
                }
            }

            return total;
        }

        bool m_shareRefusals {false}; ///< Hand the scan's refusal memory to the readers, as a scan does.
        std::chrono::system_clock::time_point m_now {std::chrono::system_clock::from_time_t(1'800'000'000)};
        RegistryTokenCache m_cache;
        StubTokenSource m_source;
        std::vector<std::pair<modules_log_level_t, std::string>> m_logs;
        std::unique_ptr<ScriptedTransport> m_spare;
};

TEST_F(EcrReaderTest, APublicReferenceIsReadWithAnAnonymousBearerToken)
{
    m_transport->queued["/manifests/1.0"].push_back(
        []
    {
        HttpResponse response;
        response.status = 401;
        response.headers["www-authenticate"] =
            R"(Bearer realm="https://public.ecr.aws/token/",service="public.ecr.aws",scope="aws")";

        return response;
    }());
    m_transport->answers.push_back({"/token/", json(200, R"({"token":"public-token"})")});
    scriptResolution(*m_transport);

    const auto instance = ecrReader(PUBLIC_REFERENCE, m_transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Success);

    // The token request is the form the reader builds for any Bearer registry, scoped to
    // the repository, and carries no credential.
    ASSERT_GE(m_transport->calls.size(), 2u);
    EXPECT_EQ(m_transport->calls[1].url,
              "https://public.ecr.aws/token/?service=public.ecr.aws&scope=repository%3Adocker%2Flibrary%2Falpine%3Apull");
    EXPECT_FALSE(m_transport->calls[1].basic);
    EXPECT_TRUE(m_source.calls.empty()) << "public ECR must never reach AWS";

    for (const auto& call : m_transport->calls)
    {
        EXPECT_EQ(call.url.rfind("https://public.ecr.aws/", 0), 0u) << call.url;
    }

    // The manifest is then requested with the Bearer token.
    auto sawBearer {false};

    for (const auto& call : m_transport->calls)
    {
        for (const auto& header : call.headers)
        {
            sawBearer = sawBearer || header == "Authorization: Bearer public-token";
        }
    }

    EXPECT_TRUE(sawBearer);
}

TEST_F(EcrReaderTest, ACredentialConfiguredForPublicEcrIsNotSent)
{
    m_config.registryAuth.push_back({"public.ecr.aws", "ecr_key_id", "ecr_secret", {}});

    HttpResponse challenge;
    challenge.status = 401;
    challenge.headers["www-authenticate"] =
        R"(Bearer realm="https://public.ecr.aws/token/",service="public.ecr.aws",scope="aws")";
    m_transport->queued["/manifests/1.0"].push_back(challenge);
    m_transport->answers.push_back({"/token/", json(200, R"({"token":"public-token"})")});
    scriptResolution(*m_transport);

    const auto instance = ecrReader(PUBLIC_REFERENCE, m_transport);
    instance->discover();

    for (const auto& call : m_transport->calls)
    {
        EXPECT_FALSE(call.basic) << "a credential reached " << call.url;
    }
}

TEST_F(EcrReaderTest, APublicRealmOutsideTheRegistryIsRefused)
{
    HttpResponse challenge;
    challenge.status = 401;
    challenge.headers["www-authenticate"] = R"(Bearer realm="https://public.ecr.aws@attacker.example/token/")";
    m_transport->answers.push_back({"/manifests/1.0", challenge});

    const auto instance = ecrReader(PUBLIC_REFERENCE, m_transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    for (const auto& call : m_transport->calls)
    {
        EXPECT_EQ(call.url.find("attacker.example"), std::string::npos) << call.url;
    }
}

TEST_F(EcrReaderTest, APrivateReferenceSendsTheBasicTokenFromTheFirstRequest)
{
    scriptResolution(*m_transport);

    const auto instance = ecrReader(ECR_REFERENCE, m_transport);
    const auto result {instance->discover()};

    EXPECT_EQ(result.status, ReadStatus::Success);

    ASSERT_EQ(m_source.calls.size(), 1u);
    EXPECT_EQ(m_source.calls[0].region, "us-east-1");
    EXPECT_EQ(m_source.calls[0].dnsSuffix, "amazonaws.com");
    EXPECT_EQ(m_source.calls[0].accessKeyId, "AKIDEXAMPLE");
    EXPECT_EQ(m_source.calls[0].secretAccessKey, "example-secret-access-key");

    // No unauthenticated request is wasted, and nothing is asked of a token endpoint: the
    // challenge of a private registry names none that this module would use.
    ASSERT_FALSE(m_transport->calls.empty());

    for (const auto& call : m_transport->calls)
    {
        EXPECT_EQ(call.url.rfind(std::string {"https://"} + ECR_HOST + "/v2/my-backend/", 0), 0u) << call.url;
        EXPECT_FALSE(call.basic);

        auto sawBasic {false};

        for (const auto& header : call.headers)
        {
            sawBasic = sawBasic || header == "Authorization: Basic ecr-token-1";
            EXPECT_EQ(header.find("Bearer"), std::string::npos) << header;
        }

        EXPECT_TRUE(sawBasic) << call.url;
    }
}

TEST_F(EcrReaderTest, TheTokenIsSharedAcrossTheReferencesOfARegistry)
{
    auto* second {new ScriptedTransport()};
    scriptResolution(*m_transport);
    scriptResolution(*second);

    const auto first = ecrReader(ECR_REFERENCE, m_transport);
    EXPECT_EQ(first->discover().status, ReadStatus::Success);

    const auto other = ecrReader(std::string {ECR_HOST} + "/my-backend:1.0", second);
    EXPECT_EQ(other->discover().status, ReadStatus::Success);

    EXPECT_EQ(m_source.calls.size(), 1u) << "the second reference should have reused the token";
    EXPECT_EQ(m_cache.size(), 1u);

    for (const auto& call : second->calls)
    {
        EXPECT_NE(std::find(call.headers.begin(), call.headers.end(), "Authorization: Basic ecr-token-1"),
                  call.headers.end());
    }
}

TEST_F(EcrReaderTest, TheTokenIsRenewedBeforeItExpires)
{
    auto* second {new ScriptedTransport()};
    scriptResolution(*m_transport);
    scriptResolution(*second);

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);

    // Eleven hours and fifty minutes into a twelve hour token: inside the ten minute margin.
    m_now += std::chrono::hours {11} + std::chrono::minutes {50};

    const auto renewed = ecrReader(ECR_REFERENCE, second);
    EXPECT_EQ(renewed->discover().status, ReadStatus::Success);

    EXPECT_EQ(m_source.calls.size(), 2u);

    for (const auto& call : second->calls)
    {
        EXPECT_NE(std::find(call.headers.begin(), call.headers.end(), "Authorization: Basic ecr-token-2"),
                  call.headers.end());
    }
}

TEST_F(EcrReaderTest, ATokenWellInsideItsLifetimeIsNotRenewed)
{
    auto* second {new ScriptedTransport()};
    scriptResolution(*m_transport);
    scriptResolution(*second);

    ecrReader(ECR_REFERENCE, m_transport)->discover();
    m_now += std::chrono::hours {6};
    ecrReader(ECR_REFERENCE, second)->discover();

    EXPECT_EQ(m_source.calls.size(), 1u);
}

TEST_F(EcrReaderTest, ARefusedTokenIsRenewedOnceAndTheRequestRepeated)
{
    for (const long status : {400L, 401L, 403L})
    {
        SCOPED_TRACE(status);

        m_source.calls.clear();
        m_cache.clear();

        auto* transport {new ScriptedTransport()};
        scriptResolution(*transport);
        transport->queued["/manifests/1.0"].push_back(json(status, DENIED_BODY));

        const auto instance = ecrReader(ECR_REFERENCE, transport);
        EXPECT_EQ(instance->discover().status, ReadStatus::Success);

        EXPECT_EQ(m_source.calls.size(), 2u);

        // The repeated request carries the new token, and the cache holds it.
        std::vector<std::string> manifestTokens;

        for (const auto& call : transport->calls)
        {
            if (call.url.find("/manifests/1.0") != std::string::npos)
            {
                for (const auto& header : call.headers)
                {
                    if (header.rfind("Authorization: Basic ", 0) == 0)
                    {
                        manifestTokens.push_back(header);
                    }
                }
            }
        }

        ASSERT_EQ(manifestTokens.size(), 2u);
        EXPECT_EQ(manifestTokens[0], "Authorization: Basic ecr-token-1");
        EXPECT_EQ(manifestTokens[1], "Authorization: Basic ecr-token-2");
        ASSERT_TRUE(m_cache.lookup(cacheKey()).has_value());
        EXPECT_EQ(m_cache.lookup(cacheKey())->value(), "ecr-token-2");
    }
}

TEST_F(EcrReaderTest, ARepeatedRefusalIsReportedWithTheRegistrysReasonAndNotRetriedForever)
{
    for (const long status : {400L, 401L, 403L})
    {
        SCOPED_TRACE(status);

        m_source.calls.clear();
        m_logs.clear();
        m_cache.clear();

        auto* transport {new ScriptedTransport()};
        transport->answers.push_back({"/manifests/", json(status, DENIED_BODY)});

        const auto instance = ecrReader(ECR_REFERENCE, transport);
        EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

        EXPECT_EQ(m_source.calls.size(), 2u) << "one token and one renewal, never a third";
        EXPECT_EQ(transport->countMatching("/manifests/1.0"), 2u);

        EXPECT_TRUE(logged("Reference '" + std::string {ECR_REFERENCE} + "'"));
        EXPECT_TRUE(logged("DENIED: Your Authorization Token is invalid.")) << "the registry's reason is missing";
    }
}

TEST_F(EcrReaderTest, ARefusalWhoseBodyEchoesTheRequestNamesOnlyTheCode)
{
    auto* transport {new ScriptedTransport()};
    transport->answers.push_back(
        {"/manifests/",
         json(400,
              R"({"errors":[{"code":"DENIED","message":"bad header Authorization: Basic ecr-token-1 for AKIDEXAMPLE"}]})")});

    const auto instance = ecrReader(ECR_REFERENCE, transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(logged("DENIED"));

    for (const auto& entry : m_logs)
    {
        EXPECT_EQ(entry.second.find("ecr-token"), std::string::npos) << entry.second;
        EXPECT_EQ(entry.second.find("AKIDEXAMPLE"), std::string::npos) << entry.second;
    }
}

TEST_F(EcrReaderTest, ARenewalThatFailsIsReportedWithAwsReason)
{
    auto* transport {new ScriptedTransport()};
    transport->answers.push_back({"/manifests/", json(400, DENIED_BODY)});

    m_source.results.emplace_back();
    m_source.results.front().ok = true;
    m_source.results.front().token = Secret {"ecr-token-1"};
    m_source.results.front().expiresAt = m_now + std::chrono::hours {12};
    m_source.results.push_back(failure(400, "AWS does not accept the access key id (UnrecognizedClientException)"));

    const auto instance = ecrReader(ECR_REFERENCE, transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(logged("a new one could not be obtained"));
    EXPECT_TRUE(logged("UnrecognizedClientException"));
    EXPECT_EQ(m_cache.size(), 0u) << "a refused token must not stay cached";
}

TEST_F(EcrReaderTest, APrivateReferenceWithNoRegistryEntryFailsBeforeAnyRequest)
{
    m_config.registryAuth.clear();

    const auto instance = ecrReader(ECR_REFERENCE, m_transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(m_transport->calls.empty());
    EXPECT_TRUE(m_source.calls.empty());
    EXPECT_EQ(countLogged("no credential is configured for " + std::string {ECR_HOST}), 1u);
    EXPECT_TRUE(logged("Reference '" + std::string {ECR_REFERENCE} + "'"));
    EXPECT_TRUE(logged("access_key_id_keystore_key"));
}

TEST_F(EcrReaderTest, ACredentialMissingFromTheStoreFailsBeforeAnyRequest)
{
    m_credentials.values.erase("container_images/ecr_secret");

    const auto instance = ecrReader(ECR_REFERENCE, m_transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(m_transport->calls.empty());
    EXPECT_TRUE(m_source.calls.empty());
    EXPECT_TRUE(logged("is missing from the agent credential store"));
}

TEST_F(EcrReaderTest, AnAwsFailureIsReportedWithTheReferenceAndTheReasonAndNotCached)
{
    m_source.results.push_back(failure(400, "AWS does not accept the access key id (UnrecognizedClientException)"));

    const auto instance = ecrReader(ECR_REFERENCE, m_transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(m_transport->calls.empty()) << "the registry must not be asked when there is no token";
    EXPECT_EQ(m_source.calls.size(), 1u) << "a rejected credential is not retried";
    EXPECT_EQ(m_cache.size(), 0u);
    EXPECT_EQ(countLogged("UnrecognizedClientException"), 1u);
    EXPECT_TRUE(logged("Reference '" + std::string {ECR_REFERENCE} + "'"));

    // Nothing was remembered, so a corrected credential works at the next scan.
    auto* transport {new ScriptedTransport()};
    scriptResolution(*transport);
    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, AClockSkewReasonReachesTheLog)
{
    m_source.results.push_back(
        failure(400, "AWS refused the signature because the agent clock differs too much from AWS time"));

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(logged("the agent clock differs too much from AWS time"));
}

TEST_F(EcrReaderTest, ThrottlingIsRetried)
{
    m_source.results.push_back(failure(429, "AWS throttled the request (ThrottlingException)"));
    scriptResolution(*m_transport);

    const auto instance = ecrReader(ECR_REFERENCE, m_transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, ThrottlingThatNeverEndsGivesUpAndSaysSo)
{
    for (auto attempt = 0; attempt < 10; ++attempt)
    {
        m_source.results.push_back(failure(429, "AWS throttled the request (ThrottlingException)"));
    }

    m_config.limits.maxAttempts = 3;

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_source.calls.size(), 3u);
    EXPECT_TRUE(logged("ThrottlingException"));
}

TEST_F(EcrReaderTest, AConfiguredRegionOverridesTheOneInTheHost)
{
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "eu-west-1"});
    scriptResolution(*m_transport);

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);

    ASSERT_EQ(m_source.calls.size(), 1u);
    EXPECT_EQ(m_source.calls[0].region, "eu-west-1");

    // One line naming both regions, neither of which is a secret.
    EXPECT_EQ(countLogged("overrides"), 1u);

    for (const auto& entry : m_logs)
    {
        if (entry.second.find("overrides") != std::string::npos)
        {
            EXPECT_NE(entry.second.find("eu-west-1"), std::string::npos);
            EXPECT_NE(entry.second.find("us-east-1"), std::string::npos);
            EXPECT_EQ(entry.first, LOG_DEBUG);
        }
    }

    // The token is kept per region it was issued for.
    EXPECT_TRUE(m_cache.lookup(cacheKey("eu-west-1")).has_value());
    EXPECT_FALSE(m_cache.lookup(cacheKey("us-east-1")).has_value());
}

TEST_F(EcrReaderTest, TheRegionOfTheHostIsUsedWhenNoneIsConfigured)
{
    scriptResolution(*m_transport);

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);

    ASSERT_EQ(m_source.calls.size(), 1u);
    EXPECT_EQ(m_source.calls[0].region, "us-east-1");
    EXPECT_FALSE(logged("overrides"));
}

TEST_F(EcrReaderTest, ARegionEqualToTheHostsIsNotReportedAsAnOverride)
{
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "us-east-1"});
    scriptResolution(*m_transport);

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);
    EXPECT_FALSE(logged("overrides"));
}

TEST_F(EcrReaderTest, AReferenceOfAnotherRegistryDoesNotUseThePrivateTokens)
{
    // GHCR and the cache coexist: a GHCR reference never reads the ECR token or the source.
    m_transport->answers.push_back({"/manifests/1.0", json(200, "{not json")});

    EXPECT_EQ(ecrReader("ghcr.io/owner/app:1.0", m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_source.calls.empty());
    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(EcrReaderTest, OneFailingEcrReferenceDoesNotStopTheNext)
{
    auto* good {new ScriptedTransport()};
    scriptResolution(*good);

    m_credentials.values.erase("container_images/ecr_secret");
    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);

    m_credentials.values["container_images/ecr_secret"] = "example-secret-access-key";
    EXPECT_EQ(ecrReader(ECR_REFERENCE, good)->discover().status, ReadStatus::Success);
}

namespace
{
    // The form AWS documents for an IAM denial. Not measured against a real account.
    constexpr auto PERMISSION_BODY =
        R"({"errors":[{"code":"DENIED","message":"User: arn:aws:iam::123456789012:user/wazuh-ci is not authorized to )"
        R"(perform: ecr:BatchGetImage on resource: arn:aws:ecr:us-east-1:123456789012:repository/my-backend"}]})";
} // namespace

TEST_F(EcrReaderTest, AMissingPermissionCostsOneSignedCallWhateverTheNumberOfReferences)
{
    constexpr int REFERENCES {3};

    for (const long status : {403L, 400L})
    {
        SCOPED_TRACE(status);

        m_source.calls.clear();
        m_logs.clear();
        m_cache.clear();

        for (auto index = 0; index < REFERENCES; ++index)
        {
            auto* transport {new ScriptedTransport()};
            transport->answers.push_back({"/manifests/", json(status, PERMISSION_BODY)});

            const auto instance = ecrReader(ECR_REFERENCE, transport);
            EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

            // The refused request was not repeated, and the shared token was kept.
            EXPECT_EQ(transport->countMatching("/manifests/1.0"), 1u);
        }

        EXPECT_EQ(m_source.calls.size(), 1u) << "a missing permission must not cost a second signed call";
        EXPECT_TRUE(m_cache.lookup(cacheKey()).has_value()) << "a valid token was dropped";
        EXPECT_EQ(countLogged("is not authorized to perform: ecr:BatchGetImage"), static_cast<std::size_t>(REFERENCES));
        EXPECT_TRUE(logged("arn:aws:iam::123456789012:user/wazuh-ci"));
        EXPECT_TRUE(logged("arn:aws:ecr:us-east-1:123456789012:repository/my-backend")) << "the resource ARN was cut";
    }
}

TEST_F(EcrReaderTest, ATokenRefusedAfterARegionOverrideSaysSoAndIsNotRenewed)
{
    for (const long status : {400L, 401L, 403L})
    {
        SCOPED_TRACE(status);

        m_source.calls.clear();
        m_logs.clear();
        m_cache.clear();
        m_config.registryAuth.clear();
        m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "eu-west-1"});

        auto* transport {new ScriptedTransport()};
        transport->answers.push_back({"/manifests/", json(status, DENIED_BODY)});

        const auto instance = ecrReader(ECR_REFERENCE, transport);
        EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

        EXPECT_EQ(m_source.calls.size(), 1u) << "a token from the same wrong region must not be asked for twice";
        EXPECT_EQ(m_source.calls[0].region, "eu-west-1");
        EXPECT_EQ(transport->countMatching("/manifests/1.0"), 1u);

        EXPECT_TRUE(logged("the registry refused the token requested in the configured region 'eu-west-1', "
                           "and the registry host is in 'us-east-1'"));
        EXPECT_TRUE(logged("Reference '" + std::string {ECR_REFERENCE} + "'"));
        EXPECT_TRUE(logged("The token was not renewed"));

        for (const auto& entry : m_logs)
        {
            EXPECT_EQ(entry.second.find("ecr-token"), std::string::npos) << entry.second;
            EXPECT_EQ(entry.second.find("example-secret-access-key"), std::string::npos) << entry.second;
        }
    }
}

TEST_F(EcrReaderTest, ARegionOverrideEqualToTheHostsKeepsTheRenewal)
{
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "us-east-1"});

    auto* transport {new ScriptedTransport()};
    transport->answers.push_back({"/manifests/", json(400, DENIED_BODY)});

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Failed);

    EXPECT_EQ(m_source.calls.size(), 2u) << "no region mismatch, so the usual single renewal applies";
    EXPECT_FALSE(logged("configured region"));
}

TEST_F(EcrReaderTest, ARegionOverrideThatTheRegistryAcceptsStillWorks)
{
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "eu-west-1"});
    scriptResolution(*m_transport);

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_source.calls.size(), 1u);
}

TEST_F(EcrReaderTest, AReasonThatEndsInAPeriodIsNotFollowedByAnother)
{
    // Registry and AWS messages are often sentences, and the log line adds its own full stop.
    auto* transport {new ScriptedTransport()};
    transport->answers.push_back(
        {"/manifests/", json(404, R"({"errors":[{"code":"NAME_UNKNOWN","message":"The repository does not exist."}]})")});

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(logged("NAME_UNKNOWN: The repository does not exist."));

    for (const auto& entry : m_logs)
    {
        EXPECT_EQ(entry.second.find(".."), std::string::npos) << entry.second;
    }

    // And one that does not end in a period still gets exactly one.
    m_logs.clear();
    auto* denied {new ScriptedTransport()};
    denied->answers.push_back({"/manifests/", json(403, PERMISSION_BODY)});
    EXPECT_EQ(ecrReader(ECR_REFERENCE, denied)->discover().status, ReadStatus::Failed);

    for (const auto& entry : m_logs)
    {
        if (entry.first == LOG_WARNING)
        {
            EXPECT_EQ(entry.second.back(), '.') << entry.second;
            EXPECT_EQ(entry.second.find(".."), std::string::npos) << entry.second;
        }
    }
}

TEST_F(EcrReaderTest, ARepeatedRefusalLinesNeverHaveADoublePeriod)
{
    auto* transport {new ScriptedTransport()};
    transport->answers.push_back({"/manifests/", json(400, DENIED_BODY)});

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(logged("DENIED: Your Authorization Token is invalid."));

    for (const auto& entry : m_logs)
    {
        EXPECT_EQ(entry.second.find(".."), std::string::npos) << entry.second;
    }
}

TEST_F(EcrReaderTest, AnEmptyRefusalIsCheckedAgainstTheManifestBeforeTheTokenIsDropped)
{
    // No body to read, as on the layer path: the manifest is asked for again to learn why.
    auto* transport {new ScriptedTransport()};
    transport->queued["/manifests/1.0"].push_back(json(403, ""));
    transport->queued["/manifests/1.0"].push_back(json(403, PERMISSION_BODY));

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_source.calls.size(), 1u);
    EXPECT_TRUE(m_cache.lookup(cacheKey()).has_value());
}

TEST_F(EcrReaderTest, AnEmptyRefusalThatTheManifestSaysIsTheTokenRenewsIt)
{
    auto* transport {new ScriptedTransport()};
    scriptResolution(*transport);
    transport->queued["/manifests/1.0"].push_back(json(400, ""));
    transport->queued["/manifests/1.0"].push_back(json(400, DENIED_BODY));

    const auto instance = ecrReader(ECR_REFERENCE, transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, AnEmptyRefusalThatTheManifestDoesNotRepeatLeavesTheTokenAlone)
{
    // The content host after a redirect answers 403 too, and the token was fine.
    auto* transport {new ScriptedTransport()};
    scriptResolution(*transport);
    transport->queued["/manifests/1.0"].push_back(json(403, ""));

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_source.calls.size(), 1u);
}

TEST_F(EcrReaderTest, A401FromTheRegistryAlwaysRenewsTheToken)
{
    auto* transport {new ScriptedTransport()};
    scriptResolution(*transport);
    transport->queued["/manifests/1.0"].push_back(json(401, PERMISSION_BODY));

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Success);
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, AReasonQuotingTheConfiguredCredentialIsNotLogged)
{
    auto* transport {new ScriptedTransport()};
    transport->answers.push_back(
        {"/manifests/",
         json(403, R"({"errors":[{"code":"DENIED","message":"key AKIDEXAMPLE secret example-secret-access-key refused"}]})")});

    EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(logged("403"));

    for (const auto& entry : m_logs)
    {
        EXPECT_EQ(entry.second.find("example-secret-access-key"), std::string::npos) << entry.second;
        EXPECT_EQ(entry.second.find("AKIDEXAMPLE"), std::string::npos) << entry.second;
    }
}

TEST_F(EcrReaderTest, AStoredAccessKeyIdThatIsNotWellFormedIsReportedWithoutBeingEchoed)
{
    m_credentials.values["container_images/ecr_key_id"] = "AKIDEXAMPLEWITHBLANK ";

    EcrTokenClient client {[](const EcrPostRequest&, HttpResponse&, std::string&) -> bool
    {
        ADD_FAILURE() << "nothing may be sent for a key id that could not be one";
        return false;
    }};

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport, &client)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(logged("the stored access key id is not well-formed"));
    EXPECT_FALSE(logged("AKIDEXAMPLEWITHBLANK"));
}

// ---------------------------------------------------------------------------------------
// Nothing derived from a credential reaches a log line
// ---------------------------------------------------------------------------------------

TEST_F(EcrReaderTest, NoLogLineAtAnyLevelCarriesACredentialOrAnythingDerivedFromOne)
{
    const std::string accessKeyId {"AKIDREDACTIONCHECK01"};
    const std::string secretKey {"SECRET/redaction+check/0123456789abcdefghij"};
    const std::string password {"PW-REDACTION-0123456789"};
    const auto token {base64("AWS:" + password)};

    m_credentials.values["container_images/ecr_key_id"] = accessKeyId;
    m_credentials.values["container_images/ecr_secret"] = secretKey;

    // Everything the signer sends is recorded, so the values derived from the credential
    // are known to the test and can be searched for.
    std::vector<EcrPostRequest> sent;
    enum class Mode { Succeed, EchoEverything, Throw } mode {Mode::Succeed};

    auto clock = [this] { return m_now; };
    EcrTokenClient client {[&](const EcrPostRequest& request, HttpResponse& answer, std::string&)
    {
        sent.push_back(request);

        if (mode == Mode::Throw)
        {
            throw std::runtime_error("signing failed for " + secretKey + " " + request.headers.back());
        }

        if (mode == Mode::EchoEverything)
        {
            const auto& authorization {request.headers.back()};

            answer.status = 400;
            answer.body = R"({"__type":"InvalidSignatureException","message":"Credential=)" + accessKeyId +
                          " " + authorization + " secret " + secretKey + " token " + token + "\"}";

            return true;
        }

        answer.status = 200;
        answer.body = R"({"authorizationData":[{"authorizationToken":")" + token + R"(","expiresAt":)" +
                      std::to_string(std::chrono::duration_cast<std::chrono::seconds>(m_now.time_since_epoch()).count() + 43200) +
                      "}]}";

        return true;
    }, clock};

    // 1. The whole flow succeeds.
    scriptResolution(*m_transport);
    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport, &client)->discover().status, ReadStatus::Success);

    // 2. The registry refuses the token, quoting it, and the renewal succeeds.
    auto* refused {new ScriptedTransport()};
    scriptResolution(*refused);
    refused->queued["/manifests/1.0"].push_back(
        json(400, R"({"errors":[{"code":"DENIED","message":"The token is invalid. Authorization: Basic )" + token + R"("}]})"));
    m_cache.clear();
    EXPECT_EQ(ecrReader(ECR_REFERENCE, refused, &client)->discover().status, ReadStatus::Success);

    // 3. AWS refuses the call and quotes everything it was sent.
    m_cache.clear();
    mode = Mode::EchoEverything;
    EXPECT_EQ(ecrReader(ECR_REFERENCE, new ScriptedTransport(), &client)->discover().status, ReadStatus::Failed);

    // 4. The signing path throws, with the secret in the exception text.
    mode = Mode::Throw;
    EXPECT_EQ(ecrReader(ECR_REFERENCE, new ScriptedTransport(), &client)->discover().status, ReadStatus::Failed);

    ASSERT_FALSE(sent.empty());
    ASSERT_FALSE(m_logs.empty());

    // The values that must never appear. The signature and the signing key are taken from
    // what was really sent and from the signer itself, not recomputed by hand.
    const auto& authorization {sent.front().headers.back()};
    const auto signaturePosition {authorization.find("Signature=")};
    ASSERT_NE(signaturePosition, std::string::npos);

    aws::SigningRequest scope;
    scope.region = "us-east-1";
    scope.service = "ecr";
    scope.amzDate = aws::formatAmzDate(m_now);

    const std::vector<std::string> forbidden {
        accessKeyId,
        secretKey,
        token,
        password,
        "AWS:" + password,
        authorization,
        authorization.substr(signaturePosition + std::string {"Signature="}.size()),
        hex(aws::signingKey(Secret {secretKey}, scope).value()),
        "AWS4" + secretKey,
        "Credential=",
        "Signature=",
        "AWS4-HMAC-SHA256",
    };

    auto sawDebug {false};

    for (const auto& entry : m_logs)
    {
        sawDebug = sawDebug || entry.first == LOG_DEBUG;

        for (const auto& value : forbidden)
        {
            EXPECT_EQ(entry.second.find(value), std::string::npos)
                << "a log line carries '" << value << "': " << entry.second;
        }
    }

    EXPECT_TRUE(sawDebug) << "the test must capture debug lines to mean anything";
    EXPECT_TRUE(logged("could not be resolved")) << "the failures must still be reported";
}

// ---------------------------------------------------------------------------------------
// Amazon ECR on the rules #38830 set for GHCR
// ---------------------------------------------------------------------------------------

namespace
{
    constexpr auto MANIFEST_WITH_A_LAYER_ECR = R"({"mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"digest":"sha256:cccc3333"},"layers":[{"digest":"sha256:dddd4444"}]})";

    // The form AWS documents for a wrong token, the other half of a permission denial.
    constexpr auto OTHER_REPOSITORY = "123456789012.dkr.ecr.us-east-1.amazonaws.com/other-backend:1.0";
    constexpr auto SECOND_TAG = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-backend:2.0";
} // namespace

// What stops an ECR registry being read as anonymous, and what makes it different from GHCR.
TEST_F(EcrReaderTest, APrivateEcrRegistryIsNeverReadAnonymouslyAfterItRefusedTheCredential)
{
    // A registry that, once the credential is refused, would serve anyone with a Bearer
    // token. If the fallback existed the third manifest request would succeed.
    HttpResponse bearer;
    bearer.status = 401;
    bearer.headers["www-authenticate"] =
        std::string {R"(Bearer realm="https://)"} + ECR_HOST + R"(/token",service="ecr")";

    auto* transport {new ScriptedTransport()};
    transport->queued["/manifests/1.0"].push_back(bearer);
    transport->queued["/manifests/1.0"].push_back(bearer);
    transport->answers.push_back({"/token", json(200, R"({"token":"anonymous-token"})")});
    scriptResolution(*transport);

    const auto instance = ecrReader(ECR_REFERENCE, transport);
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_EQ(transport->countMatching("/token"), 0u) << "an anonymous token was requested";
    EXPECT_EQ(transport->countMatching("/manifests/1.0"), 2u) << "a request was made after the refusal";
    EXPECT_TRUE(logged("the registry rejected the credential")) << "the credential error does not stand";
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, ARefusedAnonymousReadOfPublicEcrIsNotCalledARejectedCredential)
{
    HttpResponse challengeResponse;
    challengeResponse.status = 401;
    challengeResponse.headers["www-authenticate"] =
        R"(Bearer realm="https://public.ecr.aws/token/",service="public.ecr.aws",scope="aws")";

    auto* transport {new ScriptedTransport()};
    transport->answers.push_back({"/manifests/1.0", challengeResponse});
    transport->answers.push_back({"/token/", json(200, R"({"token":"public-token"})")});

    EXPECT_EQ(ecrReader(PUBLIC_REFERENCE, transport)->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(logged("the registry requires a credential for this reference"));
    EXPECT_FALSE(logged("rejected the credential"));
    EXPECT_TRUE(m_source.calls.empty());
}

// The refusal memory of a scan, for a private ECR registry: the account host and the repository.
TEST_F(EcrReaderTest, ARefusedRepositoryFailsItsOtherTagsWithoutAnyRequest)
{
    m_shareRefusals = true;

    auto* first {new ScriptedTransport()};
    first->answers.push_back({"/manifests/", json(403, PERMISSION_BODY)});
    EXPECT_EQ(ecrReader(ECR_REFERENCE, first)->discover().status, ReadStatus::Failed);
    ASSERT_EQ(m_refusedScopes.size(), 1u);
    EXPECT_EQ(m_refusedScopes.begin()->first, std::string {ECR_HOST} + "/my-backend");

    m_logs.clear();
    auto* second {new ScriptedTransport()};
    scriptResolution(*second);
    const auto secondReader = ecrReader(SECOND_TAG, second);
    EXPECT_EQ(secondReader->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(second->calls.empty()) << "a refused repository was asked again";
    EXPECT_EQ(m_source.calls.size(), 1u) << "one signed call for the whole registry";
    EXPECT_TRUE(logged("is not authorized to perform: ecr:BatchGetImage"));
    EXPECT_TRUE(logged("An earlier reference of " + std::string {ECR_HOST} + "/my-backend was refused in this scan"));
    EXPECT_TRUE(m_cache.lookup(cacheKey()).has_value()) << "the refusal memory must not touch the token cache";
}

TEST_F(EcrReaderTest, ARefusalIsKeptPerRepositoryAndNotForTheWholeHost)
{
    m_shareRefusals = true;

    auto* first {new ScriptedTransport()};
    first->answers.push_back({"/manifests/", json(403, PERMISSION_BODY)});
    EXPECT_EQ(ecrReader(ECR_REFERENCE, first)->discover().status, ReadStatus::Failed);

    // Another repository of the same account may be one the credential is allowed to read.
    auto* other {new ScriptedTransport()};
    scriptResolution(*other);
    const auto otherReader = ecrReader(OTHER_REPOSITORY, other);
    EXPECT_EQ(otherReader->discover().status, ReadStatus::Success);

    EXPECT_FALSE(other->calls.empty());
    EXPECT_EQ(m_source.calls.size(), 1u) << "the token is shared across repositories";
}

TEST_F(EcrReaderTest, ARefusalOfANestedRepositoryDoesNotCoverItsNeighbourUnderTheSamePrefix)
{
    // "team/app" and "team/other" share a first path segment. GHCR scopes a refusal by that
    // segment, an organization. An ECR account has none, and the policy is per repository.
    m_shareRefusals = true;

    auto* first {new ScriptedTransport()};
    first->answers.push_back({"/manifests/", json(403, PERMISSION_BODY)});
    EXPECT_EQ(ecrReader(std::string {ECR_HOST} + "/team/app:1.0", first)->discover().status, ReadStatus::Failed);

    auto* neighbour {new ScriptedTransport()};
    scriptResolution(*neighbour);
    const auto neighbourReader = ecrReader(std::string {ECR_HOST} + "/team/other:1.0", neighbour);
    EXPECT_EQ(neighbourReader->discover().status, ReadStatus::Success);
    EXPECT_FALSE(neighbour->calls.empty());
}

TEST_F(EcrReaderTest, ABadCredentialAtAwsCostsOneSignedCallPerScan)
{
    // A mistyped secret says the same for every reference of the host. One signed call, one
    // reason from AWS, and the references after it are answered from the memory of the scan.
    m_shareRefusals = true;
    m_source.results.push_back(failure(400, "AWS rejected the signature, so the secret access key does not match the access key id (InvalidSignatureException)"));

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);

    ASSERT_EQ(m_refusedScopes.size(), 1u);
    EXPECT_EQ(m_refusedScopes.begin()->first, ECR_HOST) << "kept under the host: it is the credential that failed";

    for (const std::string reference : {SECOND_TAG, OTHER_REPOSITORY, "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app:3"})
    {
        auto* next {new ScriptedTransport()};
        scriptResolution(*next);
        const auto nextReader = ecrReader(reference, next);

        EXPECT_EQ(nextReader->discover().status, ReadStatus::Failed) << reference;
        EXPECT_TRUE(next->calls.empty()) << reference << " asked the registry";
    }

    EXPECT_EQ(m_source.calls.size(), 1u) << "one signed call for all four references";
    EXPECT_EQ(countLogged("InvalidSignatureException"), 4u);
    EXPECT_TRUE(logged("An earlier reference of " + std::string {ECR_HOST} + " was refused in this scan, so nothing was requested"));
    EXPECT_TRUE(m_cache.lookup(cacheKey()) == std::nullopt);
}

TEST_F(EcrReaderTest, EveryKindOfAwsRefusalOfTheCredentialIsRemembered)
{
    for (const long status : {400L, 401L, 403L, 404L})
    {
        SCOPED_TRACE(status);

        m_refusedScopes.clear();
        m_source.calls.clear();
        m_shareRefusals = true;
        m_source.results.push_back(failure(status, "AWS refused the credential"));

        EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
        m_transport = new ScriptedTransport();
        EXPECT_EQ(m_refusedScopes.count(ECR_HOST), 1u);
    }
}

TEST_F(EcrReaderTest, ThrottlingAndServerErrorsFromAwsAreNotRemembered)
{
    m_shareRefusals = true;
    m_config.limits.maxAttempts = 2;

    for (const long status : {429L, 500L, 502L, 503L, 504L, TRANSPORT_FAILURE})
    {
        SCOPED_TRACE(status);

        m_refusedScopes.clear();
        m_source.calls.clear();
        m_source.results.push_back(failure(status, "AWS could not be reached"));
        m_source.results.push_back(failure(status, "AWS could not be reached"));

        auto* first {new ScriptedTransport()};
        const auto firstReader = ecrReader(ECR_REFERENCE, first);
        EXPECT_EQ(firstReader->discover().status, ReadStatus::Failed);
        EXPECT_TRUE(m_refusedScopes.empty()) << "a failure that says nothing about the credential was kept";

        // The next reference tries again, and works.
        auto* next {new ScriptedTransport()};
        scriptResolution(*next);
        const auto nextReader = ecrReader(ECR_REFERENCE, next);
        EXPECT_EQ(nextReader->discover().status, ReadStatus::Success);
        EXPECT_EQ(m_source.calls.size(), 3u);

        m_cache.clear();
    }
}

TEST_F(EcrReaderTest, ATokenCallThrottledOnceAndThenAnsweredIsNotRemembered)
{
    m_shareRefusals = true;
    m_source.results.push_back(failure(429, "AWS throttled the request (ThrottlingException)"));
    scriptResolution(*m_transport);

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);
    EXPECT_TRUE(m_refusedScopes.empty());
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, ACredentialThatAwsRefusedIsStillReportedWhenTheStoreIsMissingAKey)
{
    // The check of the store comes first and costs nothing, so it is not what is remembered.
    m_shareRefusals = true;
    m_credentials.values.erase("container_images/ecr_secret");

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_refusedScopes.empty());
}

TEST_F(EcrReaderTest, ARegionRefusalIsRememberedForTheRepositoryToo)
{
    m_shareRefusals = true;
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "eu-west-1"});

    auto* first {new ScriptedTransport()};
    first->answers.push_back({"/manifests/", json(400, DENIED_BODY)});
    EXPECT_EQ(ecrReader(ECR_REFERENCE, first)->discover().status, ReadStatus::Failed);

    m_logs.clear();
    auto* second {new ScriptedTransport()};
    scriptResolution(*second);
    const auto secondReader = ecrReader(SECOND_TAG, second);
    EXPECT_EQ(secondReader->discover().status, ReadStatus::Failed);

    EXPECT_TRUE(second->calls.empty());
    EXPECT_EQ(m_source.calls.size(), 1u);
    EXPECT_TRUE(logged("the configured region 'eu-west-1'"));
}

TEST_F(EcrReaderTest, TheTwoFormsOfRefusalScopeCannotMeet)
{
    // The two scope forms cannot meet: an ECR scope is the host and the whole repository.
    RegistryReference ecr;
    std::string error;
    ASSERT_TRUE(parseRegistryReference(ECR_REFERENCE, ecr, error)) << error;
    EXPECT_EQ(ecr.refusalScope(), std::string {ECR_HOST} + "/my-backend");

    RegistryReference ghcr;
    ASSERT_TRUE(parseRegistryReference("ghcr.io/owner/app/sub:1.0", ghcr, error)) << error;
    EXPECT_EQ(ghcr.refusalScope(), "ghcr.io/owner");
}

// A repository, a role or a user named after the words the registry uses about a token.
TEST_F(EcrReaderTest, AMissingPermissionOnARepositoryNamedAfterATokenIsNotATokenRefusal)
{
    for (const std::string name : {"token-service", "expiry-job", "oauth-token-proxy"})
    {
        SCOPED_TRACE(name);

        m_source.calls.clear();
        m_logs.clear();
        m_cache.clear();

        const auto body {std::string {R"({"errors":[{"code":"DENIED","message":"User: arn:aws:iam::123456789012:user/token-admin )"} +
                         R"(is not authorized to perform: ecr:BatchGetImage on resource: )" +
                         "arn:aws:ecr:us-east-1:123456789012:repository/" + name + R"("}]})"};

        for (auto index = 0; index < 3; ++index)
        {
            auto* transport {new ScriptedTransport()};
            transport->answers.push_back({"/manifests/", json(403, body)});
            const auto instance = ecrReader(std::string {ECR_HOST} + "/" + name + ":1.0", transport);
            EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
            EXPECT_EQ(transport->countMatching("/manifests/"), 1u) << "the refused request was repeated";
        }

        EXPECT_EQ(m_source.calls.size(), 1u) << "a missing permission must not cost a second signed call";
        EXPECT_TRUE(m_cache.lookup(cacheKey()).has_value()) << "a valid token was dropped";
        EXPECT_TRUE(logged("is not authorized to perform: ecr:BatchGetImage"));
    }
}

TEST_F(EcrReaderTest, AMissingPermissionUnderARegionOverrideDoesNotBlameTheRegion)
{
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "eu-west-1"});

    const auto body {std::string {R"({"errors":[{"code":"DENIED","message":"User: arn:aws:iam::123456789012:user/ci )"} +
                     R"(is not authorized to perform: ecr:BatchGetImage on resource: )" +
                     R"(arn:aws:ecr:us-east-1:123456789012:repository/token-service"}]})"};

    auto* transport {new ScriptedTransport()};
    transport->answers.push_back({"/manifests/", json(403, body)});
    const auto instance = ecrReader(std::string {ECR_HOST} + "/token-service:1.0", transport);

    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);
    EXPECT_FALSE(logged("the registry refused the token requested in the configured region"))
        << "the permission was blamed on the region";
    EXPECT_TRUE(logged("is not authorized to perform: ecr:BatchGetImage"));
    EXPECT_EQ(m_source.calls.size(), 1u);
}

// What is remembered, from each place a refusal ends a reference.
TEST_F(EcrReaderTest, ARejectedCredentialAnswered401IsRememberedForTheRepository)
{
    m_shareRefusals = true;

    auto* first {new ScriptedTransport()};
    first->answers.push_back({"/manifests/", json(401, PERMISSION_BODY)});
    EXPECT_EQ(ecrReader(ECR_REFERENCE, first)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_refusedScopes.count(std::string {ECR_HOST} + "/my-backend"), 1u);

    auto* second {new ScriptedTransport()};
    scriptResolution(*second);
    const auto secondReader = ecrReader(SECOND_TAG, second);
    EXPECT_EQ(secondReader->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(second->calls.empty());
}

TEST_F(EcrReaderTest, ATokenRefusedAgainAfterItsRenewalIsRememberedForTheRepository)
{
    m_shareRefusals = true;

    auto* first {new ScriptedTransport()};
    first->answers.push_back({"/manifests/", json(400, DENIED_BODY)});
    EXPECT_EQ(ecrReader(ECR_REFERENCE, first)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_source.calls.size(), 2u);
    EXPECT_EQ(m_refusedScopes.count(std::string {ECR_HOST} + "/my-backend"), 1u);

    m_logs.clear();
    auto* second {new ScriptedTransport()};
    scriptResolution(*second);
    const auto secondReader = ecrReader(SECOND_TAG, second);
    EXPECT_EQ(secondReader->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(second->calls.empty());

    // The reason ends in a period, and the line goes on: one full stop between them, not two.
    EXPECT_TRUE(logged("DENIED: Your Authorization Token is invalid. An earlier reference of "));

    for (const auto& entry : m_logs)
    {
        EXPECT_EQ(entry.second.find(".."), std::string::npos) << entry.second;
    }
}

// GetAuthorizationToken follows the retry rules of the token exchange of the other registries.
TEST_F(EcrReaderTest, ThrottlingFromAwsEndsAtOnceWhenTheModuleIsAskedToStop)
{
    for (auto attempt = 0; attempt < 5; ++attempt)
    {
        m_source.results.push_back(failure(429, "AWS throttled the request (ThrottlingException)"));
        m_source.results.back().retryAfter = "30";
    }

    // The stop arrives while the call is in flight. A wait for the 30 seconds AWS asked for
    // must not hold the module thread: waitOrStop answers at once.
    m_source.onFetch = [this] { m_stop = true; };

    const auto before {std::chrono::steady_clock::now()};
    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_LT(std::chrono::steady_clock::now() - before, std::chrono::seconds {5});

    EXPECT_EQ(m_source.calls.size(), 1u);
    EXPECT_TRUE(logged("the module was asked to stop"));
}

TEST_F(EcrReaderTest, ThrottlingWaitsForWhatAwsAsksFor)
{
    // The base delay is 1 ms in this suite, so only the Retry-After can make this wait a second.
    m_source.results.push_back(failure(429, "AWS throttled the request (ThrottlingException)"));
    m_source.results.back().retryAfter = "1";
    scriptResolution(*m_transport);

    const auto before {std::chrono::steady_clock::now()};
    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Success);

    EXPECT_GE(std::chrono::steady_clock::now() - before, std::chrono::milliseconds {900});
    EXPECT_EQ(m_source.calls.size(), 2u);
}

TEST_F(EcrReaderTest, AStopRequestedBeforeTheCallPreventsIt)
{
    m_stop = true;

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_TRUE(m_source.calls.empty()) << "nothing may be signed once the module is stopping";
}

TEST_F(EcrReaderTest, AServerErrorFromAwsIsRetried)
{
    for (const long status : {500L, 502L, 503L, 504L})
    {
        SCOPED_TRACE(status);

        m_source.calls.clear();
        m_cache.clear();
        m_source.results.push_back(failure(status, "AWS answered " + std::to_string(status)));

        auto* transport {new ScriptedTransport()};
        scriptResolution(*transport);

        EXPECT_EQ(ecrReader(ECR_REFERENCE, transport)->discover().status, ReadStatus::Success);
        EXPECT_EQ(m_source.calls.size(), 2u);
    }
}

TEST_F(EcrReaderTest, ACallThatWouldFailTheSameWayIsTriedOnce)
{
    // A certificate that does not verify or an unusable address: no response, and the same
    // on every attempt, so the back-off would only be spent on the same answer.
    for (auto attempt = 0; attempt < 5; ++attempt)
    {
        auto copy {failure(TRANSPORT_FAILURE, "the request to AWS could not be completed: SSL peer certificate")};
        copy.retryable = false;
        m_source.results.push_back(std::move(copy));
    }

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_source.calls.size(), 1u);
    EXPECT_TRUE(logged("SSL peer certificate"));
}

TEST_F(EcrReaderTest, ACallThatMayClearUpIsRetriedUpToTheAttempts)
{
    for (auto attempt = 0; attempt < 10; ++attempt)
    {
        m_source.results.push_back(failure(TRANSPORT_FAILURE, "the request to AWS could not be completed: timeout"));
    }

    m_config.limits.maxAttempts = 3;

    EXPECT_EQ(ecrReader(ECR_REFERENCE, m_transport)->discover().status, ReadStatus::Failed);
    EXPECT_EQ(m_source.calls.size(), 3u);
}

// What is stored for an ECR image is what is stored for a GHCR one.
TEST_F(EcrReaderTest, TheStoredNameIsTheFullImageName)
{
    scriptResolution(*m_transport);

    const auto result {ecrReader(ECR_REFERENCE, m_transport)->discover()};

    ASSERT_EQ(result.status, ReadStatus::Success);
    ASSERT_EQ(result.records.size(), 1u);
    EXPECT_EQ(result.records.front().tag, std::string {ECR_HOST} + "/my-backend:1.0");
    ASSERT_EQ(result.records.front().tags.size(), 1u);
    EXPECT_EQ(result.records.front().tags.front(), std::string {ECR_HOST} + "/my-backend:1.0");
    EXPECT_EQ(result.records.front().source.location, ECR_REFERENCE);
}

TEST_F(EcrReaderTest, ATagFollowedByADigestPullsTheDigestAndKeepsTheTag)
{
    const std::string digest {"sha256:" + std::string(64, 'a')};

    auto* transport {new ScriptedTransport()};
    transport->answers.push_back({"/manifests/" + digest, json(200, MANIFEST)});
    transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

    const auto instance = ecrReader(std::string {ECR_HOST} + "/my-backend:1.0@" + digest, transport);
    const auto result {instance->discover()};

    ASSERT_EQ(result.status, ReadStatus::Success);
    ASSERT_EQ(result.records.size(), 1u);
    EXPECT_EQ(transport->countMatching("/manifests/1.0"), 0u) << "the tag was pulled instead of the digest";
    EXPECT_EQ(result.records.front().tag, std::string {ECR_HOST} + "/my-backend:1.0@" + digest);
    ASSERT_EQ(result.records.front().tags.size(), 1u);
    EXPECT_EQ(result.records.front().tags.front(), std::string {ECR_HOST} + "/my-backend:1.0");
}

// The layer path is the shared one: nothing ECR-specific reads, bounds or retries a layer.
class EcrLayerTest : public EcrReaderTest
{
    protected:
        /// @brief A reader of the private reference whose layer attempts end as @p outcomes, the last repeating.
        std::unique_ptr<RegistryImageReader> layerReader(ScriptedTransport* transport, std::vector<BlobOutcome> outcomes)
        {
            m_outcomes = std::move(outcomes);

            auto instance {ecrReader(ECR_REFERENCE, transport)};
            instance->setBlobStreamFactory([this](const TransportConfig&,
                                                  const std::string&,
                                                  const std::vector<std::string>& headers,
                                                  const std::uint64_t,
                                                  const std::atomic<bool>*)
            {
                m_attemptHeaders.push_back(headers);

                const auto index {std::min(m_attemptHeaders.size(), m_outcomes.size()) - 1};

                return std::unique_ptr<IBlobStream> {std::make_unique<ScriptedBlob>(m_outcomes[index])};
            });

            return instance;
        }

        static BlobOutcome refused(const long status)
        {
            BlobOutcome outcome;
            outcome.failed = true;
            outcome.status = status;
            outcome.error = "the registry answered " + std::to_string(status);

            return outcome;
        }

        /// @brief The image, with one layer, and a transport that answers the manifest as the
        /// registry would answer the request that follows a refused layer.
        ScriptedTransport* imageWithALayer(std::vector<HttpResponse> manifestAnswers)
        {
            auto* transport {new ScriptedTransport()};
            transport->answers.push_back({"/blobs/sha256:cccc3333", json(200, configBlob())});

            for (auto& answer : manifestAnswers)
            {
                transport->queued["/manifests/1.0"].push_back(std::move(answer));
            }

            return transport;
        }

        std::vector<std::vector<std::string>> m_attemptHeaders;
        std::vector<BlobOutcome> m_outcomes;
};

TEST_F(EcrLayerTest, ALayerRefusedForTheTokenIsRenewedOnceAfterTheManifestConfirmsIt)
{
    // The layer is refused with no body to read. The manifest is asked for again, and the
    // registry says the token is the cause.
    auto* transport {imageWithALayer({json(200, MANIFEST_WITH_A_LAYER_ECR), json(400, DENIED_BODY)})};

    const auto instance = layerReader(transport, {refused(400), BlobOutcome {}});
    EXPECT_EQ(instance->discover().status, ReadStatus::Success);

    EXPECT_EQ(m_source.calls.size(), 2u);
    ASSERT_EQ(m_attemptHeaders.size(), 2u);
    ASSERT_EQ(m_attemptHeaders[0].size(), 1u);
    EXPECT_EQ(m_attemptHeaders[0][0], "Authorization: Basic ecr-token-1");
    ASSERT_EQ(m_attemptHeaders[1].size(), 1u);
    EXPECT_EQ(m_attemptHeaders[1][0], "Authorization: Basic ecr-token-2");
}

TEST_F(EcrLayerTest, ALayerRefusedForAPermissionIsNotRenewedAndReportsTheStatus)
{
    auto* transport {imageWithALayer({json(200, MANIFEST_WITH_A_LAYER_ECR), json(403, PERMISSION_BODY)})};

    const auto instance = layerReader(transport, {refused(403)});
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_EQ(m_source.calls.size(), 1u) << "a missing permission must not cost a second signed call";
    EXPECT_EQ(m_attemptHeaders.size(), 1u);
    EXPECT_TRUE(logged("layer sha256:dddd4444 could not be retrieved: the registry answered 403"));
    EXPECT_FALSE(logged("renewing the credential failed"));
}

TEST_F(EcrLayerTest, ALayerRefusedAfterARegionOverrideSaysSoAndIsNotRenewed)
{
    m_config.registryAuth.clear();
    m_config.registryAuth.push_back({ECR_HOST, "ecr_key_id", "ecr_secret", "eu-west-1"});

    auto* transport {imageWithALayer({json(200, MANIFEST_WITH_A_LAYER_ECR), json(400, DENIED_BODY)})};

    const auto instance = layerReader(transport, {refused(400)});
    EXPECT_EQ(instance->discover().status, ReadStatus::Failed);

    EXPECT_EQ(m_source.calls.size(), 1u);
    EXPECT_TRUE(logged("the registry refused the token requested in the configured region 'eu-west-1'"));
}

TEST_F(EcrLayerTest, ALayerThatFailsMidTransferIsRetriedLikeAnyOther)
{
    auto* transport {imageWithALayer({json(200, MANIFEST_WITH_A_LAYER_ECR)})};

    BlobOutcome reset;
    reset.failed = true;
    reset.status = 200;

    const auto instance = layerReader(transport, {reset, BlobOutcome {}});
    EXPECT_EQ(instance->discover().status, ReadStatus::Success);

    EXPECT_EQ(m_attemptHeaders.size(), 2u);
    EXPECT_EQ(m_source.calls.size(), 1u) << "a reset is not a reason to ask AWS again";
}

TEST_F(EcrLayerTest, AnUnsupportedLayerCompressionIsSkippedAndReported)
{
    auto* transport {imageWithALayer({json(200, MANIFEST_WITH_A_LAYER_ECR)})};

    BlobOutcome xz;
    xz.content = std::string {"\xfd\x37\x7a\x58\x5a\x00", 6} + " compressed bytes this reader cannot expand";

    const auto instance = layerReader(transport, {xz});
    EXPECT_EQ(instance->discover().status, ReadStatus::Success);

    EXPECT_TRUE(logged("NOT IMPLEMENTED: layer 'sha256:dddd4444'"));
    EXPECT_TRUE(logged("is xz compressed"));
}
