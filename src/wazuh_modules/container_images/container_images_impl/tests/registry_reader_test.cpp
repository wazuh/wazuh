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
#include "registry_image_reader.hpp"
#include "registry_transport.hpp"

#include <gtest/gtest.h>

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
