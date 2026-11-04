/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/downloadEndpoint.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using namespace remoted::endpoints::download;
using remoted::endpoints::WpkAuthorization;

namespace
{
    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Creates a throwaway directory tree and removes it on destruction.
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = "/tmp/wazuh-download-test-XXXXXX";
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');

            const char* created = ::mkdtemp(buffer.data());
            if (created == nullptr)
            {
                throw std::system_error {errno, std::generic_category(), "mkdtemp"};
            }
            m_path = created;
        }

        ~TempDir()
        {
            for (auto it = m_files.rbegin(); it != m_files.rend(); ++it)
            {
                ::unlink(it->c_str());
            }
            for (auto it = m_dirs.rbegin(); it != m_dirs.rend(); ++it)
            {
                ::rmdir(it->c_str());
            }
            ::rmdir(m_path.c_str());
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::string& path() const
        {
            return m_path;
        }

        std::string makeDir(const std::string& relative)
        {
            std::string full = m_path;
            std::size_t start = 0;
            while (start < relative.size())
            {
                const auto slash = relative.find('/', start);
                const auto part =
                    relative.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
                full += "/" + part;
                ::mkdir(full.c_str(), 0700);
                m_dirs.push_back(full);
                if (slash == std::string::npos)
                {
                    break;
                }
                start = slash + 1;
            }
            return full;
        }

        std::string writeFile(const std::string& relative, const std::string& contents)
        {
            const std::string full = m_path + "/" + relative;
            std::ofstream out {full, std::ios::binary};
            out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
            out.close();
            m_files.push_back(full);
            return full;
        }

        std::string track(const std::string& relative)
        {
            const std::string full = m_path + "/" + relative;
            m_files.push_back(full);
            return full;
        }

    private:
        std::string m_path;
        std::vector<std::string> m_files;
        std::vector<std::string> m_dirs;
    };

    /// Drains a source the way the transport does.
    std::string drain(remoted::http::IByteSource& source, std::size_t chunkSize)
    {
        std::string collected;
        std::string chunk;

        while (true)
        {
            chunk.resize(chunkSize);
            const auto bytesRead = source.read(chunk.data(), chunkSize);
            if (bytesRead == 0)
            {
                break;
            }
            collected.append(chunk, 0, bytesRead);
        }

        return collected;
    }

    /// Records whichever delivery mode the handler chose, draining a stream the way the transport
    /// would so a test can assert on the exact bytes an agent would receive.
    class RecordingResponder final : public remoted::http::IHttpResponder
    {
    public:
        void send(remoted::http::HttpResponse response) override
        {
            ++responses;
            if (answered)
            {
                return;
            }
            answered = true;
            status = response.status;
            headers = std::move(response.headers);
            body = std::move(response.body);
        }

        void stream(remoted::http::StreamResponse response) override
        {
            ++responses;
            if (throwOnStream)
            {
                throw std::runtime_error("stream refused");
            }
            if (answered)
            {
                return;
            }
            answered = true;
            streamed = true;
            status = response.status;
            headers = response.headers;
            // chunkSize 0 means "use the server's configured size" (see StreamResponse); the real
            // transport substitutes HttpServerConfig::streamChunkSize there, so a double that
            // passed the 0 straight through would read nothing at all.
            chunkSize = response.chunkSize != 0 ? response.chunkSize : 64U * 1024U;
            body = drain(*response.source, chunkSize);
        }

        int responses {0}; ///< Every send()/stream() call, including the ones ignored after the first.
        bool throwOnStream {false};
        bool answered {false};
        bool streamed {false};
        std::size_t chunkSize {0}; ///< The size actually used, after the 0 -> default substitution.
        int status {0};
        std::string body;
        std::vector<std::pair<std::string, std::string>> headers;
    };

    /// Builds a verified request whose payload views a buffer the caller keeps alive.
    std::shared_ptr<remoted::auth::AuthenticatedRequest> authenticatedRequest(const std::shared_ptr<std::string>& body,
                                                                              const std::string& agentId = "001")
    {
        auto request = std::make_shared<remoted::auth::AuthenticatedRequest>();
        request->agentId = agentId;
        request->protocolVersion = "1";
        request->method = "POST";
        request->requestTarget = "/download";
        request->payload = remoted::auth::Payload {*body, body};
        return request;
    }

    /// Stands in for the registry-backed source: one answer, or nullopt for "this agent has no
    /// known membership" (never enrolled a startup, or evicted).
    class FakeAgentGroupSource : public remoted::endpoints::IAgentGroupSource
    {
    public:
        explicit FakeAgentGroupSource(std::optional<std::string> selector)
            : m_selector(std::move(selector))
        {
        }

        void resolveSelector(const std::string&,
                             std::function<void(remoted::endpoints::GroupVerdict)> done) const override
        {
            ++calls;
            if (m_selector)
            {
                done(remoted::endpoints::GroupVerdict {remoted::endpoints::GroupVerdictKind::Selector, *m_selector});
            }
            else
            {
                done(remoted::endpoints::GroupVerdict {remoted::endpoints::GroupVerdictKind::Deny, {}});
            }
        }

        mutable std::atomic<int> calls {0};

    private:
        std::optional<std::string> m_selector;
    };

    /// A source whose verdict the test controls: held until deliver(), which may run on any thread.
    class ScriptedAgentGroupSource : public remoted::endpoints::IAgentGroupSource
    {
    public:
        void resolveSelector(const std::string&,
                             std::function<void(remoted::endpoints::GroupVerdict)> done) const override
        {
            std::lock_guard lock(m_mutex);
            m_pending = std::move(done);
        }
        bool pending() const
        {
            std::lock_guard lock(m_mutex);
            return static_cast<bool>(m_pending);
        }
        void deliver(remoted::endpoints::GroupVerdict verdict) const
        {
            std::function<void(remoted::endpoints::GroupVerdict)> done;
            {
                std::lock_guard lock(m_mutex);
                done = std::move(m_pending);
            }
            done(std::move(verdict));
        }

    private:
        mutable std::mutex m_mutex;
        mutable std::function<void(remoted::endpoints::GroupVerdict)> m_pending;
    };

    std::shared_ptr<const remoted::endpoints::IAgentGroupSource> sourceFor(std::optional<std::string> selector)
    {
        return std::make_shared<const FakeAgentGroupSource>(std::move(selector));
    }

    /// Default selector for the cases that are not about authorization: whatever the body asks for
    /// is the agent's own, so those cases keep exercising exactly what they used to.
    std::shared_ptr<const remoted::endpoints::IAgentGroupSource> allowingSourceFor(const std::string& bodyText)
    {
        const auto idStart = bodyText.find(R"("resource_id":")");
        if (idStart == std::string::npos)
        {
            return sourceFor(std::nullopt);
        }
        const auto valueStart = idStart + std::string_view {R"("resource_id":")"}.size();
        const auto valueEnd = bodyText.find('"', valueStart);
        if (valueEnd == std::string::npos)
        {
            return sourceFor(std::nullopt);
        }
        return sourceFor(bodyText.substr(valueStart, valueEnd - valueStart));
    }

    /// Stands in for the task manager: one fixed answer, delivered the way the selected mode says.
    class FakeWpkAuthorizer final : public remoted::endpoints::IWpkAuthorizer
    {
    public:
        enum class Mode
        {
            Synchronous,       ///< done() before authorize() returns.
            FromAnotherThread, ///< done() on a thread the test joins with join().
            Hold,              ///< done() kept in `held`, for the test to call.
            Twice              ///< done() twice, synchronously.
        };

        explicit FakeWpkAuthorizer(WpkAuthorization answer, Mode mode = Mode::Synchronous)
            : m_answer(answer)
            , m_mode(mode)
        {
        }

        ~FakeWpkAuthorizer() override
        {
            join();
        }

        FakeWpkAuthorizer(const FakeWpkAuthorizer&) = delete;
        FakeWpkAuthorizer& operator=(const FakeWpkAuthorizer&) = delete;

        void authorize(const std::string& agentId,
                       const std::string& wpkFile,
                       std::function<void(WpkAuthorization)> done) const override
        {
            calls.emplace_back(agentId, wpkFile);
            if (onAuthorize)
            {
                onAuthorize();
            }

            switch (m_mode)
            {
                case Mode::Synchronous: done(m_answer); break;
                case Mode::FromAnotherThread:
                    m_thread = std::thread([answer = m_answer, done = std::move(done)] { done(answer); });
                    break;
                case Mode::Hold: held = std::move(done); break;
                case Mode::Twice:
                    done(m_answer);
                    done(m_answer);
                    break;
            }
        }

        void join() const
        {
            if (m_thread.joinable())
            {
                m_thread.join();
            }
        }

        mutable std::vector<std::pair<std::string, std::string>> calls; ///< (agentId, wpkFile) per call.
        mutable std::function<void(WpkAuthorization)> held;             ///< Mode::Hold only.
        std::function<void()> onAuthorize;                              ///< Runs inside authorize(), before any answer.

    private:
        WpkAuthorization m_answer;
        Mode m_mode;
        mutable std::thread m_thread;
    };

    std::shared_ptr<FakeWpkAuthorizer>
    wpkAuthorizerAnswering(WpkAuthorization answer, FakeWpkAuthorizer::Mode mode = FakeWpkAuthorizer::Mode::Synchronous)
    {
        return std::make_shared<FakeWpkAuthorizer>(answer, mode);
    }

    /// For the cases that are not about WPK authorization.
    std::shared_ptr<const remoted::endpoints::IWpkAuthorizer> grantingWpkAuthorizer()
    {
        return wpkAuthorizerAnswering(WpkAuthorization::Granted);
    }

    std::shared_ptr<RecordingResponder> runOn(const remoted::endpoints::AuthenticatedHandler& handler,
                                              const std::string& bodyText)
    {
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(bodyText);
        handler(authenticatedRequest(body), responder);
        return responder;
    }

    std::string wpkBody(const std::string& wpkFile)
    {
        return R"({"resource_type":"wpk","resource_id":")" + wpkFile + R"("})";
    }

    std::shared_ptr<RecordingResponder> runHandler(const std::string& bodyText, ResourcePaths paths = {})
    {
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(bodyText);
        makeHandler(std::move(paths), {}, allowingSourceFor(bodyText), grantingWpkAuthorizer())(
            authenticatedRequest(body), responder);
        return responder;
    }

    /// Same, with an explicit group source -- the authorization cases.
    std::shared_ptr<RecordingResponder>
    runHandlerAs(const std::string& bodyText, std::optional<std::string> ownSelector, ResourcePaths paths = {})
    {
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(bodyText);
        makeHandler(std::move(paths), {}, sourceFor(std::move(ownSelector)), grantingWpkAuthorizer())(
            authenticatedRequest(body), responder);
        return responder;
    }

    DownloadRequest configRequest(std::string group)
    {
        return DownloadRequest {ResourceType::Config, std::move(group)};
    }

    constexpr auto VALID_CONFIG_BODY {R"({"resource_type":"config","resource_id":"web-servers"})"};
} // namespace

// ---------------------------------------------------------------------------
// parseRequest
// ---------------------------------------------------------------------------

TEST(DownloadParseRequestTest, AcceptsAConfigRequest)
{
    const auto parsed = parseRequest(VALID_CONFIG_BODY);

    ASSERT_TRUE(std::holds_alternative<DownloadRequest>(parsed));
    EXPECT_EQ(std::get<DownloadRequest>(parsed).type, ResourceType::Config);
    EXPECT_EQ(std::get<DownloadRequest>(parsed).resourceId, "web-servers");
}

TEST(DownloadParseRequestTest, AcceptsAWpkRequest)
{
    const auto parsed = parseRequest(R"({"resource_type":"wpk","resource_id":"wazuh_agent_v5.0.1_linux_x86_64.wpk"})");

    ASSERT_TRUE(std::holds_alternative<DownloadRequest>(parsed));
    EXPECT_EQ(std::get<DownloadRequest>(parsed).type, ResourceType::Wpk);
    EXPECT_EQ(std::get<DownloadRequest>(parsed).resourceId, "wazuh_agent_v5.0.1_linux_x86_64.wpk");
}

TEST(DownloadParseRequestTest, AcceptsMembersInEitherOrder)
{
    EXPECT_TRUE(std::holds_alternative<DownloadRequest>(
        parseRequest(R"({"resource_id":"web-servers","resource_type":"config"})")));
}

TEST(DownloadParseRequestTest, RejectsMalformedBodies)
{
    const char* bodies[] = {
        "",                                                          // empty
        "not json",                                                  // not JSON
        "[]",                                                        // not an object
        R"("a string")",                                             // not an object
        R"({"resource_type":"config"})",                             // missing resource_id
        R"({"resource_id":"web-servers"})",                          // missing resource_type
        R"({"resource_type":"config","resource_id":"a","extra":1})", // additionalProperties: false
        R"({"resource_type":1,"resource_id":"a"})",                  // wrong type
        R"({"resource_type":"config","resource_id":123})",           // wrong type
        R"({"resource_type":"config","resource_id":null})",          // wrong type
        R"({"resource_type":"config","resource_id":"a",)",           // truncated
    };

    for (const auto* body : bodies)
    {
        const auto parsed = parseRequest(body);
        ASSERT_TRUE(std::holds_alternative<RequestError>(parsed)) << "accepted: " << body;
        EXPECT_EQ(std::get<RequestError>(parsed), RequestError::Malformed) << "body: " << body;
    }
}

TEST(DownloadParseRequestTest, RejectsAnUnknownResourceType)
{
    const auto parsed = parseRequest(R"({"resource_type":"secrets","resource_id":"a"})");

    ASSERT_TRUE(std::holds_alternative<RequestError>(parsed));
    EXPECT_EQ(std::get<RequestError>(parsed), RequestError::UnknownResourceType);
}

TEST(DownloadParseRequestTest, ResourceTypeIsCaseSensitive)
{
    const auto parsed = parseRequest(R"({"resource_type":"CONFIG","resource_id":"a"})");

    ASSERT_TRUE(std::holds_alternative<RequestError>(parsed));
    EXPECT_EQ(std::get<RequestError>(parsed), RequestError::UnknownResourceType);
}

TEST(DownloadParseRequestTest, RejectsABodyOverTheParseCap)
{
    // Rejected on size BEFORE parsing, so a hostile blob never costs heap proportional to itself.
    std::string body = R"({"resource_type":"config","resource_id":")";
    body.append(kMaxRequestJsonSize, 'a');
    body.append(R"("})");

    const auto parsed = parseRequest(body);
    ASSERT_TRUE(std::holds_alternative<RequestError>(parsed));
    EXPECT_EQ(std::get<RequestError>(parsed), RequestError::Malformed);
}

TEST(DownloadParseRequestTest, DeeplyNestedInputIsRejectedWithoutBlowingTheStack)
{
    // Iterative parsing keeps the parser's stack usage constant; this asserts it does not crash.
    const auto parsed = parseRequest(std::string(1000, '['));

    ASSERT_TRUE(std::holds_alternative<RequestError>(parsed));
    EXPECT_EQ(std::get<RequestError>(parsed), RequestError::Malformed);
}

TEST(DownloadParseRequestTest, ReportsAnInvalidResourceIdDistinctlyFromAMalformedBody)
{
    const auto parsed = parseRequest(R"({"resource_type":"config","resource_id":"../../etc/shadow"})");

    ASSERT_TRUE(std::holds_alternative<RequestError>(parsed));
    EXPECT_EQ(std::get<RequestError>(parsed), RequestError::InvalidResourceId);
}

// ---------------------------------------------------------------------------
// Resource-id grammars
// ---------------------------------------------------------------------------

TEST(DownloadGroupNameTest, AcceptsWazuhsGroupGrammar)
{
    EXPECT_TRUE(isValidGroupName("default"));
    EXPECT_TRUE(isValidGroupName("web-servers"));
    EXPECT_TRUE(isValidGroupName("centos_8.1"));
    EXPECT_TRUE(isValidGroupName("a:b;c=d+e!f@g(h)"));
    EXPECT_TRUE(isValidGroupName(std::string(255, 'g')));
}

TEST(DownloadGroupNameTest, RejectsPathAndSeparatorCharacters)
{
    EXPECT_FALSE(isValidGroupName(""));
    EXPECT_FALSE(isValidGroupName("."));
    EXPECT_FALSE(isValidGroupName(".."));
    EXPECT_FALSE(isValidGroupName("../../etc/shadow"));
    EXPECT_FALSE(isValidGroupName("a/b"));
    EXPECT_FALSE(isValidGroupName("a\\b"));
    EXPECT_FALSE(isValidGroupName(std::string("a\0b", 3)));
    EXPECT_FALSE(isValidGroupName("%2e%2e%2f"));
    EXPECT_FALSE(isValidGroupName("caf\xc3\xa9"));
    EXPECT_FALSE(isValidGroupName(std::string(256, 'g')));
}

TEST(DownloadGroupNameTest, RejectsACommaAsASingleGroupName)
{
    // A single group name never contains a comma; the CSV form is a selector, checked separately.
    EXPECT_FALSE(isValidGroupName("default,web-servers"));
}

TEST(DownloadGroupSelectorTest, AcceptsOneGroupOrAMultigroupCsv)
{
    EXPECT_TRUE(isValidGroupSelector("web-servers"));
    EXPECT_TRUE(isValidGroupSelector("web-servers,databases"));
    EXPECT_TRUE(isValidGroupSelector("a,b,c,d"));
}

TEST(DownloadGroupSelectorTest, RejectsMalformedSeparatorUse)
{
    // Each entry must be a valid group name, which rules these out without special cases.
    EXPECT_FALSE(isValidGroupSelector(""));
    EXPECT_FALSE(isValidGroupSelector(","));
    EXPECT_FALSE(isValidGroupSelector(",web-servers")); // leading
    EXPECT_FALSE(isValidGroupSelector("web-servers,")); // trailing
    EXPECT_FALSE(isValidGroupSelector("web,,servers")); // doubled
}

TEST(DownloadGroupSelectorTest, RejectsATraversableEntryAnywhereInTheSelector)
{
    EXPECT_FALSE(isValidGroupSelector("web-servers,.."));
    EXPECT_FALSE(isValidGroupSelector("..,web-servers"));
    EXPECT_FALSE(isValidGroupSelector("web-servers,a/b"));
    EXPECT_FALSE(isValidGroupSelector("a,."));
}

TEST(DownloadWpkNameTest, AcceptsRealisticPackageNames)
{
    EXPECT_TRUE(isValidWpkFilename("wazuh_agent_v5.0.1_linux_x86_64.wpk"));
    EXPECT_TRUE(isValidWpkFilename("a.wpk"));
}

TEST(DownloadWpkNameTest, RequiresTheWpkExtension)
{
    EXPECT_FALSE(isValidWpkFilename("wazuh_agent_v5.0.1"));
    EXPECT_FALSE(isValidWpkFilename("passwd"));
    EXPECT_FALSE(isValidWpkFilename(".wpk")); // leading dot, even with the right extension
    EXPECT_FALSE(isValidWpkFilename("wpk"));
    EXPECT_FALSE(isValidWpkFilename(""));
}

TEST(DownloadWpkNameTest, RejectsAnythingThatCouldLeaveTheUpgradeDirectory)
{
    EXPECT_FALSE(isValidWpkFilename("../../../etc/shadow.wpk"));
    EXPECT_FALSE(isValidWpkFilename("sub/dir.wpk"));
    EXPECT_FALSE(isValidWpkFilename("..wpk"));   // starts with a dot
    EXPECT_FALSE(isValidWpkFilename("./a.wpk")); // starts with a dot
    EXPECT_FALSE(isValidWpkFilename(std::string("a\0.wpk", 6)));
    EXPECT_FALSE(isValidWpkFilename("a b.wpk"));
    EXPECT_FALSE(isValidWpkFilename("a:b.wpk")); // allowed in a group name, not in a filename
    EXPECT_FALSE(isValidWpkFilename(std::string(252, 'a') + ".wpk"));
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

TEST(DownloadErrorResponseTest, MapsRequestErrorsToDistinguishable400s)
{
    EXPECT_EQ(errorResponseFor(RequestError::Malformed).status, 400);
    EXPECT_EQ(errorResponseFor(RequestError::UnknownResourceType).status, 400);
    EXPECT_EQ(errorResponseFor(RequestError::InvalidResourceId).status, 400);
    EXPECT_NE(errorResponseFor(RequestError::Malformed).body, errorResponseFor(RequestError::UnknownResourceType).body);
}

TEST(DownloadErrorResponseTest, MapsNotFoundAndInternalDistinctly)
{
    EXPECT_EQ(errorResponseFor(LocateError::NotFound).status, 404);
    EXPECT_EQ(errorResponseFor(LocateError::Internal).status, 500);
}

// ---------------------------------------------------------------------------
// locateResource
// ---------------------------------------------------------------------------

TEST(DownloadLocateTest, ConfigResolvesUnderTheSharedDirectoryUsingTheRequestedGroup)
{
    // locateResource() maps a resource id to a path and nothing else; authorization happens above
    // it, in the handler (see DownloadHandlerTest's denial cases).
    const auto result = locateResource(configRequest("web-servers"), {});

    EXPECT_EQ(result.error, LocateError::None);
    EXPECT_EQ(result.path, std::string {remoted::paths::kSharedDir} + "/web-servers/merged.mg");
}

TEST(DownloadLocateTest, AnyRequestedGroupResolvesRegardlessOfTheAgent)
{
    // This layer is identity-free BY DESIGN: it cannot tell whose group it is, which is what keeps
    // its containment argument about the id grammars and O_NOFOLLOW alone. The membership check
    // that decides whose group it may be lives in the handler above it.
    for (const auto* group : {"web-servers", "databases", "default", "some-other-team"})
    {
        const auto result = locateResource(configRequest(group), {});
        EXPECT_EQ(result.error, LocateError::None);
        EXPECT_EQ(result.path, std::string {remoted::paths::kSharedDir} + "/" + group + "/merged.mg");
    }
}

TEST(DownloadMultigroupDirNameTest, MatchesWhatWazuhDbComputesForTheSameSelector)
{
    // wazuh-db builds the directory with OS_SHA256_String_sized(csv, out, WDB_GROUP_HASH_SIZE),
    // WDB_GROUP_HASH_SIZE == 32, i.e. the first SIXTEEN digest bytes as 32 lowercase hex characters.
    // Pinned literals: the first 32 hex characters of sha256 over each selector verbatim.
    EXPECT_EQ(multigroupDirName("web-servers,databases"), "97d668590155b0b50fb09c254d636adc");
    EXPECT_EQ(multigroupDirName("alpha,beta"), "76ba5a3bc22ef0b439168b9a5c771ceb");
    EXPECT_EQ(multigroupDirName("default,web-servers"), "b9d4f26372114529987a9805a4049313");
}

TEST(DownloadMultigroupDirNameTest, IsOrderSensitiveJustLikeWazuhDb)
{
    // The CSV is hashed verbatim, so a reordered selector names a different (non-existent)
    // directory. Sorting here would point at a directory the manager never created.
    EXPECT_NE(multigroupDirName("web-servers,databases"), multigroupDirName("databases,web-servers"));
}

TEST(DownloadLocateTest, AMultigroupSelectorResolvesUnderVarMultigroups)
{
    const auto result = locateResource(configRequest("web-servers,databases"), {});

    EXPECT_EQ(result.error, LocateError::None);
    EXPECT_EQ(result.path, "var/multigroups/97d668590155b0b50fb09c254d636adc/merged.mg");
}

TEST(DownloadLocateTest, HonoursInjectedBaseDirectories)
{
    ResourcePaths paths;
    paths.sharedDir = "/tmp/shared";
    paths.multigroupsDir = "/tmp/multigroups";
    paths.wpkDir = "/tmp/upgrade";

    EXPECT_EQ(locateResource(configRequest("a"), paths).path, "/tmp/shared/a/merged.mg");
    EXPECT_EQ(locateResource(configRequest("a,b"), paths).path,
              "/tmp/multigroups/" + multigroupDirName("a,b") + "/merged.mg");
    EXPECT_EQ(locateResource(DownloadRequest {ResourceType::Wpk, "p.wpk"}, paths).path, "/tmp/upgrade/p.wpk");
}

TEST(DownloadLocateTest, WpkResolvesUnderTheUpgradeDirectory)
{
    const auto result = locateResource(DownloadRequest {ResourceType::Wpk, "wazuh_agent_v5.0.1_linux_x86_64.wpk"}, {});

    EXPECT_EQ(result.error, LocateError::None);
    EXPECT_EQ(result.path, "var/upgrade/wazuh_agent_v5.0.1_linux_x86_64.wpk");
}

TEST(DownloadLocateTest, HostileGroupNamesNeverReachLocateResource)
{
    // Config now joins agent input into a path, so the grammar is the containment boundary for
    // both resource types. Anything traversable must be rejected during parsing.
    for (const auto* hostile : {"../../etc", "..", ".", "a/b"})
    {
        const auto body = std::string {R"({"resource_type":"config","resource_id":")"} + hostile + R"("})";
        ASSERT_TRUE(std::holds_alternative<RequestError>(parseRequest(body))) << "accepted hostile group: " << hostile;
    }
}

// ---------------------------------------------------------------------------
// FileByteSource
// ---------------------------------------------------------------------------

TEST(DownloadFileByteSourceTest, ReadsAFileSmallerThanOneChunkByteExactly)
{
    TempDir dir;
    const std::string contents = "merged config contents";
    const auto path = dir.writeFile("merged.mg", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());
    EXPECT_EQ((*source)->size(), contents.size());
    EXPECT_EQ(drain(**source, 64), contents);
}

TEST(DownloadFileByteSourceTest, ReassemblesAFileSpanningManyChunks)
{
    TempDir dir;
    // Deliberately not a multiple of the chunk size: the final short read is the case most likely
    // to be mishandled, and mistaking it for end-of-stream would silently truncate a transfer.
    std::string contents;
    contents.reserve(70000);
    for (std::size_t i = 0; i < 70000; ++i)
    {
        contents.push_back(static_cast<char>('A' + (i % 26)));
    }
    const auto path = dir.writeFile("large.wpk", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());
    EXPECT_EQ(drain(**source, 64U * 1024U), contents);
}

TEST(DownloadFileByteSourceTest, ReadsAFileThatIsAnExactMultipleOfTheChunkSize)
{
    TempDir dir;
    const std::string contents(4096, 'x');
    const auto path = dir.writeFile("aligned.bin", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());
    EXPECT_EQ(drain(**source, 1024), contents);
}

TEST(DownloadFileByteSourceTest, AnEmptyFileIsImmediatelyEndOfStream)
{
    TempDir dir;
    const auto path = dir.writeFile("empty.mg", "");

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());
    EXPECT_EQ((*source)->size(), 0U);
    EXPECT_EQ(drain(**source, 1024), "");
}

TEST(DownloadFileByteSourceTest, AZeroCapacityReadIsNotMistakenForEndOfStream)
{
    TempDir dir;
    const auto path = dir.writeFile("data.bin", "abc");

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());

    char buffer[4] {};
    EXPECT_EQ((*source)->read(buffer, 0), 0U);
    EXPECT_EQ(drain(**source, 16), "abc"); // nothing was consumed
}

// A merged.mg or a WPK can be rewritten IN PLACE while it is being served: c_group() with the
// default remoted.disk_storage=0 truncates merged.mg and rewrites it, and a WPK is fetched straight
// to its final path. The descriptor then follows the new contents, and the failure that matters is
// silent -- read() hits the new end-of-file, returns 0, and the transport emits the terminating
// chunk, so the agent accepts a spliced file as COMPLETE. Each case below must throw instead, which
// aborts the transfer without a terminator and makes the agent retry.

TEST(DownloadFileByteSourceTest, TruncationMidTransferAbortsRatherThanLookingComplete)
{
    TempDir dir;
    const std::string contents(8192, 'a');
    const auto path = dir.writeFile("merged.mg", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());

    // Consume part of the file, then truncate it the way an in-place rewrite would.
    std::vector<char> buffer(1024);
    ASSERT_EQ((*source)->read(buffer.data(), buffer.size()), 1024U);
    ASSERT_EQ(::truncate(path.c_str(), 2048), 0);

    // Drains the remaining 1 KiB, then hits the new EOF, which must NOT look like a clean end.
    EXPECT_THROW(
        {
            while ((*source)->read(buffer.data(), buffer.size()) > 0)
            {
            }
        },
        std::runtime_error);
}

TEST(DownloadFileByteSourceTest, AFileGrowingMidTransferAborts)
{
    TempDir dir;
    // A WPK still being staged grows in place; the bytes already sent belong to a version that no
    // longer exists, so continuing would splice two files together.
    const std::string contents(4096, 'w');
    const auto path = dir.writeFile("staging.wpk", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());

    std::vector<char> buffer(1024);
    ASSERT_EQ((*source)->read(buffer.data(), buffer.size()), 1024U);

    {
        std::ofstream appending {path, std::ios::binary | std::ios::app};
        appending << std::string(8192, 'W');
    }

    EXPECT_THROW(
        {
            while ((*source)->read(buffer.data(), buffer.size()) > 0)
            {
            }
        },
        std::runtime_error);
}

TEST(DownloadFileByteSourceTest, ARewriteKeepingTheSameLengthIsCaughtByMtime)
{
    TempDir dir;
    // The byte-count check cannot see this one: same length, different contents. Only the mtime
    // captured at open() distinguishes it.
    const std::string contents(4096, 'o');
    const auto path = dir.writeFile("merged.mg", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());

    std::vector<char> buffer(1024);
    ASSERT_EQ((*source)->read(buffer.data(), buffer.size()), 1024U);

    // Sleep so the rewrite lands in a distinguishable mtime even on a coarse-grained filesystem.
    std::this_thread::sleep_for(std::chrono::milliseconds {20});
    dir.writeFile("merged.mg", std::string(4096, 'n'));

    EXPECT_THROW(
        {
            while ((*source)->read(buffer.data(), buffer.size()) > 0)
            {
            }
        },
        std::runtime_error);
}

TEST(DownloadFileByteSourceTest, ModificationAbortsOnTheNextChunkNotAtEndOfStream)
{
    TempDir dir;
    // The point of checking per chunk: a writer landing early must not cost the whole file in
    // reads and socket writes before the transfer is abandoned. Asserting that the very NEXT read
    // throws is what distinguishes per-chunk detection from an end-of-stream-only check -- the
    // latter would happily return ~1 MiB more before noticing.
    const std::string contents(1024 * 1024, 'a');
    const auto path = dir.writeFile("big.wpk", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());

    std::vector<char> buffer(4096);
    ASSERT_EQ((*source)->read(buffer.data(), buffer.size()), 4096U);

    // Same length, so only the mtime baseline can see it. Sleep so the rewrite lands in a
    // distinguishable mtime even on a coarse-grained filesystem.
    std::this_thread::sleep_for(std::chrono::milliseconds {20});
    dir.writeFile("big.wpk", std::string(1024 * 1024, 'b'));

    EXPECT_THROW((*source)->read(buffer.data(), buffer.size()), std::runtime_error);
}

TEST(DownloadFileByteSourceTest, AnUntouchedFileStreamsToCompletion)
{
    TempDir dir;
    // The counterpart to the three above: the detection must not fire on a normal transfer, or
    // every download would abort.
    const std::string contents(8192, 'k');
    const auto path = dir.writeFile("quiet.mg", contents);

    auto source = openRegularFile(path);
    ASSERT_TRUE(source.has_value());
    EXPECT_NO_THROW({ EXPECT_EQ(drain(**source, 1024), contents); });
}

TEST(DownloadFileByteSourceTest, OpeningAMissingFileReportsEnoent)
{
    TempDir dir;
    errno = 0;
    EXPECT_FALSE(openRegularFile(dir.path() + "/does-not-exist.mg").has_value());
    EXPECT_EQ(errno, ENOENT);
}

TEST(DownloadFileByteSourceTest, ADirectoryIsRejectedAsNotARegularFile)
{
    // open(O_RDONLY) on a directory SUCCEEDS on Linux, so without the S_ISREG check this would be
    // a 200 that streams nothing rather than a 404.
    TempDir dir;
    errno = 0;
    EXPECT_FALSE(openRegularFile(dir.path()).has_value());
    EXPECT_EQ(errno, EINVAL);
}

TEST(DownloadFileByteSourceTest, ASymlinkIsRefusedByONofollow)
{
    TempDir dir;
    const auto target = dir.writeFile("real.wpk", "payload");
    const auto link = dir.track("link.wpk");
    ASSERT_EQ(::symlink(target.c_str(), link.c_str()), 0);

    errno = 0;
    EXPECT_FALSE(openRegularFile(link).has_value());
    EXPECT_EQ(errno, ELOOP);
}

TEST(DownloadFileByteSourceTest, AReadErrorThrowsRatherThanEndingTheStream)
{
    // A mid-transfer read failure must never look like a clean end-of-stream: that would emit the
    // terminating chunk and hand the agent a truncated file that appears complete. A write-only
    // descriptor is a valid, owned fd whose read() fails with EBADF.
    const int writeOnlyFd = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
    ASSERT_GE(writeOnlyFd, 0);

    FileByteSource unreadable {writeOnlyFd, 0};
    char buffer[16] {};
    EXPECT_THROW(unreadable.read(buffer, sizeof(buffer)), std::system_error);
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

TEST(DownloadHandlerTest, AnswersFourHundredForAMalformedBody)
{
    const auto responder = runHandler("not json");

    EXPECT_EQ(responder->status, 400);
    EXPECT_FALSE(responder->streamed);
}

TEST(DownloadHandlerTest, AnswersFourHundredAndFourWhenTheGroupHasNoMergedFile)
{
    TempDir dir;
    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    EXPECT_EQ(runHandler(VALID_CONFIG_BODY, paths)->status, 404);
}

TEST(DownloadHandlerTest, StreamsTheResolvedFileAsAnOctetStream)
{
    TempDir dir;
    dir.makeDir("shared/web-servers");
    const std::string contents = "#!/bin/sh\nmerged configuration\n";
    dir.writeFile("shared/web-servers/merged.mg", contents);

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    const auto responder = runHandler(VALID_CONFIG_BODY, paths);

    EXPECT_TRUE(responder->streamed);
    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, contents);
    ASSERT_EQ(responder->headers.size(), 1U);
    EXPECT_EQ(responder->headers.front().first, "Content-Type");
    EXPECT_EQ(responder->headers.front().second, "application/octet-stream");
}

// The remoted.download.* family: each admission outcome lands in its own counter, and a started
// stream records both the count and the bytes OFFERED (the file size, counted once at start --
// never per chunk). All asserted through one handler so the cells are proven independent.
TEST(DownloadHandlerTest, MetricsCountEachOutcomeAndOfferedBytes)
{
    TempDir dir;
    dir.makeDir("shared/web-servers");
    const std::string contents = "#!/bin/sh\nmerged configuration\n";
    dir.writeFile("shared/web-servers/merged.mg", contents);

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);
    auto handler = makeHandler(paths, metrics, sourceFor("web-servers"), grantingWpkAuthorizer());

    // Two handlers, ONE metric set: the counters are what this test proves independent, and since
    // authorization now runs before resolution, reaching the 404 path takes an agent entitled to a
    // group whose merged.mg is not on disk (the group exists in wazuh-db, the file is not built
    // yet) rather than one asking for a group that is not its own -- that is a 403 now.
    auto handlerForAMissingOwnGroup = makeHandler(paths, metrics, sourceFor("no-such-group"), grantingWpkAuthorizer());

    const auto runWith = [](auto& target, const std::string& bodyText)
    {
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(bodyText);
        target(authenticatedRequest(body), responder);
        return responder;
    };
    const auto run = [&](const std::string& bodyText)
    {
        return runWith(handler, bodyText);
    };

    EXPECT_EQ(run("not json")->status, 400);
    EXPECT_EQ(metrics.rejected->get(), 1U);

    EXPECT_EQ(
        runWith(handlerForAMissingOwnGroup, R"({"resource_type":"config","resource_id":"no-such-group"})")->status,
        404);
    EXPECT_EQ(metrics.notFound->get(), 1U);
    EXPECT_EQ(metrics.denied->get(), 0U); // an entitled request that 404s is not a denial

    const auto streamedResponder = run(VALID_CONFIG_BODY);
    EXPECT_TRUE(streamedResponder->streamed);
    EXPECT_EQ(metrics.started->get(), 1U);
    EXPECT_EQ(metrics.bytesTotal->get(), contents.size());
    EXPECT_EQ(metrics.openError->get(), 0U); // nothing above was an open failure
}

TEST(DownloadHandlerTest, StreamsTheEffectiveConfigForAMultigroupSelector)
{
    // End to end: a CSV selector must reach the var/multigroups file, not a member group's.
    TempDir dir;
    const std::string selector = "web-servers,databases";
    dir.makeDir("shared/web-servers");
    dir.writeFile("shared/web-servers/merged.mg", "SINGLE GROUP - must not be served");
    dir.makeDir("multigroups/" + multigroupDirName(selector));
    dir.writeFile("multigroups/" + multigroupDirName(selector) + "/merged.mg", "EFFECTIVE MULTIGROUP CONFIG");

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";
    paths.multigroupsDir = dir.path() + "/multigroups";

    const auto responder = runHandler(R"({"resource_type":"config","resource_id":"web-servers,databases"})", paths);

    EXPECT_EQ(responder->status, 200);
    EXPECT_TRUE(responder->streamed);
    EXPECT_EQ(responder->body, "EFFECTIVE MULTIGROUP CONFIG");
}

TEST(DownloadHandlerTest, StreamsTheGroupTheAgentNamed)
{
    TempDir dir;
    dir.makeDir("shared/web-servers");
    dir.makeDir("shared/databases");
    dir.writeFile("shared/web-servers/merged.mg", "WEB SERVERS CONFIG");
    dir.writeFile("shared/databases/merged.mg", "DATABASES CONFIG");

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    EXPECT_EQ(runHandler(VALID_CONFIG_BODY, paths)->body, "WEB SERVERS CONFIG");
    EXPECT_EQ(runHandler(R"({"resource_type":"config","resource_id":"databases"})", paths)->body, "DATABASES CONFIG");
}

TEST(DownloadHandlerTest, StreamsAStagedWpk)
{
    TempDir dir;
    dir.makeDir("upgrade");
    const std::string contents(200000, '\x7f'); // spans several chunks
    dir.writeFile("upgrade/pkg.wpk", contents);

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto responder = runHandler(R"({"resource_type":"wpk","resource_id":"pkg.wpk"})", paths);

    EXPECT_EQ(responder->status, 200);
    EXPECT_TRUE(responder->streamed);
    EXPECT_EQ(responder->body, contents);
}

TEST(DownloadHandlerTest, AnswersFourHundredAndFourWhenTheResolvedFileIsMissing)
{
    // Discovered before any byte is written, which is what makes a clean 404 possible at all.
    TempDir dir;
    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    const auto responder = runHandler(VALID_CONFIG_BODY, paths);

    EXPECT_EQ(responder->status, 404);
    EXPECT_FALSE(responder->streamed);
}

// ---------------------------------------------------------------------------
// Authorization (#38683): a config download is served only for the selector the requesting agent's
// own groups produce -- the same string /control handed it as config_token. Everything else is a
// 403 decided BEFORE any path is resolved.
// ---------------------------------------------------------------------------

TEST(DownloadHandlerTest, ServesTheAgentsOwnSelector)
{
    TempDir dir;
    dir.makeDir("shared/web-servers");
    dir.writeFile("shared/web-servers/merged.mg", "own group\n");

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    const auto responder =
        runHandlerAs(R"({"resource_type":"config","resource_id":"web-servers"})", "web-servers", paths);

    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, "own group\n");
}

TEST(DownloadHandlerTest, ServesTheAgentsOwnMultigroupSelector)
{
    // The multigroup directory is sha256(csv)[0:8] over the selector verbatim; the agent is
    // entitled to exactly the CSV /control gave it.
    TempDir dir;
    const std::string selector {"web-servers,databases"};
    dir.makeDir("multigroups/" + multigroupDirName(selector));
    dir.writeFile("multigroups/" + multigroupDirName(selector) + "/merged.mg", "effective config\n");

    ResourcePaths paths;
    paths.multigroupsDir = dir.path() + "/multigroups";

    const auto responder =
        runHandlerAs(R"({"resource_type":"config","resource_id":")" + selector + R"("})", selector, paths);

    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, "effective config\n");
}

TEST(DownloadHandlerTest, DeniesAnotherGroupsSelector)
{
    TempDir dir;
    dir.makeDir("shared/databases");
    dir.writeFile("shared/databases/merged.mg", "SECRET aws access key\n");

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    // The agent belongs to web-servers and asks for databases -- the defect this closes.
    const auto responder =
        runHandlerAs(R"({"resource_type":"config","resource_id":"databases"})", "web-servers", paths);

    EXPECT_EQ(responder->status, 403);
    EXPECT_EQ(responder->body, R"({"error":"Forbidden","code":403})");
    EXPECT_FALSE(responder->streamed);
}

TEST(DownloadHandlerTest, DeniesAReorderedMultigroupSelector)
{
    // Order is identity: "a,b" and "b,a" name different multigroup directories, and config_hash was
    // computed over one of them. A reordered CSV is somebody else's selector.
    const auto responder =
        runHandlerAs(R"({"resource_type":"config","resource_id":"databases,web-servers"})", "web-servers,databases");

    EXPECT_EQ(responder->status, 403);
}

TEST(DownloadHandlerTest, DeniesWhenTheAgentHasNoRegistryEntry)
{
    // Fail closed. An agent can reach /download without ever sending /control/startup, and that
    // ordering is entirely the caller's to choose -- so a miss must not fall through to serving
    // whatever the request named.
    const auto responder = runHandlerAs(R"({"resource_type":"config","resource_id":"web-servers"})", std::nullopt);

    EXPECT_EQ(responder->status, 403);
}

TEST(DownloadHandlerTest, DeniesWhenNoGroupSourceIsWired)
{
    // A miswired handler must deny, never serve: the failure mode of this check has to be closed.
    auto responder = std::make_shared<RecordingResponder>();
    auto body = std::make_shared<std::string>(VALID_CONFIG_BODY);
    makeHandler({}, {}, nullptr, grantingWpkAuthorizer())(authenticatedRequest(body), responder);

    EXPECT_EQ(responder->status, 403);
}

TEST(DownloadHandlerTest, DeniedRequestsAreIndistinguishableWhetherTheGroupExists)
{
    // The 200-vs-404 enumeration oracle: the answer must not depend on whether the group the agent
    // is not in happens to exist on disk. Both denials are decided before any path is resolved.
    TempDir dir;
    dir.makeDir("shared/databases");
    dir.writeFile("shared/databases/merged.mg", "SECRET\n");

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    const auto existing = runHandlerAs(R"({"resource_type":"config","resource_id":"databases"})", "web-servers", paths);
    const auto absent =
        runHandlerAs(R"({"resource_type":"config","resource_id":"no-such-group"})", "web-servers", paths);

    EXPECT_EQ(existing->status, absent->status);
    EXPECT_EQ(existing->body, absent->body);
    EXPECT_EQ(existing->status, 403);
}

TEST(DownloadHandlerTest, MetricsCountDenialsSeparatelyFromParseRejections)
{
    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);
    auto handler = makeHandler({}, metrics, sourceFor("web-servers"), grantingWpkAuthorizer());

    auto responder = std::make_shared<RecordingResponder>();
    auto body = std::make_shared<std::string>(R"({"resource_type":"config","resource_id":"databases"})");
    handler(authenticatedRequest(body), responder);

    ASSERT_EQ(responder->status, 403);
    EXPECT_EQ(metrics.denied->get(), 1U);
    EXPECT_EQ(metrics.rejected->get(), 0U);
    EXPECT_EQ(metrics.notFound->get(), 0U);
    EXPECT_EQ(metrics.openError->get(), 0U);
    EXPECT_EQ(metrics.started->get(), 0U);
}

// ---------------------------------------------------------------------------
// WPK authorization: a WPK is served only when the task manager reports an open upgrade task for
// this agent and this file. A denial is indistinguishable from a missing file; no answer is a 503
// and nothing is opened.
// ---------------------------------------------------------------------------

TEST(DownloadHandlerTest, WpkGrantedStreamsTheRequestedFile)
{
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/a.wpk", "PACKAGE A");
    dir.writeFile("upgrade/b.wpk", "PACKAGE B");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto authorizer = wpkAuthorizerAnswering(WpkAuthorization::Granted);
    const auto responder = runOn(makeHandler(paths, {}, sourceFor(std::nullopt), authorizer), wpkBody("b.wpk"));

    EXPECT_EQ(responder->status, 200);
    EXPECT_TRUE(responder->streamed);
    EXPECT_EQ(responder->body, "PACKAGE B");
    ASSERT_EQ(authorizer->calls.size(), 1U);
    EXPECT_EQ(authorizer->calls.front(), std::make_pair(std::string {"001"}, std::string {"b.wpk"}));
}

TEST(DownloadHandlerTest, WpkDeniedAnswersTheSameNotFoundAsAMissingFile)
{
    // The existence oracle: an agent without a task must not learn whether the file is staged.
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/pkg.wpk", "package\n");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);

    const auto denied =
        runOn(makeHandler(paths, metrics, sourceFor(std::nullopt), wpkAuthorizerAnswering(WpkAuthorization::Denied)),
              wpkBody("pkg.wpk"));
    EXPECT_EQ(metrics.denied->get(), 1U);
    EXPECT_EQ(metrics.notFound->get(), 0U);

    const auto missing =
        runOn(makeHandler(paths, metrics, sourceFor(std::nullopt), wpkAuthorizerAnswering(WpkAuthorization::Granted)),
              wpkBody("absent.wpk"));
    EXPECT_EQ(metrics.denied->get(), 1U);
    EXPECT_EQ(metrics.notFound->get(), 1U);

    EXPECT_EQ(denied->status, 404);
    EXPECT_FALSE(denied->streamed);
    EXPECT_FALSE(missing->streamed);
    EXPECT_EQ(denied->status, missing->status);
    EXPECT_EQ(denied->headers, missing->headers);
    EXPECT_EQ(denied->body, missing->body);
    EXPECT_EQ(metrics.started->get(), 0U);
}

TEST(DownloadHandlerTest, WpkUnavailableAnswersServiceUnavailableWithoutOpening)
{
    // The file is absent on purpose: opening it would show up as a 404 and a notFound count.
    TempDir dir;
    dir.makeDir("upgrade");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);

    const auto responder = runOn(
        makeHandler(paths, metrics, sourceFor(std::nullopt), wpkAuthorizerAnswering(WpkAuthorization::Unavailable)),
        wpkBody("pkg.wpk"));

    EXPECT_EQ(responder->status, 503);
    EXPECT_EQ(responder->body, R"({"error":"Service unavailable","code":503})");
    EXPECT_FALSE(responder->streamed);
    EXPECT_EQ(metrics.wpkAuthUnavailable->get(), 1U);
    EXPECT_EQ(metrics.started->get(), 0U);
    EXPECT_EQ(metrics.notFound->get(), 0U);
    EXPECT_EQ(metrics.openError->get(), 0U);
    EXPECT_EQ(metrics.denied->get(), 0U);
}

TEST(DownloadHandlerTest, WpkWithoutAnAuthorizerIsUnavailable)
{
    TempDir dir;
    dir.makeDir("upgrade");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);

    const auto responder = runOn(makeHandler(paths, metrics, sourceFor(std::nullopt), nullptr), wpkBody("pkg.wpk"));

    EXPECT_EQ(responder->status, 503);
    EXPECT_EQ(responder->body, R"({"error":"Service unavailable","code":503})");
    EXPECT_EQ(metrics.wpkAuthUnavailable->get(), 1U);
    EXPECT_EQ(metrics.notFound->get(), 0U);
    EXPECT_EQ(metrics.openError->get(), 0U);
}

TEST(DownloadHandlerTest, WpkGrantedFromAnotherThreadStillStreams)
{
    TempDir dir;
    dir.makeDir("upgrade");
    const std::string contents(200000, '\x7f');
    dir.writeFile("upgrade/pkg.wpk", contents);

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto authorizer =
        wpkAuthorizerAnswering(WpkAuthorization::Granted, FakeWpkAuthorizer::Mode::FromAnotherThread);
    const auto responder = runOn(makeHandler(paths, {}, sourceFor(std::nullopt), authorizer), wpkBody("pkg.wpk"));
    authorizer->join();

    EXPECT_EQ(responder->status, 200);
    EXPECT_TRUE(responder->streamed);
    EXPECT_EQ(responder->body, contents);
}

TEST(DownloadHandlerTest, WpkAServingFailureStillAnswers)
{
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/pkg.wpk", "package\n");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto handler =
        makeHandler(paths, {}, sourceFor(std::nullopt), wpkAuthorizerAnswering(WpkAuthorization::Granted));
    auto responder = std::make_shared<RecordingResponder>();
    responder->throwOnStream = true;
    handler(authenticatedRequest(std::make_shared<std::string>(wpkBody("pkg.wpk"))), responder);

    EXPECT_TRUE(responder->answered);
    EXPECT_EQ(responder->status, 500);
}

TEST(DownloadHandlerTest, WpkPayloadIsReleasedBeforeTheTaskManagerAnswers)
{
    // The wait for the task manager must not hold the request's in-flight byte reservation.
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/pkg.wpk", "package\n");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto authorizer = wpkAuthorizerAnswering(WpkAuthorization::Granted, FakeWpkAuthorizer::Mode::Hold);
    const auto handler = makeHandler(paths, {}, sourceFor(std::nullopt), authorizer);

    auto responder = std::make_shared<RecordingResponder>();
    auto body = std::make_shared<std::string>(wpkBody("pkg.wpk"));
    const std::weak_ptr<std::string> bodyAlive {body};
    auto request = authenticatedRequest(body);
    body.reset();
    // Checked when the task manager is asked, not after the handler returns: by then the request
    // is gone whether or not the handler released it.
    bool releasedWhenAsked {false};
    authorizer->onAuthorize = [&]
    {
        releasedWhenAsked = bodyAlive.expired();
    };
    handler(std::move(request), responder);

    ASSERT_TRUE(authorizer->held);
    EXPECT_TRUE(releasedWhenAsked);
    EXPECT_FALSE(responder->answered);

    const auto done = authorizer->held;
    done(WpkAuthorization::Granted);

    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, "package\n");
}

TEST(DownloadHandlerTest, WpkASecondAnswerIsIgnored)
{
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/pkg.wpk", "package\n");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);

    const auto responder =
        runOn(makeHandler(paths,
                          metrics,
                          sourceFor(std::nullopt),
                          wpkAuthorizerAnswering(WpkAuthorization::Denied, FakeWpkAuthorizer::Mode::Twice)),
              wpkBody("pkg.wpk"));

    EXPECT_EQ(responder->responses, 1);
    EXPECT_EQ(responder->status, 404);
    EXPECT_EQ(metrics.denied->get(), 1U);
}

TEST(DownloadHandlerTest, WpkGrammarRejectionsNeverReachTheAuthorizer)
{
    const auto authorizer = wpkAuthorizerAnswering(WpkAuthorization::Granted);
    const auto handler = makeHandler({}, {}, sourceFor(std::nullopt), authorizer);

    EXPECT_EQ(runOn(handler, wpkBody("../x.wpk"))->status, 400);
    EXPECT_EQ(runOn(handler, wpkBody("x.zip"))->status, 400);
    EXPECT_TRUE(authorizer->calls.empty());
}

TEST(DownloadHandlerTest, ConfigDownloadsNeverConsultTheWpkAuthorizer)
{
    TempDir dir;
    dir.makeDir("shared/web-servers");
    dir.writeFile("shared/web-servers/merged.mg", "own group\n");

    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";

    const auto authorizer = wpkAuthorizerAnswering(WpkAuthorization::Granted);
    const auto responder = runOn(makeHandler(paths, {}, sourceFor("web-servers"), authorizer), VALID_CONFIG_BODY);

    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, "own group\n");
    EXPECT_TRUE(authorizer->calls.empty());
}

TEST(DownloadHandlerTest, WpkRequestsAreAuthorizedByTheirTaskNotByGroups)
{
    // An agent with no known group membership still gets the WPK its upgrade task names.
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/pkg.wpk", "package\n");

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto responder =
        runOn(makeHandler(paths, {}, sourceFor(std::nullopt), wpkAuthorizerAnswering(WpkAuthorization::Granted)),
              wpkBody("pkg.wpk"));

    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, "package\n");
}

// -----------------------------------------------------------------------------
// The verdict may arrive later, from another thread (#39147): a config download whose registry
// entry is missing or expired waits on a wazuh-db lookup without holding the HTTP worker.
// -----------------------------------------------------------------------------

TEST(DownloadHandlerTest, ContinuesAfterADeferredVerdict)
{
    TempDir dir;
    dir.makeDir("shared/web-servers");
    dir.writeFile("shared/web-servers/merged.mg", "own group\n");
    ResourcePaths paths;
    paths.sharedDir = dir.path() + "/shared";
    const auto source = std::make_shared<ScriptedAgentGroupSource>();
    auto responder = std::make_shared<RecordingResponder>();
    auto body = std::make_shared<std::string>(R"({"resource_type":"config","resource_id":"web-servers"})");
    const auto request = authenticatedRequest(body);

    makeHandler(paths, {}, source, grantingWpkAuthorizer())(request, responder);

    // The handler returned without an answer, and the body was already released: the wait must not
    // hold the request's in-flight reservation.
    ASSERT_TRUE(source->pending());
    EXPECT_FALSE(responder->answered);
    EXPECT_TRUE(request->payload.bytes().empty());

    std::thread lookupWorker(
        [&]
        {
            source->deliver(
                remoted::endpoints::GroupVerdict {remoted::endpoints::GroupVerdictKind::Selector, "web-servers"});
        });
    lookupWorker.join();

    EXPECT_EQ(responder->status, 200);
    EXPECT_TRUE(responder->streamed);
    EXPECT_EQ(responder->body, "own group\n");
}

TEST(DownloadHandlerTest, AnswersServiceUnavailableWhenTheSourceIsUnavailable)
{
    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);
    const auto source = std::make_shared<ScriptedAgentGroupSource>();
    auto responder = std::make_shared<RecordingResponder>();
    auto body = std::make_shared<std::string>(R"({"resource_type":"config","resource_id":"default"})");

    makeHandler({}, metrics, source, grantingWpkAuthorizer())(authenticatedRequest(body), responder);
    source->deliver(remoted::endpoints::GroupVerdict {remoted::endpoints::GroupVerdictKind::Unavailable, {}});

    EXPECT_EQ(responder->status, 503);
    EXPECT_NE(responder->body.find("dependency_unavailable"), std::string::npos);
    EXPECT_NE(responder->body.find("wazuh-db"), std::string::npos);
    EXPECT_EQ(metrics.unavailable->get(), 1U);
    EXPECT_EQ(metrics.denied->get(), 0U); // a failed lookup is not a denial: the agent retries it
}

TEST(DownloadHandlerTest, AnswersServiceUnavailableForAnAgentWithNoLocalRow)
{
    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);
    auto answerFor = [&](remoted::endpoints::GroupVerdictKind kind)
    {
        const auto source = std::make_shared<ScriptedAgentGroupSource>();
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(R"({"resource_type":"config","resource_id":"default"})");
        makeHandler({}, metrics, source, grantingWpkAuthorizer())(authenticatedRequest(body), responder);
        source->deliver(remoted::endpoints::GroupVerdict {kind, {}});
        return responder;
    };

    const auto noRow = answerFor(remoted::endpoints::GroupVerdictKind::NoRow);
    EXPECT_EQ(noRow->status, 503); // retried like a failed lookup, never a denial
    EXPECT_EQ(metrics.noRow->get(), 1U);
    EXPECT_EQ(metrics.unavailable->get(), 0U); // counted apart from a failed lookup...
    EXPECT_EQ(metrics.denied->get(), 0U);

    const auto failed = answerFor(remoted::endpoints::GroupVerdictKind::Unavailable);
    EXPECT_EQ(noRow->body, failed->body); // ...but the same answer on the wire
    EXPECT_EQ(metrics.noRow->get(), 1U);
}

TEST(DownloadHandlerTest, AnswersServiceUnavailableForASupersededLookup)
{
    wazuh::metrics::Manager manager;
    const auto metrics = makeDownloadMetrics(manager);
    auto answerFor = [&](remoted::endpoints::GroupVerdictKind kind)
    {
        const auto source = std::make_shared<ScriptedAgentGroupSource>();
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(R"({"resource_type":"config","resource_id":"default"})");
        makeHandler({}, metrics, source, grantingWpkAuthorizer())(authenticatedRequest(body), responder);
        source->deliver(remoted::endpoints::GroupVerdict {kind, {}});
        return responder;
    };

    // A read that may predate a revocation never authorizes: retried like a failed lookup.
    const auto superseded = answerFor(remoted::endpoints::GroupVerdictKind::Superseded);
    EXPECT_EQ(superseded->status, 503);
    EXPECT_EQ(metrics.unavailable->get(), 1U); // a membership that could not be established now
    EXPECT_EQ(metrics.denied->get(), 0U);
    EXPECT_EQ(metrics.noRow->get(), 0U);

    const auto failed = answerFor(remoted::endpoints::GroupVerdictKind::Unavailable);
    EXPECT_EQ(superseded->body, failed->body); // the same answer on the wire
}

TEST(DownloadHandlerTest, WpkRequestsNeverResolve)
{
    TempDir dir;
    dir.makeDir("upgrade");
    dir.writeFile("upgrade/pkg.wpk", "package\n");
    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";
    const auto source = std::make_shared<FakeAgentGroupSource>(std::nullopt);
    auto responder = std::make_shared<RecordingResponder>();
    auto body = std::make_shared<std::string>(R"({"resource_type":"wpk","resource_id":"pkg.wpk"})");

    makeHandler(paths, {}, source, grantingWpkAuthorizer())(authenticatedRequest(body), responder);

    EXPECT_EQ(source->calls.load(), 0); // no group lookup, no wazuh-db round trip, for a WPK: its task decides
    EXPECT_EQ(responder->status, 200);
    EXPECT_EQ(responder->body, "package\n");
}
