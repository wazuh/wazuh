/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/downloadEndpoint.hpp"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <variant>
#include <vector>

using namespace remoted::endpoints::download;

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
                const auto part = relative.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
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
            if (answered)
            {
                return;
            }
            answered = true;
            status = response.status;
            body = std::move(response.body);
        }

        void stream(remoted::http::StreamResponse response) override
        {
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

    std::shared_ptr<RecordingResponder> runHandler(const std::string& bodyText, ResourcePaths paths = {})
    {
        auto responder = std::make_shared<RecordingResponder>();
        auto body = std::make_shared<std::string>(bodyText);
        makeHandler(std::move(paths))(authenticatedRequest(body), responder);
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
        R"({"resource_type":"config"})",                              // missing resource_id
        R"({"resource_id":"web-servers"})",                           // missing resource_type
        R"({"resource_type":"config","resource_id":"a","extra":1})",  // additionalProperties: false
        R"({"resource_type":1,"resource_id":"a"})",                   // wrong type
        R"({"resource_type":"config","resource_id":123})",            // wrong type
        R"({"resource_type":"config","resource_id":null})",           // wrong type
        R"({"resource_type":"config","resource_id":"a",)",            // truncated
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
    EXPECT_FALSE(isValidGroupSelector(",web-servers"));   // leading
    EXPECT_FALSE(isValidGroupSelector("web-servers,"));   // trailing
    EXPECT_FALSE(isValidGroupSelector("web,,servers"));   // doubled
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
    // resource_id names the group the agent asks for and the manager serves exactly that -- no
    // group lookup, no membership check (protocol decision on #38022).
    const auto result = locateResource(configRequest("web-servers"), {});

    EXPECT_EQ(result.error, LocateError::None);
    EXPECT_EQ(result.path, "/etc/shared/web-servers/merged.mg");
}

TEST(DownloadLocateTest, AnyRequestedGroupResolvesRegardlessOfTheAgent)
{
    // Documents the consequence of dropping the lookup: this layer cannot tell whose group it is,
    // so it serves whichever the caller names.
    for (const auto* group : {"web-servers", "databases", "default", "some-other-team"})
    {
        const auto result = locateResource(configRequest(group), {});
        EXPECT_EQ(result.error, LocateError::None);
        EXPECT_EQ(result.path, std::string {"/etc/shared/"} + group + "/merged.mg");
    }
}

TEST(DownloadMultigroupDirNameTest, MatchesWhatWazuhDbComputesForTheSameSelector)
{
    // wazuh-db builds the directory with OS_SHA256_String_sized(csv, out, WDB_GROUP_HASH_SIZE),
    // WDB_GROUP_HASH_SIZE == 8, i.e. the first FOUR digest bytes as eight lowercase hex characters.
    // Pinned literals, confirmed against a live manager which created var/multigroups/97d66859 for
    // "web-servers,databases" and /76ba5a3b for "alpha,beta".
    EXPECT_EQ(multigroupDirName("web-servers,databases"), "97d66859");
    EXPECT_EQ(multigroupDirName("alpha,beta"), "76ba5a3b");
    EXPECT_EQ(multigroupDirName("default,web-servers"), "b9d4f263");
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
    EXPECT_EQ(result.path, "/var/multigroups/97d66859/merged.mg");
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
    EXPECT_EQ(result.path, "/var/upgrade/wazuh_agent_v5.0.1_linux_x86_64.wpk");
}

TEST(DownloadLocateTest, HostileGroupNamesNeverReachLocateResource)
{
    // Config now joins agent input into a path, so the grammar is the containment boundary for
    // both resource types. Anything traversable must be rejected during parsing.
    for (const auto* hostile : {"../../etc", "..", ".", "a/b"})
    {
        const auto body = std::string {R"({"resource_type":"config","resource_id":")"} + hostile + R"("})";
        ASSERT_TRUE(std::holds_alternative<RequestError>(parseRequest(body)))
            << "accepted hostile group: " << hostile;
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

    const auto responder =
        runHandler(R"({"resource_type":"config","resource_id":"web-servers,databases"})", paths);

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
    EXPECT_EQ(runHandler(R"({"resource_type":"config","resource_id":"databases"})", paths)->body,
              "DATABASES CONFIG");
}

TEST(DownloadHandlerTest, StreamsAStagedWpk)
{
    TempDir dir;
    dir.makeDir("upgrade");
    const std::string contents(200000, '\x7f'); // spans several chunks
    dir.writeFile("upgrade/pkg.wpk", contents);

    ResourcePaths paths;
    paths.wpkDir = dir.path() + "/upgrade";

    const auto responder =
        runHandler(R"({"resource_type":"wpk","resource_id":"pkg.wpk"})", paths);

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
