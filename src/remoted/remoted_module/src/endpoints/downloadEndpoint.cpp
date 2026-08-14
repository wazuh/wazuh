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

#include "downloadEndpoint.hpp"

#include "loggerHelper.h"

#include <rapidjson/document.h>

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace
{
    constexpr auto DOWNLOAD_LOGTAG {"wazuh-manager-remoted:endpoints"};

    const LogFn& logFn()
    {
        static const LogFn instance {LogFn {DOWNLOAD_LOGTAG}.compose("download")};
        return instance;
    }

    /// Longest accepted resource id. MAX_GROUP_NAME for a group; also a sane bound for a filename.
    constexpr std::size_t MAX_RESOURCE_ID_SIZE {255};

    /// Wire spellings of ResourceType.
    constexpr auto RESOURCE_TYPE_CONFIG {"config"};
    constexpr auto RESOURCE_TYPE_WPK {"wpk"};
    constexpr auto WPK_EXTENSION {".wpk"};

    /// Separator wazuh uses between groups in a multigroup selector (MULTIGROUP_SEPARATOR).
    constexpr char GROUP_SEPARATOR {','};

    /**
     * @brief Hex characters in a multigroup directory name.
     *
     * Must equal wazuh-db's WDB_GROUP_HASH_SIZE (8). Note that is 8 HEX CHARACTERS -- the first
     * four digest bytes -- not the first eight bytes.
     */
    constexpr std::size_t MULTIGROUP_HASH_HEX_CHARS {8};

    /// Cap on a whole multigroup selector, mirroring wazuh's own multigroup length allowance.
    constexpr std::size_t MAX_MULTIGROUP_SELECTOR_SIZE {4096};

    /// Basename of a merged centralized configuration (SHAREDCFG_FILENAME).
    constexpr auto MERGED_CONFIG_FILENAME {"merged.mg"};

    /// Characters wazuh accepts in a single group name (w_validate_group_name's set, minus comma).
    bool isGroupNameChar(char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == ':' ||
               c == ';' || c == '_' || c == '-' || c == '=' || c == '+' || c == '!' || c == '@' || c == '(' || c == ')';
    }

    /// Stricter set for a value that gets joined into a path.
    bool isWpkNameChar(char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
               c == '-';
    }

    bool isDotOrDotDot(std::string_view value)
    {
        return value == "." || value == "..";
    }

    bool endsWith(std::string_view value, std::string_view suffix)
    {
        return value.size() >= suffix.size() && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    std::string joinPath(const std::string& directory, const std::string& name)
    {
        if (directory.empty())
        {
            return name;
        }
        return directory.back() == '/' ? directory + name : directory + '/' + name;
    }

    /// Reads a required string member, rejecting a missing member or a non-string value.
    const rapidjson::Value* stringMember(const rapidjson::Document& doc, const char* name)
    {
        const auto member = doc.FindMember(name);
        if (member == doc.MemberEnd() || !member->value.IsString())
        {
            return nullptr;
        }
        return &member->value;
    }

    const char* resourceTypeName(remoted::endpoints::download::ResourceType type)
    {
        return type == remoted::endpoints::download::ResourceType::Config ? RESOURCE_TYPE_CONFIG : RESOURCE_TYPE_WPK;
    }

    /// errno -> the error a failed open maps to. Absent or wrong-typed is a plain 404; anything
    /// else is ours, not the agent's, so it surfaces as a 500 and gets logged.
    remoted::endpoints::download::LocateError errorForOpenErrno(int openErrno)
    {
        using remoted::endpoints::download::LocateError;
        switch (openErrno)
        {
            case ENOENT:
            case ENOTDIR:
            case ELOOP:  // O_NOFOLLOW rejected a symlink: indistinguishable from absent, to the agent.
            case EINVAL: // openRegularFile()'s marker for "not a regular file".
                return LocateError::NotFound;
            default: return LocateError::Internal;
        }
    }
} // namespace

namespace remoted::endpoints::download
{

    // -----------------------------------------------------------------------
    // Request parsing and grammars
    // -----------------------------------------------------------------------

    bool isValidGroupName(std::string_view group)
    {
        if (group.empty() || group.size() > MAX_RESOURCE_ID_SIZE || isDotOrDotDot(group))
        {
            return false;
        }

        for (const char c : group)
        {
            if (!isGroupNameChar(c))
            {
                return false;
            }
        }

        return true;
    }

    bool isValidGroupSelector(std::string_view selector)
    {
        if (selector.empty() || selector.size() > MAX_MULTIGROUP_SELECTOR_SIZE)
        {
            return false;
        }

        // Every entry must be a valid group name on its own. That rejects an empty entry, so a
        // leading comma, a trailing comma and a doubled comma are all rejected without needing
        // their own cases -- and it keeps "." / ".." out of a selector that will be joined.
        std::size_t start = 0;
        while (true)
        {
            const auto separator = selector.find(GROUP_SEPARATOR, start);
            const auto entry =
                selector.substr(start, separator == std::string_view::npos ? std::string_view::npos : separator - start);

            if (!isValidGroupName(entry))
            {
                return false;
            }

            if (separator == std::string_view::npos)
            {
                return true;
            }
            start = separator + 1;
        }
    }

    bool isValidWpkFilename(std::string_view filename)
    {
        if (filename.empty() || filename.size() > MAX_RESOURCE_ID_SIZE || filename.front() == '.' ||
            !endsWith(filename, WPK_EXTENSION))
        {
            return false;
        }

        for (const char c : filename)
        {
            if (!isWpkNameChar(c))
            {
                return false;
            }
        }

        return true;
    }

    std::variant<DownloadRequest, RequestError> parseRequest(std::string_view body)
    {
        if (body.empty() || body.size() > kMaxRequestJsonSize)
        {
            return RequestError::Malformed;
        }

        rapidjson::Document doc;
        // Length-based, non-in-situ parse: the body is a view into a shared buffer that is neither
        // mutable nor NUL-terminated. kParseIterativeFlag bounds the parser's C-stack usage to a
        // constant regardless of nesting depth, so a hostile body cannot overflow this thread's stack.
        doc.Parse<rapidjson::kParseIterativeFlag>(body.data(), body.size());

        if (doc.HasParseError() || !doc.IsObject())
        {
            return RequestError::Malformed;
        }

        // `additionalProperties: false`, so an unexpected member is a rejection rather than
        // something to skip: accepting it would let a future field be silently ignored by an older
        // manager, which only surfaces in production.
        if (doc.MemberCount() != 2)
        {
            return RequestError::Malformed;
        }

        const auto* typeValue = stringMember(doc, "resource_type");
        const auto* idValue = stringMember(doc, "resource_id");

        if (typeValue == nullptr || idValue == nullptr)
        {
            return RequestError::Malformed;
        }

        const std::string_view typeText {typeValue->GetString(), typeValue->GetStringLength()};
        const std::string_view idText {idValue->GetString(), idValue->GetStringLength()};

        DownloadRequest request;

        if (typeText == RESOURCE_TYPE_CONFIG)
        {
            request.type = ResourceType::Config;
            if (!isValidGroupSelector(idText))
            {
                return RequestError::InvalidResourceId;
            }
        }
        else if (typeText == RESOURCE_TYPE_WPK)
        {
            request.type = ResourceType::Wpk;
            if (!isValidWpkFilename(idText))
            {
                return RequestError::InvalidResourceId;
            }
        }
        else
        {
            return RequestError::UnknownResourceType;
        }

        request.resourceId.assign(idText);
        return request;
    }

    // -----------------------------------------------------------------------
    // Error mapping
    // -----------------------------------------------------------------------

    remoted::http::HttpResponse errorResponseFor(RequestError error)
    {
        switch (error)
        {
            case RequestError::UnknownResourceType:
                return remoted::http::HttpResponse::json(400, R"({"error":"Invalid resource type","code":400})");
            case RequestError::InvalidResourceId:
                return remoted::http::HttpResponse::json(400, R"({"error":"Invalid resource identifier","code":400})");
            case RequestError::Malformed: break;
        }

        return remoted::http::HttpResponse::json(400, R"({"error":"Invalid request format","code":400})");
    }

    remoted::http::HttpResponse errorResponseFor(LocateError error)
    {
        if (error == LocateError::Internal)
        {
            return remoted::http::HttpResponse::json(500, R"({"error":"Internal server error","code":500})");
        }

        return remoted::http::HttpResponse::json(404, R"({"error":"Resource not found","code":404})");
    }

    // -----------------------------------------------------------------------
    // Resolution
    // -----------------------------------------------------------------------

    std::string multigroupDirName(const std::string& groupSelector)
    {
        unsigned char digest[EVP_MAX_MD_SIZE] {};
        unsigned int digestLength {0};

        if (EVP_Digest(groupSelector.data(), groupSelector.size(), digest, &digestLength, EVP_sha256(), nullptr) != 1)
        {
            throw std::runtime_error("SHA-256 is unavailable; cannot resolve a multigroup directory");
        }

        static constexpr char HEX_DIGITS[] = "0123456789abcdef";

        std::string name;
        name.reserve(MULTIGROUP_HASH_HEX_CHARS);

        for (unsigned int i = 0; i < MULTIGROUP_HASH_HEX_CHARS / 2 && i < digestLength; ++i)
        {
            name.push_back(HEX_DIGITS[(digest[i] >> 4) & 0x0F]);
            name.push_back(HEX_DIGITS[digest[i] & 0x0F]);
        }

        return name;
    }

    LocateResult locateResource(const DownloadRequest& request, const ResourcePaths& paths)
    {
        // Safe to join directly: the grammars have already rejected any name containing a
        // separator, equal to "." or "..", or beginning with a dot, and openRegularFile()'s
        // O_NOFOLLOW stops the single remaining component being a symlink.
        if (request.type == ResourceType::Wpk)
        {
            return LocateResult {joinPath(paths.wpkDir, request.resourceId), LocateError::None};
        }

        // Several groups -> the effective (multigroup) configuration, whose directory is the hash
        // of the selector verbatim. Hashed rather than joined, so no database is needed and the
        // directory name is hex by construction.
        const bool isMultigroup = request.resourceId.find(GROUP_SEPARATOR) != std::string::npos;

        const std::string directory = isMultigroup
                                          ? joinPath(paths.multigroupsDir, multigroupDirName(request.resourceId))
                                          : joinPath(paths.sharedDir, request.resourceId);

        return LocateResult {joinPath(directory, MERGED_CONFIG_FILENAME), LocateError::None};
    }

    // -----------------------------------------------------------------------
    // File streaming
    // -----------------------------------------------------------------------

    FileByteSource::FileByteSource(int fd, std::uint64_t size) noexcept
        : m_fd {fd}
        , m_size {size}
    {
        // Baseline for the mid-transfer modification check in read(). Best-effort on purpose: a
        // descriptor we cannot stat is not a reason to refuse to serve a file we already opened
        // successfully. m_mtimeKnown is what makes that true -- without it, a failed fstat would
        // leave the baseline at zero, every comparison would mismatch, and EVERY transfer would
        // abort. The byte-count half of the check stands on its own either way.
        struct stat info
        {
        };
        if (::fstat(m_fd, &info) == 0)
        {
            m_mtimeSec = static_cast<std::int64_t>(info.st_mtim.tv_sec);
            m_mtimeNsec = static_cast<std::int64_t>(info.st_mtim.tv_nsec);
            m_mtimeKnown = true;
        }
    }

    FileByteSource::~FileByteSource()
    {
        if (m_fd >= 0)
        {
            // Deliberately unchecked: close() can report a deferred write error, but this
            // descriptor is read-only and there is nothing actionable to do from a destructor.
            ::close(m_fd);
            m_fd = -1;
        }
    }

    std::size_t FileByteSource::read(char* buffer, std::size_t capacity)
    {
        if (buffer == nullptr || capacity == 0 || m_fd < 0)
        {
            return 0;
        }

        // EINTR is not a failure: a signal landing mid-read must not truncate a transfer.
        // Everything else is, and it has to propagate -- returning 0 would look like a clean
        // end-of-stream, so the transport would emit the terminating chunk and the agent would
        // receive a silently truncated file that appears complete.
        ssize_t bytesRead = 0;
        do
        {
            bytesRead = ::read(m_fd, buffer, capacity);
        } while (bytesRead < 0 && errno == EINTR);

        if (bytesRead < 0)
        {
            throw std::system_error {errno, std::generic_category(), "read() failed while streaming a resource"};
        }

        if (bytesRead == 0)
        {
            // End of stream. The per-chunk check below has already covered everything up to the
            // last data read; this catches a writer that landed between that read and this one.
            if (m_delivered != m_size)
            {
                // Short by construction: end-of-file arrived before the file's own length.
                throw std::runtime_error {"the resource was truncated while it was being streamed"};
            }
            checkNotModified();
            return 0;
        }

        m_delivered += static_cast<std::uint64_t>(bytesRead);

        // More readable than the file held at open(): the bytes already sent belong to a version
        // that no longer exists. Cheap enough to keep as its own invariant -- it needs no syscall.
        if (m_delivered > m_size)
        {
            throw std::runtime_error {"the resource grew while it was being streamed"};
        }

        // Checked per chunk, not only at end-of-stream. Same criterion either way, but a writer
        // that lands one second into a 1 GiB transfer would otherwise cost the full gigabyte of
        // reads and socket writes before the transfer is abandoned; here it costs one more chunk.
        // The price is an fstat() per chunk -- no path resolution, no I/O, against a read() plus a
        // socket write that are already happening.
        checkNotModified();

        return static_cast<std::size_t>(bytesRead);
    }

    void FileByteSource::checkNotModified() const
    {
        struct stat info
        {
        };
        if (::fstat(m_fd, &info) != 0)
        {
            throw std::system_error {errno, std::generic_category(), "fstat() failed while streaming a resource"};
        }

        // Classified rather than lumped together, so the abort WARN names what actually happened:
        // a shorter file is a truncating rewrite (c_group() on merged.mg), a longer one is a file
        // still being staged (a WPK mid-download), and an unchanged length with a moved mtime is a
        // same-size rewrite -- the case no byte count can see.
        const auto currentSize = static_cast<std::uint64_t>(info.st_size);

        if (currentSize < m_size)
        {
            throw std::runtime_error {"the resource was truncated while it was being streamed"};
        }

        if (currentSize > m_size)
        {
            throw std::runtime_error {"the resource grew while it was being streamed"};
        }

        // Same length: only the baseline mtime distinguishes it, and only when we recorded one.
        // Without a baseline the check is skipped rather than assumed to have failed.
        if (m_mtimeKnown && (static_cast<std::int64_t>(info.st_mtim.tv_sec) != m_mtimeSec ||
                             static_cast<std::int64_t>(info.st_mtim.tv_nsec) != m_mtimeNsec))
        {
            throw std::runtime_error {"the resource was modified while it was being streamed"};
        }
    }

    std::uint64_t FileByteSource::size() const noexcept
    {
        return m_size;
    }

    std::optional<std::shared_ptr<FileByteSource>> openRegularFile(const std::string& path)
    {
        // O_NOFOLLOW: refuse a symlink as the final component. O_CLOEXEC: never leak the descriptor
        // into a child process (remoted forks for other work).
        int fd = -1;
        do
        {
            fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        } while (fd < 0 && errno == EINTR);

        if (fd < 0)
        {
            return std::nullopt; // errno is the caller's to map.
        }

        // fstat on the DESCRIPTOR, not stat on the path: the check then applies to the object we
        // actually opened and will stream, closing the window where the path could be swapped
        // between the check and the open.
        struct stat info
        {
        };
        if (::fstat(fd, &info) != 0)
        {
            const int savedErrno = errno;
            ::close(fd);
            errno = savedErrno;
            return std::nullopt;
        }

        if (!S_ISREG(info.st_mode))
        {
            ::close(fd);
            errno = EINVAL;
            return std::nullopt;
        }

        return std::make_shared<FileByteSource>(fd, static_cast<std::uint64_t>(info.st_size));
    }

    // -----------------------------------------------------------------------
    // Handler
    // -----------------------------------------------------------------------

    remoted::endpoints::AuthenticatedHandler makeHandler(ResourcePaths paths)
    {
        return [paths = std::move(paths)](
                   std::shared_ptr<const remoted::auth::AuthenticatedRequest> request,
                   std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            const auto parsed = parseRequest(request->payload.bytes());

            if (const auto* error = std::get_if<RequestError>(&parsed))
            {
                // Client fault, fully attacker-controlled in volume: debug only.
                LOGFN_DEBUG2(logFn(), "Rejected a /download request from agent '%s'.", request->agentId.c_str());
                responder->send(errorResponseFor(*error));
                return;
            }

            const auto& downloadRequest = std::get<DownloadRequest>(parsed);
            const std::string agentId = request->agentId;

            const auto located = locateResource(downloadRequest, paths);

            // The body has served its purpose. Releasing here -- rather than letting the request die
            // with the handler -- returns its in-flight byte reservation before a transfer that may
            // run for minutes begins.
            request->payload.release();
            request.reset();

            // Opened BEFORE the response starts: once a 200 and a chunk are on the wire the status
            // can no longer be corrected, so a missing file has to be discovered here to be a clean
            // 404 rather than a truncated 200.
            errno = 0;
            auto source = openRegularFile(located.path);

            if (!source)
            {
                const int openErrno = errno;
                const auto mapped = errorForOpenErrno(openErrno);

                if (mapped == LocateError::Internal)
                {
                    LOGFN_ERROR(logFn(),
                                "Could not open '%s' to serve a /download request from agent '%s': %s.",
                                located.path.c_str(),
                                agentId.c_str(),
                                std::strerror(openErrno));
                }
                else
                {
                    LOGFN_DEBUG2(logFn(),
                                 "Resource '%s' is unavailable for agent '%s': %s.",
                                 located.path.c_str(),
                                 agentId.c_str(),
                                 std::strerror(openErrno));
                }

                responder->send(errorResponseFor(mapped));
                return;
            }

            LOGFN_DEBUG1(logFn(),
                         "Serving '%s' (%llu byte(s)) to agent '%s' for a '%s' download.",
                         located.path.c_str(),
                         static_cast<unsigned long long>((*source)->size()),
                         agentId.c_str(),
                         resourceTypeName(downloadRequest.type));

            remoted::http::StreamResponse response;
            response.status = 200;
            response.headers.emplace_back("Content-Type", "application/octet-stream");
            response.source = std::move(*source);

            responder->stream(std::move(response));
        };
    }

} // namespace remoted::endpoints::download
