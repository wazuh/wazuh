/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_DOWNLOAD_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_DOWNLOAD_ENDPOINT_HPP

#include "common/installPaths.hpp"     // remoted::paths
#include "downloadMetrics.hpp"         // DownloadMetrics
#include "endpoint.hpp"                // AuthenticatedHandler
#include "http_server/IHttpServer.hpp" // HttpResponse, IByteSource
#include "iAgentGroupSource.hpp"       // IAgentGroupSource

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace remoted::endpoints::download
{

    /**
     * @brief The kinds of resource `POST /download` can serve.
     *
     * Closed set, mirroring the wire enum (#37733 5.4). An unrecognized value is a 400, never a
     * fallback.
     */
    enum class ResourceType
    {
        Config, ///< The agent's merged centralized configuration (`merged.mg`).
        Wpk     ///< A WPK upgrade package staged on the manager.
    };

    /// @brief A parsed, syntactically-valid `/download` request body.
    struct DownloadRequest
    {
        ResourceType type {ResourceType::Config};
        /// Group selector (Config) or WPK filename (Wpk). Empty only for a Config request that did
        /// not send one: the selector is then derived from the authenticated agent's own groups.
        std::optional<std::string> resourceId;
    };

    /// @brief Why a request body was rejected before anything was looked up.
    enum class RequestError
    {
        Malformed, ///< Not JSON, not an object, an unexpected set of members, wrong type, or over the size cap.
        UnknownResourceType, ///< Well-formed, but `resource_type` is not `config` or `wpk`.
        InvalidResourceId    ///< Well-formed, but `resource_id` fails the grammar for its type.
    };

    /**
     * @brief Why a resource could not be handed to the agent.
     */
    enum class LocateError
    {
        None = 0,
        NotFound, ///< -> 404. Absent, or present but not a regular file.
        Internal  ///< -> 500. An unexpected errno while opening or stat-ing.
    };

    /**
     * @brief Base directories a resource may be served from.
     *
     * A plain value rather than an interface: the only thing a test needs to vary is where the
     * files live. Defaults are the production locations (remoted::paths), relative to the installation
     * directory that is remoted's cwd: `SHAREDCFG_DIR`, `MULTIGROUPS_DIR` and `LEGACY_TASK_WPK_DEFAULT_PATH`.
     */
    struct ResourcePaths
    {
        std::string sharedDir {paths::kSharedDir};
        std::string multigroupsDir {paths::kMultigroupsDir};
        std::string wpkDir {paths::kWpkDir};
    };

    /**
     * @brief Upper bound on the request body accepted before parsing.
     *
     * A real `/download` body is under 100 bytes. Capping here -- well below the authenticated-body
     * limit -- means a pathologically large or deeply nested JSON blob is rejected outright instead
     * of costing CPU and heap proportional to its size. Same reasoning as `/stateless`'s H-line cap.
     */
    constexpr std::size_t kMaxRequestJsonSize {4U * 1024U};

    /**
     * @brief Parse and syntactically validate a `/download` request body.
     *
     * Pure: no filesystem, no lookup, no logging. Rejects (as Malformed) anything that is not a
     * JSON object. `resource_type` is always required. A `config` request carries either that
     * member alone or `resource_id` as well (in either order); a `wpk` request needs both. Any
     * other member, or a `resource_id` that is not a string, is a rejection, matching the schema's
     * `additionalProperties: false`.
     *
     * @param body Verified request body bytes (a view into the transport buffer; not NUL-terminated).
     */
    std::variant<DownloadRequest, RequestError> parseRequest(std::string_view body);

    /**
     * @brief Whether @p selector is a valid `resource_id` for a `config` request.
     *
     * Accepts either one group name, or several separated by commas -- wazuh's own multigroup form.
     * Every entry must satisfy remoted::control::isValidGroupName(), the grammar /control resolves
     * with, so an empty entry, a leading/trailing comma or a doubled comma is rejected. Total length
     * is capped at MAX_MULTIGROUP_SELECTOR_SIZE. This only validates what the request claims: the
     * served path is built from the agent's derived selector, whose names
     * remoted::control::resolveMergedConfigPath() validates again.
     *
     * A `resource_id` never reaches a path: it is only compared with the derived selector. The path
     * is built by remoted::control::resolveMergedConfigPath() from the derived groups, a single
     * group joined under the shared directory and several HASHED, so the directory they name is hex
     * by construction.
     */
    bool isValidGroupSelector(std::string_view selector);

    /**
     * @brief Whether @p filename is a syntactically valid WPK filename.
     *
     * Unlike a group name, this value IS joined into a path, so it is also held to a suffix and a
     * leading-dot rule: non-empty, at most 255 bytes, `[A-Za-z0-9._-]` only, must not begin with
     * `.`, and must end in `.wpk`. The character whitelist rules out `/`, `\`, NUL, encoded
     * traversal and unicode lookalikes in one rule, rather than by enumerating attacks.
     */
    bool isValidWpkFilename(std::string_view filename);

    /// @brief Client-visible `{"error","code"}` response for a rejected request body.
    remoted::http::HttpResponse errorResponseFor(RequestError error);

    /// @brief Client-visible `{"error","code"}` response for a resource that could not be located.
    remoted::http::HttpResponse errorResponseFor(LocateError error);

    /// @brief Outcome of resolving a request to a concrete file.
    struct LocateResult
    {
        std::string path; ///< Under one of the ResourcePaths directories; empty unless error == None.
        LocateError error {LocateError::None};
    };

    /**
     * @brief Resolve a verified WPK request to the file to serve: `<wpkDir>/<resourceId>`.
     *
     * A `config` request is not resolved here: its path depends on the agent's groups, so the
     * handler derives it with remoted::control::resolveMergedConfigPath() once the agent is
     * authorized, and this function answers NotFound for one. An empty `resourceId` is NotFound too.
     *
     * The WPK form joins agent-supplied input into a path, so containment rests on the grammar in
     * isValidWpkFilename(): no `/`, no `.`/`..`, no leading dot. Loosening it to admit a separator
     * would break that and require a realpath() containment check instead. `O_NOFOLLOW`
     * (openRegularFile()) covers the final component, which here is the agent-supplied one.
     *
     * Deliberately identity-free: it maps a resource id to a path and nothing else. WPK requests
     * are not authorized against groups (their authority is the agent's pending upgrade task).
     */
    LocateResult locateResource(const DownloadRequest& request, const ResourcePaths& paths);

    /**
     * @brief An IByteSource backed by an open file descriptor.
     *
     * Holds the descriptor for the whole transfer rather than reopening per chunk. When a writer
     * replaces the file by rename (`c_group()` with `remoted.disk_storage=1` writes `merged.mg.tmp`
     * and renames it into place), the open descriptor keeps serving the consistent old inode and
     * nothing further is needed.
     *
     * That is NOT the only way these files are written, which is why this class also detects
     * in-place modification:
     *   - `c_group()` in its DEFAULT configuration (`remoted.disk_storage=0`) builds the merged
     *     configuration in memory and then does `fopen(merged.mg, "w")` + `fwrite` -- truncating
     *     and rewriting the same inode.
     *   - A WPK is fetched straight to its final path (`wurl_request()` into `var/upgrade/`), so it
     *     grows in place while it is being staged.
     *
     * Either way the descriptor follows the file's new contents, and the danger is specific: the
     * next read() would hit the new end-of-file and return 0, the transport would emit the
     * terminating chunk, and the agent would accept a truncated or spliced file as COMPLETE. Being
     * cut off is recoverable -- the agent retries; being handed corrupt bytes that look whole is
     * not. See read() for how that is turned back into an abort.
     *
     * Not thread-safe by itself, and does not need to be: the transport never calls read()
     * concurrently with itself for a given response.
     */
    class FileByteSource final : public remoted::http::IByteSource
    {
    public:
        /**
         * @brief Take ownership of an already-open descriptor.
         *
         * Public so a test can build one over a pipe or a write-only fd without going through the
         * filesystem; openRegularFile() is the intended production entry point.
         */
        FileByteSource(int fd, std::uint64_t size) noexcept;

        /// Closes the descriptor.
        ~FileByteSource() override;

        FileByteSource(const FileByteSource&) = delete;
        FileByteSource& operator=(const FileByteSource&) = delete;

        /**
         * @brief Read the next slice.
         *
         * Retries on EINTR. A short read is NOT end-of-stream (it happens naturally on some
         * filesystems); only a 0-byte read is.
         *
         * After EVERY chunk -- not only at end-of-stream -- re-`fstat`s the descriptor and compares
         * size and mtime against what they were at open(). Any mismatch means the file was
         * rewritten mid-transfer, so what has been streamed is a mix of two versions:
         *   - shorter -> a truncating rewrite (c_group() on merged.mg)
         *   - longer  -> still being staged (a WPK mid-download)
         *   - same length, mtime moved -> a same-size rewrite, which no byte count can see
         *
         * Checking per chunk rather than once at the end is what bounds the waste: a writer landing
         * one second into a 1 GiB transfer would otherwise cost the whole gigabyte of reads and
         * socket writes before the transfer is abandoned. The end-of-stream check remains, covering
         * a writer that lands between the final data read and the zero-byte read.
         *
         * @throws std::system_error on an unrecoverable read error, and std::runtime_error when the
         *         file changed underneath the transfer. Both abort it. Returning 0 instead would
         *         emit the terminating chunk and hand the agent a corrupt file that looks complete;
         *         aborting makes the agent retry, which is the recoverable outcome.
         *
         * @note This detects the modification, it does not prevent it: a writer that rewrites the
         *       file with an identical length inside the same mtime granularity would still slip
         *       through, and nothing here can know a writer holds the file open before it acts.
         *       Closing that needs the writers to publish atomically by rename (as
         *       `disk_storage=1` already does) rather than any check here.
         */
        std::size_t read(char* buffer, std::size_t capacity) override;

        /// @return Size reported by fstat() when the file was opened, for logging.
        std::uint64_t size() const noexcept;

    private:
        /**
         * @brief Compare the descriptor's current size/mtime against the baseline from open().
         *
         * Called after every chunk and again at end-of-stream.
         *
         * @throws std::runtime_error naming which way it changed (truncated / grew / modified), so
         *         the abort WARN says what actually happened rather than just "it changed".
         */
        void checkNotModified() const;

        int m_fd {-1};
        std::uint64_t m_size {0};
        std::uint64_t m_delivered {0}; ///< Bytes handed to the transport so far.
        // mtime at open, kept as plain integers so this header needs no <sys/stat.h>.
        std::int64_t m_mtimeSec {0};
        std::int64_t m_mtimeNsec {0};
        bool m_mtimeKnown {false}; ///< False if the baseline fstat failed; the mtime check is then skipped.
    };

    /**
     * @brief Open @p path for streaming, requiring it to be a regular file.
     *
     * Opens with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` and fstat()s the resulting DESCRIPTOR, so the
     * type check applies to the object actually opened rather than to whatever the path resolved to
     * a moment earlier. Called before any byte of the response is written -- that ordering is what
     * lets a missing file be a clean 404 instead of a truncated 200.
     *
     * @return The source, or nullopt with `errno` left set for the caller to map to a status. A
     *         non-regular file yields nullopt with errno set to EINVAL.
     */
    std::optional<std::shared_ptr<FileByteSource>> openRegularFile(const std::string& path);

    /**
     * @brief Build the complete `POST /download` handler.
     *
     * Parses, releases the payload (a transfer outlives the request by a long way; no reason to
     * hold the body's in-flight reservation for it), resolves, opens, then streams.
     *
     * @warning The route MUST be registered with remoted::http::ResponseMode::Streamable. A
     * Buffered registration reaches IHttpResponder::stream()'s fail-loud default and every download
     * answers 500.
     *
     * @param metrics The remoted.download.* set (copied into the handler, cold path): admission
     * outcomes plus started-transfer count/bytes, all recorded before the streaming pump runs.
     * The default null object counts nothing.
     *
     * @param groups Resolves the selector the calling agent is entitled to. Required, with no
     * default: a config download is authorized against it, so silently defaulting it would mean
     * "serve anything to anyone". A null pointer, and an agent the source does not know, are both
     * DENIED (403). The file served is the one that selector names; a `resource_id` in the request
     * is optional and, when present, must equal that selector or the request is refused (403).
     *
     * The config path joins each validated group name (no separator, not `.` or `..`) into
     * `<sharedDir>/<group>/merged.mg`. `O_NOFOLLOW` covers only the final component, `merged.mg`, so
     * a symlinked group directory would be followed; planting one needs write access to the
     * manager's own shared directory, at which point the configuration served is already the
     * attacker's. A realpath() containment check would close it if that assumption weakens.
     */
    remoted::endpoints::AuthenticatedHandler
    makeHandler(ResourcePaths paths, DownloadMetrics metrics, std::shared_ptr<const IAgentGroupSource> groups);

} // namespace remoted::endpoints::download

#endif // _REMOTED_ENDPOINTS_DOWNLOAD_ENDPOINT_HPP
