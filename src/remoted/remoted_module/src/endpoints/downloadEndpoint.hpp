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

#ifndef _REMOTED_ENDPOINTS_DOWNLOAD_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_DOWNLOAD_ENDPOINT_HPP

#include "endpoint.hpp"                // AuthenticatedHandler
#include "http_server/IHttpServer.hpp" // HttpResponse, IByteSource

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
        std::string resourceId; ///< Group name (Config) or WPK filename (Wpk).
    };

    /// @brief Why a request body was rejected before anything was looked up.
    enum class RequestError
    {
        Malformed,           ///< Not JSON, not an object, missing/extra field, wrong type, or over the size cap.
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
     * files live. Defaults are the production post-chroot locations (remoted chroots to
     * /var/ossec): `SHAREDCFG_DIR`, `MULTIGROUPS_DIR` and `WM_UPGRADE_WPK_DEFAULT_PATH`.
     */
    struct ResourcePaths
    {
        std::string sharedDir {"/etc/shared"};
        std::string multigroupsDir {"/var/multigroups"};
        std::string wpkDir {"/var/upgrade"};
    };

    /**
     * @brief Upper bound on the request body accepted before parsing.
     *
     * A real `/download` body is about 80 bytes. Capping here -- well below the authenticated-body
     * limit -- means a pathologically large or deeply nested JSON blob is rejected outright instead
     * of costing CPU and heap proportional to its size. Same reasoning as `/stateless`'s H-line cap.
     */
    constexpr std::size_t kMaxRequestJsonSize {4U * 1024U};

    /**
     * @brief Parse and syntactically validate a `/download` request body.
     *
     * Pure: no filesystem, no lookup, no logging. Rejects (as Malformed) anything that is not a
     * JSON object carrying exactly `resource_type` and `resource_id`, both strings -- an unknown
     * extra member is a rejection, matching the schema's `additionalProperties: false`.
     *
     * @param body Verified request body bytes (a view into the transport buffer; not NUL-terminated).
     */
    std::variant<DownloadRequest, RequestError> parseRequest(std::string_view body);

    /**
     * @brief Whether @p group is a syntactically valid single group name.
     *
     * Mirrors wazuh's own grammar (`w_validate_group_name`): non-empty, at most MAX_GROUP_NAME
     * (255) bytes, drawn from `[A-Za-z0-9.:;_=+!@()-]`, excluding the comma (that separates entries
     * in a selector -- see isValidGroupSelector()).
     *
     * `.` and `..` are rejected explicitly, and that matters: a single group name IS joined into a
     * path (`<sharedDir>/<group>/merged.mg`), so this grammar is the containment boundary for
     * configs just as isValidWpkFilename() is for packages.
     */
    bool isValidGroupName(std::string_view group);

    /**
     * @brief Whether @p selector is a valid `resource_id` for a `config` request.
     *
     * Accepts either one group name, or several separated by commas -- wazuh's own multigroup form,
     * the same grammar `w_validate_group_name` accepts for a multigroup. Every entry must satisfy
     * isValidGroupName(), so an empty entry, a leading/trailing comma or a doubled comma is
     * rejected. Total length is capped at MAX_MULTIGROUP_SELECTOR_SIZE.
     *
     * Only the single-group form is ever joined into a path; a multi-entry selector is HASHED
     * (see multigroupDirName()), so the directory it names is hex by construction.
     */
    bool isValidGroupSelector(std::string_view selector);

    /**
     * @brief Whether @p filename is a syntactically valid WPK filename.
     *
     * Stricter than the group grammar, because this value IS joined into a path: non-empty, at most
     * 255 bytes, `[A-Za-z0-9._-]` only, must not begin with `.`, and must end in `.wpk`. The
     * character whitelist rules out `/`, `\`, NUL, encoded traversal and unicode lookalikes in one
     * rule, rather than by enumerating attacks.
     */
    bool isValidWpkFilename(std::string_view filename);

    /// @brief Client-visible `{"error","code"}` response for a rejected request body.
    remoted::http::HttpResponse errorResponseFor(RequestError error);

    /// @brief Client-visible `{"error","code"}` response for a resource that could not be located.
    remoted::http::HttpResponse errorResponseFor(LocateError error);

    /**
     * @brief Directory name a multigroup selector maps to under `var/multigroups`.
     *
     * Computed here, never looked up. wazuh-db is what NAMES that directory on disk, as
     * `OS_SHA256_String_sized(csv, out, WDB_GROUP_HASH_SIZE)` with WDB_GROUP_HASH_SIZE == 8 -- the
     * first 8 lowercase hex characters of the SHA-256, i.e. the first FOUR digest bytes.
     * Replicating that formula is exactly what keeps this endpoint free of any database access; if
     * the two ever diverge, every multi-group agent silently stops receiving configuration.
     *
     * @warning Order-sensitive, since the digest is over the selector verbatim: `"a,b"` and `"b,a"`
     * are different directories. An agent must send its groups in the order the manager reported.
     */
    std::string multigroupDirName(const std::string& groupSelector);

    /// @brief Outcome of resolving a request to a concrete file.
    struct LocateResult
    {
        std::string path; ///< Absolute path (post-chroot); empty unless error == None.
        LocateError error {LocateError::None};
    };

    /**
     * @brief Resolve a verified request to the file to serve.
     *
     * `resource_id` names what the agent is asking for and the manager serves exactly that:
     *   - Config, one group   -> `<sharedDir>/<resourceId>/merged.mg`
     *   - Config, several     -> `<multigroupsDir>/<sha256(resourceId)[0..8)>/merged.mg`
     *   - Wpk                 -> `<wpkDir>/<resourceId>`
     *
     * The multigroup form is what lets an agent in several groups fetch its EFFECTIVE configuration
     * rather than one member group's. The selector is hashed, never joined, so it needs no database
     * and cannot traverse.
     *
     * The single-group and WPK forms join agent-supplied input into a path, so containment rests on
     * the grammars in isValidGroupSelector()/isValidWpkFilename(): no `/`, no `.`/`..`, no leading
     * dot. That is what stops the agent-supplied component from naming anything outside the base
     * directory, and loosening either grammar to admit a separator would break it and require a
     * realpath() containment check instead.
     *
     * `O_NOFOLLOW` (openRegularFile()) covers only the FINAL component of the path, which differs
     * per form:
     *   - Wpk           -> `<wpkDir>/<resourceId>`, one agent-supplied component, and it is the one
     *                      opened, so O_NOFOLLOW applies to it directly.
     *   - Config        -> `<sharedDir>/<group>/merged.mg`. The component opened is `merged.mg`
     *                      (manager-owned); the agent-supplied `<group>` is an intermediate
     *                      DIRECTORY, which O_NOFOLLOW does not check. A symlinked group directory
     *                      would therefore be followed.
     *
     * That last case is not agent-exploitable -- planting it requires write access to the manager's
     * own etc/shared, at which point the configuration being served is already the attacker's --
     * so it is called out as a limit of the mechanism rather than treated as a hole. Adding a
     * realpath() containment check is what would close it if that assumption ever weakens.
     *
     * @note The manager does NOT check that the requesting agent belongs to what it asks for: per
     * the protocol decision on #38022, `resource_id` is what the agent requests and the group
     * lookup was removed. Any authenticated agent can therefore fetch any group's (or multigroup's)
     * merged configuration. `/control` must report `config_hash` over the file this resolves to for
     * the selector it hands the agent, or that agent re-downloads on every notify.
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
     */
    remoted::endpoints::AuthenticatedHandler makeHandler(ResourcePaths paths = {});

} // namespace remoted::endpoints::download

#endif // _REMOTED_ENDPOINTS_DOWNLOAD_ENDPOINT_HPP
