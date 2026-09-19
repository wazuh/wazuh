/*
 * Wazuh manager certs tool - commands
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MANAGER_CERTS_COMMANDS_HPP
#define _MANAGER_CERTS_COMMANDS_HPP

/**
 * @file commands.hpp
 * @brief The commands of `wazuh-manager-certs` (issue #39319): `inspect`/`check`, which only read,
 *        and the write transaction `add` (and, from a later stage, `remove`/`prune-expired`/
 *        `stamp`) publishes the bundle through.
 *
 * The read-only pair are pure functions over an already-parsed bundle and the leaf certificate
 * `main.cpp` read from disk: no file reads, no configuration, no writes. That split is what lets
 * the unit tests exercise both commands in process, over throwaway PKI, without a compiled binary
 * or a filesystem fixture for every case -- `main.cpp` is the only piece that opens a file for
 * them, and it does that once per run, before either of these runs (`02-diseno.md` §2.6, C27).
 *
 * Writing cannot be a pure function -- it is a transaction over a file every agent in the fleet
 * trusts -- so it is split in three instead, and the same split keeps it testable:
 *
 *   prepareWrite()  takes the exclusive lock, opens the bundle ONCE and keeps that descriptor, and
 *                   hands back everything the transaction needs (WriteContext);
 *   the command     (`add`) builds the candidate list and refuses its own inputs;
 *   finishWrite()   runs the guards every writing command shares, in one order, and publishes
 *                   through atomicWrite().
 *
 * Every syscall and every clock reading on that path comes through the seams below (IoPort, LockIo,
 * TimeSource), because the failures that matter here -- ENOSPC halfway through, a refused rename, a
 * clock that does not advance, a CA that expires while we wait for the next second -- cannot be
 * produced by a test any other way (C36).
 */

#include <ca_bundle/ca_bundle.hpp>

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace manager_certs
{
    /**
     * @brief Prints @p bundle's certificates and publication status to @p out, human-readable.
     *
     * One row per certificate: subject, issuer, `notAfter`, days remaining (may be negative, for an
     * already-expired certificate), identity (`ca_bundle::identityOf()`) and whether it signs
     * @p leaf. Then the bundle's own line: its publication block's `publication` field verbatim
     * when the bundle carries one (whatever it claims, even if some other guard would refuse it),
     * or `0 (unpublished)` when it carries none (a plain PEM, or one whose block did not parse) --
     * and, separately, `vouched: yes`/`vouched: no` from `ca_bundle::vouch()` against @p leaf and
     * @p bundle's own serialised size, which is the same verdict `check` reports.
     *
     * Never fails: an empty or unparsed bundle prints as zero certificates and `vouched: no`. The
     * return value is always 0, kept as `int` (rather than `void`) so `main.cpp` can dispatch every
     * command through one function-pointer shape (`runCheck()` is the one that can return 1).
     *
     * @p leaf may be null (leaf unreadable) -- `signsLeaf` reads false for every certificate then,
     * same as `ca_bundle::describe()`/`anyCaSignsLeaf()` with a null leaf.
     */
    int runInspect(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::ostream& out);

    /**
     * @brief Whether @p bundle may be vouched for as @p leaf's trust anchor, without writing
     *        anything (RF-12).
     *
     * Two guard groups, evaluated in order, stopping at the first failure of either:
     *
     * 1. `ca_bundle::vouch(bundle, leaf, serializedBytes)`'s own six guards (structure, the
     *    publication hash, leaf-signing, the two size caps). On failure, writes one line to @p err
     *    naming that guard -- `too_many_certificates` and `too_many_bytes` name the observed
     *    count/bytes against the limit (e.g. "7 certificates (max 6)", "8588 bytes (max 8191)"),
     *    the others name the failure in words (e.g. "no CA signs the served leaf").
     * 2. Only once (1) passes: every certificate of @p bundle, in order, must be a CA (`isCa`) and
     *    inside its validity window (`notBefore <= now <= notAfter`) -- properties
     *    `ca_bundle::vouch()` does not evaluate on its own (02-diseno.md §2.6). On the first
     *    certificate that fails either, writes one line to @p err naming it by
     *    `ca_bundle::identityOf()` and the concrete reason: "not a CA", "not yet valid (notBefore
     *    ...)" or "expired (notAfter ...)".
     *
     * Returns 0 and writes nothing only when every guard of both groups passes.
     *
     * @p serializedBytes is what the caller would actually hand out for @p bundle (i.e.
     * `ca_bundle::serializeCertificates(bundle.certificates).size()`), the same quantity
     * `too_many_bytes` is evaluated against.
     *
     * Never returns 2: an unreadable configuration, a missing bundle or a missing leaf are
     * environment problems `main.cpp` catches before either command runs.
     */
    int
    runCheck(const ca_bundle::ParsedBundle& bundle, const X509* leaf, std::size_t serializedBytes, std::ostream& err);

    // ----------------------------------------------------------------- the write transaction ---

    /// Held by WriteContext; defined in src/commands/writeLock.hpp, which the commands' own
    /// translation units include. Declared here only so the context can own one.
    class BundleWriteLock;

    /// `flock(2)` as a seam, so a test can produce an EINTR, a refusal, or a lock file that is
    /// replaced while a second writer is blocked on it. Empty means the real call.
    struct LockIo
    {
        std::function<int(int fd, int operation)> flock {};
    };

    /**
     * @brief The syscalls atomicWrite() makes, injectable. Every empty field means "call the real
     *        one", so production passes a default-constructed IoPort and nothing branches.
     *
     * Same shape and the same reason as remoted's RecordIo
     * (src/remoted/remoted_module/src/http_server/caPublicationRecord.hpp): these tests run as root,
     * where the permissions that would produce ENOSPC, a short write or a refused fsync cannot be
     * set up, and every one of those paths has to leave the bundle byte-for-byte intact.
     *
     * `close` is only ever called for the temporary's own checked close (step 9 of
     * `anexos/e7/escritura-atomica.md`); every other descriptor is closed with the real call, so a
     * test counting calls sees exactly the one the failure matrix names.
     */
    struct IoPort
    {
        std::function<int(int directoryFd, const char* name, int flags, mode_t mode)> openat {};
        std::function<ssize_t(int fd, const void* data, std::size_t bytes)> write {};
        std::function<int(int fd, bool directory)> fsync {}; ///< @p directory tells step 11 from steps 5/7.
        std::function<int(int fd, uid_t owner, gid_t group)> fchown {};
        std::function<int(int fd, mode_t mode)> fchmod {};
        std::function<int(int fd)> close {};
        std::function<int(int oldDirectoryFd, const char* oldName, int newDirectoryFd, const char* newName)>
            renameat {};
    };

    /**
     * @brief The clock the publication is decided from, injectable (C28b, C36d).
     *
     * Three readings, not one: the wall clock IS the publication an agent compares generations
     * with, the monotonic one bounds the wait so a stopped wall clock cannot hang the tool forever,
     * and the sleep is what makes "never publish a future timestamp" possible -- with `now` equal
     * to the current publication the only way to a strictly greater one is to wait for it.
     */
    struct TimeSource
    {
        std::function<std::time_t()> now {};           ///< Wall clock, Unix seconds.
        std::function<std::int64_t()> monotonicNow {}; ///< Monotonic seconds; only differences matter.
        std::function<void()> sleepUntilNextSecond {}; ///< Returns once the wall clock has ticked over.
    };

    /// The real clock: `std::time`, `CLOCK_MONOTONIC` and a sleep to the next wall second.
    TimeSource systemTimeSource();

    /**
     * @brief The destination exactly as prepareWrite() read it: what the write has to preserve, and
     *        what it re-checks before publishing (C36f).
     *
     * `device`/`inode` and `sha256` together are the "read identity". Something else replacing the
     * bundle while we held the lock means it was written WITHOUT the lock -- an operator with an
     * editor, or the installer -- and overwriting it would throw that change away silently.
     */
    struct DestinationImage
    {
        dev_t device {};
        ino_t inode {};
        std::string sha256; ///< Of the bytes read through the retained descriptor, not of the certificates.
        uid_t owner {};
        gid_t group {};
        mode_t mode {}; ///< Permission bits only.
    };

    /// What prepareWrite() needs: the resolved paths (never literals -- C36a), the leaf every guard
    /// is evaluated against, who to write in the block, and the seams.
    struct WriteRequest
    {
        std::string command;              ///< "add", ...: the word every diagnostic starts with.
        std::filesystem::path bundlePath; ///< Already resolved from `/remote/https/ca_certificate`.
        std::filesystem::path lockPath;   ///< Empty means `<bundlePath>.lock`; must be in the same directory.
        const X509* leaf {nullptr};       ///< The served certificate, read from disk by main.cpp (C15).
        std::string writtenBy;            ///< `Written by` of the block, e.g. "wazuh-manager-certs 5.0.0".
        TimeSource time {};               ///< Empty fields fall back to systemTimeSource().
        IoPort io {};
        LockIo lockIo {};
    };

    /**
     * @brief One in-flight write transaction: the lock, the directory, the single bundle descriptor
     *        and everything read through it.
     *
     * Move-only and RAII: destroying it releases the lock and closes both descriptors, so every
     * early return of a command ends the transaction without publishing.
     */
    struct WriteContext
    {
        WriteContext();
        WriteContext(WriteContext&& other);
        WriteContext& operator=(WriteContext&& other);
        WriteContext(const WriteContext&) = delete;
        WriteContext& operator=(const WriteContext&) = delete;
        ~WriteContext();

        std::string command;
        std::filesystem::path bundlePath;
        std::string basename; ///< bundlePath.filename(): what renameat() publishes onto.
        const X509* leaf {nullptr};
        std::string writtenBy;
        TimeSource time {};
        IoPort io {};

        int directoryFd {-1};                  ///< The bundle's directory; every open goes through it.
        int bundleFd {-1};                     ///< The bundle, opened once and retained (C36f).
        std::unique_ptr<BundleWriteLock> lock; ///< Held for the whole transaction.

        std::string preImage; ///< The bundle's bytes as read through bundleFd.
        DestinationImage image {};
        ca_bundle::ParsedBundle bundle;       ///< parseBundle(preImage); always well formed here.
        std::int64_t previousPublication {0}; ///< The block's publication, or 0 for a plain PEM (C30).
    };

    /// What prepareWrite() produced: an open transaction, or the exit-2 cause (the bundle is
    /// missing, is a symlink, is malformed, or the lock could not be taken).
    struct PrepareOutcome
    {
        std::optional<WriteContext> context;
        std::string message; ///< Already prefixed with the command, e.g. "add: bundle not found at ...".
        int exitCode {0};    ///< 0 with a context, 2 without one.
    };

    /// What finishWrite() did: published under `publication`, or refused with `message`.
    struct WriteOutcome
    {
        int exitCode {0};               ///< 0 published; 1 a guard refused; 2 the environment or the write failed.
        std::string message;            ///< Empty only when exitCode is 0 and durability is certain.
        std::int64_t publication {0};   ///< The generation written; 0 when nothing was.
        bool durabilityUnknown {false}; ///< Published, but the directory could not be flushed (C31).
    };

    /**
     * @brief G0 and G7: the two guards that do not depend on the bundle at all, so they run before
     *        anything is opened or locked (C34c).
     *
     * @param command       The word the message starts with.
     * @param effectiveUid  `geteuid()`.
     * @param nodeType      `/cluster/node_type` of the effective configuration.
     * @return The message to print, or empty when this node may publish. Exit 2 for the euid
     *         failure (an environment mistake), 1 for the worker one (a refusal, `02-diseno.md`
     *         §2.6) -- the caller maps them, which is why they are told apart by @p exitCode.
     */
    std::string
    writeEnvironmentFailure(const std::string& command, uid_t effectiveUid, const std::string& nodeType, int& exitCode);

    /**
     * @brief Opens the transaction: lock, then the bundle, then its contents parsed.
     *
     * In that order and no other (C36f): the lock comes first so the bytes we read are the bytes we
     * will still be looking at when we publish, and the bundle is opened ONCE -- `O_NOFOLLOW`, with
     * `fstat` on the descriptor -- and never re-resolved by name afterwards.
     *
     * Refuses with exit 2, without writing anything, when: the directory or the lock cannot be
     * used, the bundle is missing (`add` does not create it -- provision it and `stamp`, C36h), it
     * is a symlink or not a regular file, it is larger than the 1 MiB cap, or `parseBundle()` says
     * it is not well formed (GP, C34b: a file we do not understand whole is never the base of a
     * republish).
     */
    PrepareOutcome prepareWrite(WriteRequest request);

    /**
     * @brief The guards every writing command shares, then the atomic publish (C29, C34a).
     *
     * Order, fixed for all four commands: G4 (0 or more than `kMaxCertificates`) -> G6 (no CA
     * chains to the leaf; evaluated here to fail fast) -> G8 (the clock, C28b: a publication behind
     * the current one is refused, and `now == previous` or no previous publication at all waits for
     * the next second) -> @p recheckAfterWait -> G6 AGAIN with the hour re-read -> G5 (serialise
     * ONCE and cap the bytes) -> GH (the hash of those same bytes) -> atomicWrite().
     *
     * G6 twice and @p recheckAfterWait between them are not belt and braces: the wait of C28b can
     * be the second in which the only CA that chains to the leaf expires, and publishing that
     * bundle would break the invariant this whole function exists for (C29/C36d) -- after a
     * successful write, `vouch()` over the resulting file returns the publication written.
     *
     * @param context   The transaction prepareWrite() opened; consumed but not closed (the caller
     *                  owns it, and its destructor releases the lock).
     * @param candidate The certificates the file should hold afterwards, in the order they will be
     *                  written. Taken by value: these bytes are serialised exactly once.
     * @param recheckAfterWait A command's own time-sensitive guards (for `add`, G3 over the
     *                  certificates it is adding), re-evaluated with the post-wait wall clock. It
     *                  returns the message to refuse with, or an empty string. The X509 objects it
     *                  looks at live in @p candidate, which outlives the call.
     */
    WriteOutcome finishWrite(WriteContext& context,
                             std::vector<ca_bundle::X509Ptr> candidate,
                             const std::function<std::string(std::time_t now)>& recheckAfterWait = {});

    /**
     * @brief `add <file>`: appends the certificates of @p inputContents to the bundle (RF-13).
     *
     * @p inputContents is the file main.cpp already read (it is the only piece that opens files,
     * D-1) and @p inputPath is where it came from, for the diagnostics.
     *
     * Refuses with exit 2 before looking at any certificate when the input is not well formed or
     * carries none (GI, C34b), and with exit 1 -- naming the offending certificate by
     * `ca_bundle::identityOf()` -- when one of them is already in the bundle or repeated within the
     * input (G1, C34d), is not a CA (G2), or has an unreadable or out-of-window validity date (G3,
     * C36g: the ASN.1 time is checked the same way `check` does it, never through `describe()`'s 0).
     * What survives all three, appended to what the bundle already held, is the candidate
     * finishWrite() decides on.
     *
     * Prints one line to @p out on success (the generation now published); every refusal and the
     * "published but not flushed" warning go to @p err.
     */
    int runAdd(WriteContext& context,
               const std::string& inputContents,
               const std::filesystem::path& inputPath,
               std::ostream& out,
               std::ostream& err);

} // namespace manager_certs

#endif // _MANAGER_CERTS_COMMANDS_HPP
