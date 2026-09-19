/*
 * Wazuh manager certs tool - atomic bundle replacement and the shared write transaction
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// atomicWrite() and the transaction the writing commands share (prepareWrite()/finishWrite()) live
// in one translation unit on purpose: they are the two halves of the same invariant -- everything
// between taking the lock and the rename is decided here, and a command only contributes the
// candidate certificates and its own input guards. The environment guards (G0/G7) are here too,
// because they are the first two steps of that same shared path (C34c).

#include "atomicWrite.hpp"

#include "manager_certs/commands.hpp"
#include "writeLock.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <random>
#include <system_error>
#include <utility>

namespace manager_certs
{
    namespace
    {
        /// Largest bundle this tool reads or re-checks, the same cap main.cpp applies on the way in
        /// and remoted applies for `GET /cacerts`
        /// (src/remoted/remoted_module/src/http_server/caCertificateSource.hpp, `kMaxBytes`). A file
        /// that grew past it since we read it counts as "changed", which is the safe answer.
        constexpr std::size_t kMaxBundleBytes {1024U * 1024U};

        /// How long the publication may wait for the wall clock to tick past the previous one
        /// (C28b). One second is the expected wait; anything beyond this means the clock is not
        /// moving, and hanging a root command forever is worse than refusing it.
        constexpr std::int64_t kMaxWaitSeconds {3};

        /// How many names a single write tries before giving up. With the lock already serialising
        /// writers, a 16-hex nonce colliding twice is not a race, it is a broken RNG.
        constexpr int kTemporaryAttempts {10};

        std::string errnoText(int error)
        {
            return std::generic_category().message(error);
        }

        /// 16 lowercase hex characters from std::random_device -- never PID + counter, which a
        /// previous crashed run can leave exhausted (C36c).
        std::string nonce()
        {
            std::random_device source;
            std::uint64_t value = static_cast<std::uint64_t>(source()) << 32U;
            value |= static_cast<std::uint64_t>(source());
            std::array<char, 17> text {};
            std::snprintf(text.data(), text.size(), "%016llx", static_cast<unsigned long long>(value));
            return std::string {text.data()};
        }

        /// Reads @p fd whole, never asking for more than kMaxBundleBytes + 1 bytes. `overflow` says
        /// the file is larger than the cap; `error` is the errno of a failed read.
        struct BoundedRead
        {
            std::string contents;
            bool overflow {false};
            int error {0};
        };

        BoundedRead readWhole(int fd)
        {
            BoundedRead result;
            static constexpr std::size_t kChunk {16U * 1024U};
            const std::size_t limit = kMaxBundleBytes + 1;
            std::array<char, kChunk> chunk {};

            while (result.contents.size() < limit)
            {
                const std::size_t wanted = std::min(kChunk, limit - result.contents.size());
                const ssize_t got = ::read(fd, chunk.data(), wanted);
                if (got < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    result.error = errno;
                    result.contents.clear();
                    return result;
                }
                if (got == 0)
                {
                    return result;
                }
                result.contents.append(chunk.data(), static_cast<std::size_t>(got));
            }

            result.overflow = result.contents.size() > kMaxBundleBytes;
            return result;
        }

        /// `epochSeconds` as RFC 3339 in UTC, the shape the block's `Updated` field carries and the
        /// one inspect/check already print dates in. Empty only if the conversion fails.
        std::string formatRfc3339(std::time_t epochSeconds)
        {
            struct tm parts {};
            if (gmtime_r(&epochSeconds, &parts) == nullptr)
            {
                return {};
            }
            std::array<char, 32> buffer {};
            const std::size_t written = std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &parts);
            return written > 0 ? std::string {buffer.data(), written} : std::string {};
        }

        /// @p source with every empty seam replaced by the real clock, so nothing downstream has to
        /// branch on "was this injected".
        TimeSource effectiveTime(const TimeSource& source)
        {
            const TimeSource real = systemTimeSource();
            TimeSource filled = source;
            if (!filled.now)
            {
                filled.now = real.now;
            }
            if (!filled.monotonicNow)
            {
                filled.monotonicNow = real.monotonicNow;
            }
            if (!filled.sleepUntilNextSecond)
            {
                filled.sleepUntilNextSecond = real.sleepUntilNextSecond;
            }
            return filled;
        }

        /// The destination's current identity and content, read by NAME through @p directoryFd --
        /// the one place that is deliberate: step 8 asks "is the file at this name still the one we
        /// read", which only a fresh open by name can answer.
        struct CurrentDestination
        {
            bool readable {false};
            dev_t device {};
            ino_t inode {};
            std::string sha256;
        };

        CurrentDestination currentDestination(int directoryFd, const std::string& name, const IoPort& io)
        {
            CurrentDestination current;
            const int fd = io.openat ? io.openat(directoryFd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0)
                                     : ::openat(directoryFd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0)
            {
                return current;
            }

            struct stat attributes {};
            if (::fstat(fd, &attributes) != 0)
            {
                ::close(fd);
                return current;
            }

            const BoundedRead contents = readWhole(fd);
            ::close(fd);
            if (contents.error != 0 || contents.overflow)
            {
                return current;
            }

            current.readable = true;
            current.device = attributes.st_dev;
            current.inode = attributes.st_ino;
            current.sha256 = bytesSha256(contents.contents);
            return current;
        }
    } // namespace

    std::string bytesSha256(std::string_view bytes)
    {
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
        unsigned int length {0};
        if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1)
        {
            return {};
        }

        std::string hex;
        hex.reserve(static_cast<std::size_t>(length) * 2U);
        for (unsigned int index = 0; index < length; ++index)
        {
            std::array<char, 3> byte {};
            std::snprintf(byte.data(), byte.size(), "%02x", digest[index]);
            hex.append(byte.data());
        }
        return hex;
    }

    TimeSource systemTimeSource()
    {
        TimeSource source;
        source.now = []()
        {
            return std::time(nullptr);
        };
        source.monotonicNow = []() -> std::int64_t
        {
            struct timespec now {};
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            {
                // Only reachable with a broken clock id; falling back to the wall clock keeps the
                // wait bounded, which is all this reading is for.
                return static_cast<std::int64_t>(std::time(nullptr));
            }
            return static_cast<std::int64_t>(now.tv_sec);
        };
        source.sleepUntilNextSecond = []()
        {
            struct timespec now {};
            if (clock_gettime(CLOCK_REALTIME, &now) != 0)
            {
                now.tv_nsec = 0;
            }
            // The rest of the current second plus a small margin: waking up a hair early would read
            // the same second again and spin the loop for nothing.
            struct timespec pause {};
            pause.tv_sec = 0;
            pause.tv_nsec = 1000000000L - now.tv_nsec + 2000000L;
            if (pause.tv_nsec >= 1000000000L)
            {
                pause.tv_sec = 1;
                pause.tv_nsec -= 1000000000L;
            }
            while (nanosleep(&pause, &pause) != 0 && errno == EINTR)
            {
                // Interrupted: finish what is left of the wait.
            }
        };
        return source;
    }

    AtomicWriteOutcome atomicWrite(int directoryFd,
                                   const std::string& name,
                                   const std::string& contents,
                                   const DestinationImage& image,
                                   const IoPort& io)
    {
        AtomicWriteOutcome outcome;

        // Step 3: the temporary, beside the destination, in the same directory descriptor.
        std::string temporary;
        int fd = -1;
        for (int attempt = 0; attempt < kTemporaryAttempts && fd < 0; ++attempt)
        {
            temporary = name + ".tmp." + nonce();
            constexpr int kFlags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC;
            fd = io.openat ? io.openat(directoryFd, temporary.c_str(), kFlags, 0600)
                           : ::openat(directoryFd, temporary.c_str(), kFlags, 0600);
            if (fd < 0 && errno != EEXIST)
            {
                outcome.error = errno;
                outcome.message = "cannot create a temporary beside " + name + " (" + errnoText(outcome.error) + ")";
                return outcome;
            }
        }
        if (fd < 0)
        {
            outcome.error = EEXIST;
            outcome.message = "cannot find a free temporary name beside " + name;
            return outcome;
        }

        bool open = true;
        // Every failure from here to the rename: unlink OUR temporary (never anybody else's) and
        // leave the destination exactly as it is.
        const auto fail = [&](const std::string& message, int error)
        {
            if (open)
            {
                ::close(fd);
                open = false;
            }
            ::unlinkat(directoryFd, temporary.c_str(), 0);
            outcome.written = false;
            outcome.error = error != 0 ? error : EIO;
            outcome.message = message;
            return outcome;
        };

        // Step 4: the bytes finishWrite() already serialised and hashed. Short writes and EINTR are
        // not failures; no progress at all is, or this loop would never end.
        std::size_t written {0};
        while (written < contents.size())
        {
            const ssize_t chunk = io.write ? io.write(fd, contents.data() + written, contents.size() - written)
                                           : ::write(fd, contents.data() + written, contents.size() - written);
            if (chunk < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                const int cause = errno;
                return fail("cannot write the new bundle (" + errnoText(cause) + ")", cause);
            }
            if (chunk == 0)
            {
                return fail("cannot write the new bundle (no progress)", EIO);
            }
            written += static_cast<std::size_t>(chunk);
        }

        const auto flush = [&io](int descriptor, bool directory)
        {
            return io.fsync ? io.fsync(descriptor, directory) : ::fsync(descriptor);
        };

        // Step 5: the contents on the medium before anything else is decided.
        if (flush(fd, /*directory=*/false) != 0)
        {
            const int cause = errno;
            return fail("cannot flush the new bundle (" + errnoText(cause) + ")", cause);
        }

        // Step 6: the destination's own owner and mode, read from its descriptor under the lock --
        // the bundle is root:<group> 0640 and the temporary was created 0600 by us.
        const int chownResult =
            io.fchown ? io.fchown(fd, image.owner, image.group) : ::fchown(fd, image.owner, image.group);
        if (chownResult != 0)
        {
            const int cause = errno;
            return fail("cannot set the new bundle's owner (" + errnoText(cause) + ")", cause);
        }
        const int chmodResult = io.fchmod ? io.fchmod(fd, image.mode) : ::fchmod(fd, image.mode);
        if (chmodResult != 0)
        {
            const int cause = errno;
            return fail("cannot set the new bundle's mode (" + errnoText(cause) + ")", cause);
        }

        // Step 7: again, because the owner and mode set above are metadata a crash could lose.
        if (flush(fd, /*directory=*/false) != 0)
        {
            const int cause = errno;
            return fail("cannot flush the new bundle's metadata (" + errnoText(cause) + ")", cause);
        }

        // Step 8: is the destination still the file we read under the lock? A writer that did not
        // take the lock (an operator's editor, the installer) must not be overwritten silently.
        const CurrentDestination current = currentDestination(directoryFd, name, io);
        if (!current.readable || current.device != image.device || current.inode != image.inode ||
            current.sha256 != image.sha256)
        {
            return fail("destination changed since it was read; aborting without publishing", EAGAIN);
        }

        // Step 9: a checked close -- a deferred write error surfaces here and nowhere else.
        const int closeResult = io.close ? io.close(fd) : ::close(fd);
        open = false;
        if (closeResult != 0)
        {
            const int cause = errno;
            return fail("cannot close the new bundle (" + errnoText(cause) + ")", cause);
        }

        // Step 10: the publication itself, one step for every reader.
        const int renameResult = io.renameat ? io.renameat(directoryFd, temporary.c_str(), directoryFd, name.c_str())
                                             : ::renameat(directoryFd, temporary.c_str(), directoryFd, name.c_str());
        if (renameResult != 0)
        {
            const int cause = errno;
            return fail("cannot publish the new bundle (" + errnoText(cause) + ")", cause);
        }

        outcome.written = true;

        // Step 11: the rename is visible now; surviving a power loss needs the directory flushed.
        // If only this fails the file on the path is already the right one, so this is a success
        // with a warning and never an error (C31) -- the one place where "published" does not imply
        // "durable".
        if (flush(directoryFd, /*directory=*/true) != 0)
        {
            outcome.error = errno != 0 ? errno : EIO;
            outcome.durabilityUnknown = true;
            outcome.message = "published, but the directory could not be flushed (" + errnoText(outcome.error) + ")";
        }

        // Step 12 (closing the directory descriptor) belongs to whoever opened it: WriteContext
        // owns it for the whole transaction and closes it when the transaction ends.
        return outcome;
    }

    // ------------------------------------------------------------------------ WriteContext ------

    WriteContext::WriteContext() = default;

    WriteContext::WriteContext(WriteContext&& other)
        : command {std::move(other.command)}
        , bundlePath {std::move(other.bundlePath)}
        , basename {std::move(other.basename)}
        , leaf {other.leaf}
        , writtenBy {std::move(other.writtenBy)}
        , time {std::move(other.time)}
        , io {std::move(other.io)}
        , directoryFd {other.directoryFd}
        , bundleFd {other.bundleFd}
        , lock {std::move(other.lock)}
        , preImage {std::move(other.preImage)}
        , image {other.image}
        , bundle {std::move(other.bundle)}
        , previousPublication {other.previousPublication}
    {
        other.directoryFd = -1;
        other.bundleFd = -1;
        other.leaf = nullptr;
    }

    WriteContext& WriteContext::operator=(WriteContext&& other)
    {
        if (this != &other)
        {
            if (bundleFd >= 0)
            {
                ::close(bundleFd);
            }
            if (directoryFd >= 0)
            {
                ::close(directoryFd);
            }

            command = std::move(other.command);
            bundlePath = std::move(other.bundlePath);
            basename = std::move(other.basename);
            leaf = other.leaf;
            writtenBy = std::move(other.writtenBy);
            time = std::move(other.time);
            io = std::move(other.io);
            directoryFd = other.directoryFd;
            bundleFd = other.bundleFd;
            lock = std::move(other.lock);
            preImage = std::move(other.preImage);
            image = other.image;
            bundle = std::move(other.bundle);
            previousPublication = other.previousPublication;

            other.directoryFd = -1;
            other.bundleFd = -1;
            other.leaf = nullptr;
        }
        return *this;
    }

    WriteContext::~WriteContext()
    {
        // The lock goes first: it is released while we still hold the descriptors it protects.
        lock.reset();
        if (bundleFd >= 0)
        {
            ::close(bundleFd);
            bundleFd = -1;
        }
        if (directoryFd >= 0)
        {
            ::close(directoryFd);
            directoryFd = -1;
        }
    }

    // -------------------------------------------------------------------- environment guards ----

    std::string
    writeEnvironmentFailure(const std::string& command, uid_t effectiveUid, const std::string& nodeType, int& exitCode)
    {
        // G0: the bundle is root:<group> 0640 inside a 1770 directory, and the publication has to
        // be attributable to the one account that may write it. Refusing here, before anything is
        // opened, is also what keeps a non-root run from leaving a lock file behind.
        if (effectiveUid != 0)
        {
            exitCode = 2;
            return command + ": must run as root (euid 0)";
        }

        // G7: only the master publishes (RF-16). A worker's own bundle comes from the master, so
        // writing one here would give its agents a generation nobody else knows about.
        //
        // Exit 2, like G0 and not like a refused certificate: exit 1 means the material the
        // operator handed over was rejected, and nothing about being a worker says anything about
        // the material. A script walking a cluster can tell "wrong node, move on" from "this PEM is
        // bad" by the code alone, without parsing the message.
        if (nodeType == "worker")
        {
            exitCode = 2;
            return command + ": this node is a cluster worker; run 'wazuh-manager-certs --from-master' instead";
        }

        exitCode = 0;
        return {};
    }

    // ----------------------------------------------------------------------- the transaction ----

    PrepareOutcome prepareWrite(WriteRequest request)
    {
        PrepareOutcome outcome;
        const std::string prefix = request.command + ": ";
        WriteContext context;

        // PrepareOutcome holds the (move-only) context, so every exit hands the caller the same
        // object by move; the local `context` above is destroyed on the way out, which is what
        // releases the lock and the descriptors on a refusal.
        const auto fail = [&](const std::string& text)
        {
            outcome.exitCode = 2;
            outcome.message = prefix + text;
            outcome.context.reset();
            return std::move(outcome);
        };

        if (request.bundlePath.empty())
        {
            return fail("no CA bundle path to write");
        }

        // Everything is derived from the configured, already-resolved bundle path: its directory,
        // its basename, its lock. Never etc/certs/root-ca.pem, which is only this option's default
        // (C36a).
        std::filesystem::path directory = request.bundlePath.parent_path();
        if (directory.empty())
        {
            directory = ".";
        }
        context.basename = request.bundlePath.filename().string();
        if (context.basename.empty() || context.basename == "." || context.basename == "..")
        {
            return fail("the configured CA bundle path is not a file: " + request.bundlePath.string());
        }

        const std::filesystem::path lockPath =
            request.lockPath.empty() ? std::filesystem::path {request.bundlePath.string() + ".lock"} : request.lockPath;
        if (!lockPath.parent_path().empty() && lockPath.parent_path() != directory)
        {
            return fail("the lock file must live in the bundle's own directory: " + lockPath.string());
        }

        context.command = request.command;
        context.bundlePath = request.bundlePath;
        context.leaf = request.leaf;
        context.writtenBy = request.writtenBy;
        context.time = effectiveTime(request.time);
        context.io = request.io;

        context.directoryFd = ::openat(AT_FDCWD, directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (context.directoryFd < 0)
        {
            const int cause = errno;
            return fail("cannot open the CA bundle's directory " + directory.string() + " (" + errnoText(cause) + ")");
        }

        // The lock BEFORE the bundle is opened: what we are about to read has to still be what we
        // publish over, and only the lock makes that true (C34f).
        auto acquired = BundleWriteLock::acquire(
            context.directoryFd, lockPath.filename().string(), lockPath.string(), request.lockIo);
        if (!acquired.lock)
        {
            return fail(acquired.message);
        }
        context.lock = std::make_unique<BundleWriteLock>(std::move(*acquired.lock));

        context.bundleFd = ::openat(context.directoryFd, context.basename.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (context.bundleFd < 0)
        {
            const int cause = errno;
            if (cause == ENOENT)
            {
                // The installer never creates the bundle (CheckListenerCerts(),
                // src/init/inst-functions.sh:181-206): it is provisioned externally, so the honest
                // instruction is to provision it and stamp it, not to reinstall (C36h).
                return fail("bundle not found at " + request.bundlePath.string() +
                            "; provision it and run 'wazuh-manager-certs stamp'");
            }
            if (cause == ELOOP)
            {
                return fail("refusing to follow a symlink at " + request.bundlePath.string());
            }
            return fail("CA bundle cannot be opened: " + request.bundlePath.string() + " (" + errnoText(cause) + ")");
        }

        struct stat attributes {};
        if (::fstat(context.bundleFd, &attributes) != 0)
        {
            const int cause = errno;
            return fail("CA bundle cannot be read: " + request.bundlePath.string() + " (" + errnoText(cause) + ")");
        }
        if (!S_ISREG(attributes.st_mode))
        {
            return fail("CA bundle is not a regular file: " + request.bundlePath.string());
        }

        const BoundedRead contents = readWhole(context.bundleFd);
        if (contents.error != 0)
        {
            return fail("CA bundle cannot be read: " + request.bundlePath.string() + " (" + errnoText(contents.error) +
                        ")");
        }
        if (contents.overflow)
        {
            return fail("CA bundle is larger than the 1 MiB cap: " + request.bundlePath.string());
        }

        context.preImage = contents.contents;
        context.image.device = attributes.st_dev;
        context.image.inode = attributes.st_ino;
        context.image.owner = attributes.st_uid;
        context.image.group = attributes.st_gid;
        context.image.mode = attributes.st_mode & 07777;
        context.image.sha256 = bytesSha256(context.preImage);
        if (context.image.sha256.empty())
        {
            return fail("cannot hash the CA bundle at " + request.bundlePath.string());
        }

        context.bundle = ca_bundle::parseBundle(context.preImage);
        if (!context.bundle.wellFormed)
        {
            // GP (C34b): a file we do not understand whole is not a base to republish from -- doing
            // so would drop every anchor past the first block we could not decode.
            return fail("existing bundle at " + request.bundlePath.string() + " is malformed; refusing to write");
        }

        // The previous publication is what the block CLAIMS, even if its hash no longer describes
        // the certificates: agents may have been told that generation, so the next one has to be
        // strictly greater. A plain PEM (or a block-less one) counts as 0 (02-diseno.md §2.6, C30).
        context.previousPublication =
            context.bundle.block ? std::max<std::int64_t>(0, context.bundle.block->publication) : 0;

        outcome.exitCode = 0;
        outcome.context = std::move(context);
        return outcome;
    }

    WriteOutcome finishWrite(WriteContext& context,
                             std::vector<ca_bundle::X509Ptr> candidate,
                             const std::function<std::string(std::time_t now)>& recheckAfterWait)
    {
        WriteOutcome outcome;
        const std::string prefix = context.command + ": ";
        const auto refuse = [&](int code, const std::string& text)
        {
            outcome.exitCode = code;
            outcome.message = prefix + text;
            outcome.publication = 0;
            return outcome;
        };

        // G4 -- for every writing command, not just `add`: a `remove` over an oversized bundle can
        // leave one that is still oversized, and publishing zero certificates would strand the
        // fleet (C34a).
        if (candidate.empty())
        {
            return refuse(1, "0 certificates");
        }
        if (candidate.size() > ca_bundle::kMaxCertificates)
        {
            return refuse(1,
                          std::to_string(candidate.size()) + " certificates (max " +
                              std::to_string(ca_bundle::kMaxCertificates) + ")");
        }

        // G6, first pass: fail fast, before anybody waits a second for a bundle that is going to be
        // refused anyway.
        if (!ca_bundle::leafChainsToAnyCa(context.leaf, candidate))
        {
            return refuse(1, "no CA signs the served leaf");
        }

        // G8 (C28b): never publish a timestamp in the future, and never one that is not strictly
        // greater than the current publication. Behind it is a refusal; equal to it -- or with no
        // publication at all, where the file may well have been published in this very second and
        // lost its block (C30/C36e) -- is a wait for the next second.
        const TimeSource time = effectiveTime(context.time);
        const std::int64_t previous = context.previousPublication;
        std::int64_t now = static_cast<std::int64_t>(time.now());
        if (now < previous)
        {
            return refuse(1, "clock is behind the current publication " + std::to_string(previous));
        }

        if (previous == 0 || now == previous)
        {
            const std::int64_t target = std::max(previous, now);
            const std::int64_t started = time.monotonicNow();
            while (true)
            {
                time.sleepUntilNextSecond();
                const std::int64_t woke = static_cast<std::int64_t>(time.now());
                if (woke < previous)
                {
                    return refuse(1, "clock is behind the current publication " + std::to_string(previous));
                }
                if (woke < target)
                {
                    return refuse(1, "the clock moved backwards while waiting for the next second");
                }
                if (woke > target)
                {
                    now = woke;
                    break;
                }
                // The monotonic clock is what bounds this: a wall clock frozen on `target` would
                // otherwise keep a root command here forever.
                if (time.monotonicNow() - started >= kMaxWaitSeconds)
                {
                    return refuse(1,
                                  "the clock did not advance past " + std::to_string(target) + " within " +
                                      std::to_string(kMaxWaitSeconds) + " seconds");
                }
            }
        }

        // The command's own time-sensitive guards, re-evaluated with the hour we just re-read: for
        // `add`, G3 over the certificates it is adding (C36d/g). A certificate that expired during
        // the wait would otherwise be published and rejected by vouch() a millisecond later,
        // breaking exactly the invariant this function exists to keep (C29).
        if (recheckAfterWait)
        {
            const std::string failure = recheckAfterWait(static_cast<std::time_t>(now));
            if (!failure.empty())
            {
                return refuse(1, failure);
            }
        }

        // G6, second pass: same reason, for the CA that signs the leaf. leafChainsToAnyCa()
        // validates the whole chain's validity window against the clock as it is NOW.
        if (!ca_bundle::leafChainsToAnyCa(context.leaf, candidate))
        {
            return refuse(1, "no CA signs the served leaf");
        }

        // G5: serialised ONCE, here, and these exact bytes are what gets hashed, described by the
        // block and written. Re-serialising after validating could publish a block describing
        // certificates the file does not carry (C36b).
        const std::string serialized = ca_bundle::serializeCertificates(candidate);
        if (serialized.empty())
        {
            return refuse(2, "empty serialization, refusing to write");
        }
        if (serialized.size() > ca_bundle::kMaxSerializedBytes)
        {
            return refuse(1,
                          std::to_string(serialized.size()) + " bytes (max " +
                              std::to_string(ca_bundle::kMaxSerializedBytes) + ")");
        }

        // GH, over the same certificates those bytes came from.
        const std::string hash = ca_bundle::contentSha256(candidate);
        if (hash.empty())
        {
            return refuse(2, "empty content hash, refusing to write");
        }

        ca_bundle::PublicationBlock block;
        block.publication = now;
        block.contentSha256 = hash;
        block.updated = formatRfc3339(static_cast<std::time_t>(now));
        block.writtenBy = context.writtenBy.empty() ? std::string {"wazuh-manager-certs"} : context.writtenBy;
        if (block.updated.empty())
        {
            return refuse(2, "cannot format the publication time, refusing to write");
        }

        const AtomicWriteOutcome written = atomicWrite(context.directoryFd,
                                                       context.basename,
                                                       ca_bundle::renderBlock(block) + serialized,
                                                       context.image,
                                                       context.io);
        if (!written.written)
        {
            outcome.exitCode = 2;
            outcome.message = prefix + written.message;
            return outcome;
        }

        outcome.exitCode = 0;
        outcome.publication = now;
        outcome.durabilityUnknown = written.durabilityUnknown;
        if (written.durabilityUnknown)
        {
            outcome.message = prefix + written.message;
        }
        return outcome;
    }

} // namespace manager_certs
