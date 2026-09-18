/*
 * wazuh-manager-certs: inspect and check the CA bundle the manager's HTTPS listener serves.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
 */

#include "manager_certs/commands.hpp"

#include <ca_bundle/ca_bundle.hpp>
#include <manager_config/manager_config.hpp>

#include <rapidjson/document.h>
#include <rapidjson/pointer.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

#ifndef WAZUH_MANAGER_CERTS_VERSION
#define WAZUH_MANAGER_CERTS_VERSION "unknown"
#endif

namespace
{
    constexpr int EXIT_OK = 0;          ///< Command ran; the bundle is vouched for (`check`).
    constexpr int EXIT_REJECTED = 1;    ///< `inspect`/`check` refused it, or a usage error.
    constexpr int EXIT_ENVIRONMENT = 2; ///< Configuration, bundle or leaf could not be read.

    /// Same variable w_homedir() honours for the manager (defs.h WAZUH_HOME_ENV).
    constexpr const char* HOME_ENV = "WAZUH_MANAGER_HOME";
    constexpr const char* DEFAULT_FILE = "etc/wazuh-manager.conf";

    void usage(std::FILE* out)
    {
        std::fputs("Usage: wazuh-manager-certs [-f <file>] [-H <home>] <command>\n"
                   "\n"
                   "Commands:\n"
                   "  inspect             Describe the CA bundle's certificates and publication status.\n"
                   "  check               Validate the CA bundle without writing anything.\n"
                   "\n"
                   "Options:\n"
                   "  -f <file>           Configuration file (default: <home>/etc/wazuh-manager.conf).\n"
                   "  -H <home>           Manager home used to resolve relative paths (default: $WAZUH_MANAGER_HOME,\n"
                   "                      else the parent of the bin/ directory holding this program).\n"
                   "  -h, --help          This help.\n"
                   "  -V, --version       Print the version.\n"
                   "\n"
                   "-h/--help and -V/--version never read the configuration: they work with every daemon\n"
                   "stopped and without a manager home set.\n"
                   "\n"
                   "'add', 'remove', 'prune-expired', 'stamp' and '--from-master' arrive in later versions.\n"
                   "\n"
                   "Exit status: 0 success; 1 the bundle was rejected, or a usage error; 2 environment error\n"
                   "(configuration, bundle or leaf could not be read).\n",
                   out);
    }

    int usageError(const std::string& message)
    {
        std::fprintf(stderr, "wazuh-manager-certs: %s\n", message.c_str());
        usage(stderr);
        return EXIT_REJECTED;
    }

    int environmentError(const std::string& message)
    {
        std::fprintf(stderr, "wazuh-manager-certs: %s\n", message.c_str());
        return EXIT_ENVIRONMENT;
    }

    /// -H, then $WAZUH_MANAGER_HOME, then the parent of this binary's bin/ directory (as w_homedir()).
    /// Exact mold of manager_config/cli/manager-conf.cpp's resolveHome(): same fallback chain, same
    /// $WAZUH_MANAGER_HOME, so both CLIs resolve a bare relative configuration path identically.
    std::filesystem::path resolveHome(const std::string& fromOption)
    {
        if (!fromOption.empty())
        {
            return fromOption;
        }
        if (const char* env = std::getenv(HOME_ENV); env != nullptr && *env != '\0')
        {
            return env;
        }
        std::error_code ec;
        const auto exe = std::filesystem::read_symlink("/proc/self/exe", ec);
        if (!ec && exe.has_parent_path())
        {
            return exe.parent_path().parent_path();
        }
        return std::filesystem::current_path(ec);
    }

    /// @p path resolved against @p home when it is not already absolute.
    std::filesystem::path resolvePath(const std::string& path, const std::filesystem::path& home)
    {
        std::filesystem::path candidate {path};
        return candidate.is_absolute() ? candidate : home / candidate;
    }

    /// The string at @p pointer in @p document, or an empty string when absent or not a string.
    std::string stringAt(const rapidjson::Document& document, const char* pointer)
    {
        const rapidjson::Value* value = rapidjson::Pointer(pointer).Get(document);
        return (value != nullptr && value->IsString()) ? value->GetString() : std::string {};
    }

    /// Largest file this tool will ever read for the bundle or the leaf: the same cap remoted
    /// applies when it reads the CA bundle for `GET /cacerts`
    /// (src/remoted/remoted_module/src/http_server/caCertificateSource.hpp:147, `kMaxBytes`).
    /// Duplicated here rather than linked -- this tool must not depend on remoted_module -- but C9
    /// still holds: a bundle the daemon would refuse for its size must never read as "vouched: yes"
    /// here. Applied to the leaf too, for the same reason applied to everything else this tool
    /// reads: the two must never disagree about what fits.
    constexpr std::size_t kMaxFileBytes {1024U * 1024U};

    /// Why a bounded read did not produce the whole file.
    enum class ReadFailureKind
    {
        CannotOpen, ///< open(2) failed: missing, permission, a dangling symlink...
        NotRegular, ///< Opened, but fstat() says it is not a plain file (a directory, a FIFO, ...).
        ReadError,  ///< read(2) or fstat() failed after a successful open.
        TooLarge    ///< More than kMaxFileBytes were available; nothing past the cap was requested.
    };

    /// Outcome of readBounded(): the whole file (never more than kMaxFileBytes) in @p contents, or
    /// @p contents empty and @p failure/@p error naming why. @p failure/@p error are meaningless
    /// once @p contents holds a value.
    struct BoundedRead
    {
        std::optional<std::string> contents;
        ReadFailureKind failure {ReadFailureKind::CannotOpen};
        int error {0}; ///< errno of the failed call; 0 for NotRegular/TooLarge.
    };

    /// Owns a POSIX descriptor for the duration of one read.
    class PosixFd
    {
    public:
        explicit PosixFd(int fd) noexcept
            : m_fd {fd}
        {
        }
        ~PosixFd()
        {
            if (m_fd >= 0)
            {
                ::close(m_fd);
            }
        }
        PosixFd(const PosixFd&) = delete;
        PosixFd& operator=(const PosixFd&) = delete;

        int get() const noexcept
        {
            return m_fd;
        }

    private:
        int m_fd;
    };

    /// Reads @p path whole, never requesting more than kMaxFileBytes + 1 bytes from it -- so a file
    /// that grows while it is being read is capped exactly like one that already was too large --
    /// and refusing anything that fstat() on the OPEN descriptor says is not a regular file (a
    /// directory, a FIFO, a socket) before a single byte of it is parsed: fstat on the descriptor,
    /// not stat on the path, so a swap between the check and the open cannot slip one past this.
    /// O_NONBLOCK so a FIFO with no writer fails here instead of blocking the whole run. A read
    /// error discards whatever was read so far: a partial bundle or a partial leaf is not a smaller
    /// one, it is none. Mirrors remoted's readFileBounded()
    /// (src/remoted/remoted_module/src/http_server/fileRead.cpp) for the CA bundle; duplicated here
    /// because this tool must not link remoted_module, and applied to the leaf as well (C15/C27).
    BoundedRead readBounded(const std::filesystem::path& path)
    {
        const PosixFd file {::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)};
        if (file.get() < 0)
        {
            return {std::nullopt, ReadFailureKind::CannotOpen, errno};
        }

        struct stat attributes {};
        if (::fstat(file.get(), &attributes) != 0)
        {
            return {std::nullopt, ReadFailureKind::ReadError, errno};
        }
        if (!S_ISREG(attributes.st_mode))
        {
            return {std::nullopt, ReadFailureKind::NotRegular, 0};
        }

        static constexpr std::size_t kChunk {16U * 1024U};
        const std::size_t limit = kMaxFileBytes + 1;
        std::array<char, kChunk> chunk {};
        std::string contents;
        std::size_t total = 0;

        while (total < limit)
        {
            const std::size_t wanted = std::min(kChunk, limit - total);
            const ssize_t got = ::read(file.get(), chunk.data(), wanted);
            if (got < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return {std::nullopt, ReadFailureKind::ReadError, errno};
            }
            if (got == 0)
            {
                break; // EOF: the whole file fit under the cap.
            }
            contents.append(chunk.data(), static_cast<std::size_t>(got));
            total += static_cast<std::size_t>(got);
        }

        if (total > kMaxFileBytes)
        {
            return {std::nullopt, ReadFailureKind::TooLarge, 0};
        }

        return {std::move(contents), ReadFailureKind::CannotOpen, 0};
    }

    /// @p read's failure as "<subject> ...", naming @p path -- so an operator sees exactly which
    /// file and why, never just a bare exit code (C9: the tool's diagnostic and remoted's log line
    /// for the same cause should read the same way).
    std::string
    describeReadFailure(const std::string& subject, const std::filesystem::path& path, const BoundedRead& read)
    {
        switch (read.failure)
        {
            case ReadFailureKind::CannotOpen:
                return subject + " not found or not readable: " + path.string() + " (" +
                       std::generic_category().message(read.error) + ")";
            case ReadFailureKind::NotRegular: return subject + " is not a regular file: " + path.string();
            case ReadFailureKind::ReadError:
                return subject + " cannot be read: " + path.string() + " (" +
                       std::generic_category().message(read.error) + ")";
            case ReadFailureKind::TooLarge: return subject + " is larger than the 1 MiB cap: " + path.string();
        }
        return subject + " could not be read: " + path.string();
    }

    /// The leaf certificate parsed from @p contents (already read through readBounded(), C15: the
    /// leaf the listener will serve on its next start, from disk -- not from a running daemon,
    /// which may not even be up). nullptr when it does not parse as a single certificate. Parses
    /// from memory (never BIO_new_file): the bytes are already in hand, bounded, and a leaf FIFO
    /// with no writer must never reach an OpenSSL call that itself could block.
    ca_bundle::X509Ptr parseLeaf(const std::string& contents)
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio {
            BIO_new_mem_buf(contents.data(), static_cast<int>(contents.size())), &BIO_free};
        if (!bio)
        {
            ERR_clear_error();
            return {};
        }
        ca_bundle::X509Ptr leaf {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
        if (!leaf)
        {
            ERR_clear_error();
        }
        return leaf;
    }

    int run(int argc, char** argv)
    {
        std::string file;
        std::string home;
        std::vector<std::string> positional;

        for (int i = 1; i < argc; ++i)
        {
            const std::string_view arg = argv[i];
            if (arg == "-h" || arg == "--help")
            {
                usage(stdout);
                return EXIT_OK;
            }
            if (arg == "-V" || arg == "--version")
            {
                std::printf("wazuh-manager-certs %s\n", WAZUH_MANAGER_CERTS_VERSION);
                return EXIT_OK;
            }
            if (arg == "-f" || arg == "-H")
            {
                if (i + 1 >= argc)
                {
                    return usageError(std::string(arg) + " needs an argument");
                }
                (arg == "-f" ? file : home) = argv[++i];
            }
            else if (arg.size() > 1 && arg[0] == '-')
            {
                return usageError("unknown option '" + std::string(arg) + "'");
            }
            else
            {
                positional.emplace_back(arg);
            }
        }

        if (positional.empty())
        {
            return usageError("missing command");
        }
        const std::string& command = positional[0];
        if (command != "inspect" && command != "check")
        {
            return usageError("'" + command + "' is not available yet (it arrives in a later version)");
        }
        if (positional.size() != 1)
        {
            return usageError("'" + command + "' takes no arguments");
        }

        const std::filesystem::path homePath = resolveHome(home);
        const std::filesystem::path filePath = file.empty() ? homePath / DEFAULT_FILE : std::filesystem::path(file);
        std::error_code ec;
        if (!std::filesystem::is_regular_file(filePath, ec))
        {
            return environmentError("configuration file not found: " + filePath.string());
        }

        // File-existence checks are ours to do (bundle/leaf get their own, distinct messages below):
        // manager_config's own checkFiles never looks at /remote/https/ca_certificate at all, and
        // folding /remote/https/certificate's check into it would collapse "leaf missing" into
        // "configuration invalid".
        manager_config::LoadOptions options;
        options.checkFiles = false;
        options.home = homePath;
        auto loaded = manager_config::Document::load(filePath, options);
        if (const auto* error = std::get_if<manager_config::Error>(&loaded))
        {
            return environmentError("configuration is invalid: " + error->what());
        }
        const auto& document = std::get<manager_config::Document>(loaded);

        rapidjson::Document json;
        json.Parse(document.documentJson().c_str());
        if (json.HasParseError())
        {
            return environmentError("internal error: the effective configuration is not valid JSON");
        }

        const std::string bundlePathString = stringAt(json, "/remote/https/ca_certificate");
        const std::string leafPathString = stringAt(json, "/remote/https/certificate");
        if (bundlePathString.empty())
        {
            return environmentError("the effective configuration does not set /remote/https/ca_certificate");
        }
        if (leafPathString.empty())
        {
            return environmentError("the effective configuration does not set /remote/https/certificate");
        }
        const std::filesystem::path bundlePath = resolvePath(bundlePathString, homePath);
        const std::filesystem::path leafPath = resolvePath(leafPathString, homePath);

        // Bundle before leaf, always (tests/cli/manager_certs_cli_test.sh relies on this order to
        // tell which file a fixture's exit-2 is about).
        const BoundedRead bundleRead = readBounded(bundlePath);
        if (!bundleRead.contents)
        {
            return environmentError(describeReadFailure("CA bundle", bundlePath, bundleRead));
        }

        const BoundedRead leafRead = readBounded(leafPath);
        if (!leafRead.contents)
        {
            return environmentError(describeReadFailure("leaf certificate", leafPath, leafRead));
        }
        ca_bundle::X509Ptr leaf = parseLeaf(*leafRead.contents);
        if (!leaf)
        {
            return environmentError("leaf certificate does not parse as a single certificate: " + leafPath.string());
        }

        const ca_bundle::ParsedBundle bundle = ca_bundle::parseBundle(*bundleRead.contents);

        if (command == "inspect")
        {
            return manager_certs::runInspect(bundle, leaf.get(), std::cout);
        }
        // command == "check"
        const auto serializedBytes = ca_bundle::serializeCertificates(bundle.certificates).size();
        if (!bundle.certificates.empty() && serializedBytes == 0)
        {
            // serializeCertificates() failed on a bundle that DOES carry certificates: nothing to
            // hand out, so this is not "check rejects it" (exit 1), it is "we could not tell"
            // (exit 2) -- never pass 0 bytes to runCheck()'s vouch(), which would otherwise read as
            // "small enough" and pass the byte cap on a bundle that serialises to nothing at all.
            // Same call remoted's buildLocked() makes for GET /cacerts (caCertificateSource.cpp:140).
            return environmentError("internal error: failed to re-serialise the CA bundle's certificates");
        }
        return manager_certs::runCheck(bundle, leaf.get(), serializedBytes, std::cerr);
    }
} // namespace

int main(int argc, char** argv)
{
    try
    {
        return run(argc, argv);
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "wazuh-manager-certs: %s\n", e.what());
        return EXIT_ENVIRONMENT;
    }
}
