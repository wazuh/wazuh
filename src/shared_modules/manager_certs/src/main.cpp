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
        std::fputs("Usage: wazuh-manager-certs [-f <file>] [-H <home>] <command> [<argument>]\n"
                   "\n"
                   "Commands:\n"
                   "  inspect             Describe the CA bundle's certificates and publication status.\n"
                   "  check               Validate the CA bundle without writing anything.\n"
                   "  add <file>          Add the certificates of <file> to the CA bundle and publish it.\n"
                   "  remove <identity>   Remove every certificate with <identity> (as 'inspect' prints it)\n"
                   "                      from the CA bundle and publish it.\n"
                   "  prune-expired       Remove the CA bundle's expired certificates and publish it; with\n"
                   "                      nothing expired it writes nothing.\n"
                   "  stamp               Publish the CA bundle's certificates unchanged, under a new\n"
                   "                      generation.\n"
                   "\n"
                   "  --from-master [--master <host>] [--port <port>]\n"
                   "                      Worker nodes only: download the CA bundle the master publishes at\n"
                   "                      GET /cacerts over HTTPS and install it here, under the generation\n"
                   "                      the master announces. Not a command word: it is an option, and it\n"
                   "                      takes no argument of its own.\n"
                   "\n"
                   "Options:\n"
                   "  -f <file>           Configuration file (default: <home>/etc/wazuh-manager.conf).\n"
                   "  -H <home>           Manager home used to resolve relative paths (default: $WAZUH_MANAGER_HOME,\n"
                   "                      else the parent of the bin/ directory holding this program).\n"
                   "  --master <host>     Master to pull from (default: the first of cluster.nodes).\n"
                   "  --port <port>       Master's HTTPS port (default: remote.https.port).\n"
                   "  -h, --help          This help.\n"
                   "  -V, --version       Print the version.\n"
                   "\n"
                   "-h/--help and -V/--version never read the configuration: they work with every daemon\n"
                   "stopped and without a manager home set.\n"
                   "\n"
                   "'add', 'remove', 'prune-expired' and 'stamp' write: they must run as root, on the\n"
                   "master node, and each takes an exclusive lock on <bundle>.lock while it reads, validates\n"
                   "and replaces the bundle. None of them creates the bundle.\n"
                   "\n"
                   "'--from-master' writes too, and mirrors that rule: root, on a WORKER node, under the same\n"
                   "lock -- taken before it connects, so the CA that verifies the master is the one the write\n"
                   "publishes over. The master's certificate is verified against this node's own bundle and\n"
                   "nothing else; no option relaxes that.\n"
                   "\n"
                   "Exit status: 0 success; 1 the bundle or the certificate was rejected, or a usage error;\n"
                   "2 environment error (configuration, bundle, leaf or input could not be read, or this is\n"
                   "not a root process).\n",
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

    /// The integer at @p pointer written out, or an empty string when absent or not an integer.
    /// The effective configuration materialises schema defaults (`wazuh-manager-conf get
    /// remote.https.port` prints 1517 for a file that never mentions it), so an empty answer here
    /// means the configuration really has no such option, not that it was left out of the file.
    std::string numberAt(const rapidjson::Document& document, const char* pointer)
    {
        const rapidjson::Value* value = rapidjson::Pointer(pointer).Get(document);
        return (value != nullptr && value->IsInt64()) ? std::to_string(value->GetInt64()) : std::string {};
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

    /// The writing commands' own path: the leaf and (for `add`) the input file are read here
    /// (main.cpp is the only piece of this tool that opens a file, D-1), and the bundle is opened by
    /// prepareWrite() under the lock -- never before it, so what a guard validated is what gets
    /// published. @p argument is the file for `add`, the identity for `remove`, and unused by
    /// `prune-expired`/`stamp`.
    int runWrite(const std::string& command,
                 const std::string& argument,
                 const std::filesystem::path& bundlePath,
                 const std::filesystem::path& leafPath)
    {
        // The leaf first: every candidate is validated against it (C15, G6), so a missing one is an
        // environment error before any lock is taken.
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

        // Only `add` takes a file, and it is read BEFORE the lock: an unreadable input is an
        // environment error that should never cost another writer its turn on the bundle.
        const bool takesInputFile = command == "add";
        const std::filesystem::path inputPath {takesInputFile ? argument : std::string {}};
        std::string inputContents;
        if (takesInputFile)
        {
            const BoundedRead inputRead = readBounded(inputPath);
            if (!inputRead.contents)
            {
                return environmentError(describeReadFailure("input file", inputPath, inputRead));
            }
            inputContents = *inputRead.contents;
        }

        manager_certs::WriteRequest request;
        request.command = command;
        request.bundlePath = bundlePath;
        request.leaf = leaf.get();
        request.writtenBy = std::string {"wazuh-manager-certs "} + WAZUH_MANAGER_CERTS_VERSION;

        manager_certs::PrepareOutcome prepared = manager_certs::prepareWrite(std::move(request));
        if (!prepared.context)
        {
            std::fprintf(stderr, "wazuh-manager-certs: %s\n", prepared.message.c_str());
            return prepared.exitCode;
        }

        if (command == "add")
        {
            return manager_certs::runAdd(*prepared.context, inputContents, inputPath, std::cout, std::cerr);
        }
        if (command == "remove")
        {
            return manager_certs::runRemove(*prepared.context, argument, std::cout, std::cerr);
        }
        if (command == "prune-expired")
        {
            return manager_certs::runPruneExpired(*prepared.context, std::cout, std::cerr);
        }
        return manager_certs::runStamp(*prepared.context, std::cout, std::cerr);
    }

    /// `--from-master`: the worker's own write path. Same shape as runWrite() -- main.cpp reads the
    /// leaf (D-1) and hands everything else over -- except that the transaction is opened inside
    /// runFromMaster(), because the lock has to be held BEFORE the download starts (C39d), not
    /// after it, and the download is the part that needs the bundle this lock protects.
    int runFromMasterCommand(const rapidjson::Document& json,
                             const std::string& masterOption,
                             const std::string& portOption,
                             const std::filesystem::path& bundlePath,
                             const std::filesystem::path& leafPath)
    {
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

        // Where the master is: the two options override the configuration, in the one direction an
        // operator needs when the cluster section does not describe the node they can actually
        // reach. The port is required -- the schema gives it a default, so an absent one means the
        // configuration itself is not usable -- while an absent host is refused by runFromMaster()
        // with the message that tells the operator to pass --master.
        const std::string port = portOption.empty() ? numberAt(json, "/remote/https/port") : portOption;
        if (port.empty())
        {
            return environmentError("the effective configuration does not set /remote/https/port");
        }

        manager_certs::WriteRequest request;
        request.command = "--from-master";
        request.bundlePath = bundlePath;
        request.leaf = leaf.get();
        request.writtenBy = std::string {"wazuh-manager-certs "} + WAZUH_MANAGER_CERTS_VERSION;

        manager_certs::FromMasterRequest fetch;
        fetch.host = masterOption.empty() ? stringAt(json, "/cluster/nodes/0") : masterOption;
        fetch.port = port;
        fetch.globalPrefix = stringAt(json, "/remote/https/global_prefix");

        return manager_certs::runFromMaster(std::move(request), std::move(fetch), std::cout, std::cerr);
    }

    int run(int argc, char** argv)
    {
        std::string file;
        std::string home;
        std::string master;
        std::string port;
        bool fromMaster = false;
        bool addressGiven = false;
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
            // `--from-master` is an OPTION, not a command word: it is the one thing this tool does
            // that is not a verb over the local bundle, and its two modifiers only make sense with
            // it. Parsed here, before the positional command is even looked at, so the command
            // grammar below stays exactly what it was for the six commands.
            if (arg == "--from-master")
            {
                fromMaster = true;
            }
            else if (arg == "--master" || arg == "--port")
            {
                if (i + 1 >= argc)
                {
                    return usageError(std::string(arg) + " needs an argument");
                }
                (arg == "--master" ? master : port) = argv[++i];
                addressGiven = true;
            }
            else if (arg == "-f" || arg == "-H")
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

        if (addressGiven && !fromMaster)
        {
            return usageError("'--master' and '--port' are only used with '--from-master'");
        }
        if (fromMaster && !positional.empty())
        {
            return usageError("'--from-master' takes no command, and '" + positional[0] + "' was given");
        }
        if (!fromMaster && positional.empty())
        {
            return usageError("missing command");
        }

        const std::string command = fromMaster ? std::string {"--from-master"} : positional[0];
        const bool writes = command == "add" || command == "remove" || command == "prune-expired" || command == "stamp";
        if (!fromMaster)
        {
            if (command != "inspect" && command != "check" && !writes)
            {
                return usageError("'" + command + "' is not a wazuh-manager-certs command");
            }
            // `add` takes the file to add and `remove` the identity to drop; the other four take
            // nothing at all.
            if (command == "add" || command == "remove")
            {
                if (positional.size() != 2)
                {
                    return usageError("'" + command + "' takes exactly one argument: " +
                                      (command == "add" ? "the file to add" : "the identity to remove"));
                }
            }
            else if (positional.size() != 1)
            {
                return usageError("'" + command + "' takes no arguments");
            }
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

        // G0 and G7, before anything reads, opens or locks the bundle (C34c): a writing command on
        // the wrong account or on a worker node must not even create the lock file. Both come from
        // the effective configuration and the process itself, never from the bundle.
        if (writes || fromMaster)
        {
            int guardExit = 0;
            const std::string nodeType = stringAt(json, "/cluster/node_type");
            // The same G0 for both, and G7 the other way round for `--from-master`: the four
            // commands publish here and refuse on a worker, this one installs what the master
            // published and refuses anywhere else (C37a).
            const std::string failure =
                fromMaster ? manager_certs::fromMasterEnvironmentFailure(command, ::geteuid(), nodeType, guardExit)
                           : manager_certs::writeEnvironmentFailure(command, ::geteuid(), nodeType, guardExit);
            if (!failure.empty())
            {
                std::fprintf(stderr, "wazuh-manager-certs: %s\n", failure.c_str());
                return guardExit;
            }
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

        if (fromMaster)
        {
            return runFromMasterCommand(json, master, port, bundlePath, leafPath);
        }

        if (writes)
        {
            return runWrite(command, positional.size() > 1 ? positional[1] : std::string {}, bundlePath, leafPath);
        }

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
