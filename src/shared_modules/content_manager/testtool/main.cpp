// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
#include "contentIndexerAdapters.hpp"
#include "contentLogging.hpp"
#include "contentRegister.hpp"
#include "contentSink.hpp"
#include "contentTypes.hpp"
#include "loggerHelper.h"
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <future>
#include <indexer_client/keyValueConfigSource.hpp>
#include <indexer_client/runtime.hpp>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

/*
 * Test tool for the Content Manager.
 *
 * Starts the process's indexer_client runtime as modulesd does, takes a Client from it and registers one topic
 * against a live Wazuh Indexer through the library's v2 adapter. The driver thread runs a cycle at start; the tool
 * then requests one more through the same call a host's HTTP route makes and exits with its result. The sink below
 * only prints what it is given, which makes this the shortest way to see the exact shape of the delivery contract.
 *
 * Usage: see USAGE below (--help prints it). Hosts and credentials come from the arguments and the environment only
 * (no keystore). Exit code 0 when the requested cycle completed, 2 on a bad command line.
 */
static const std::string TOPIC_NAME {"test"};
static const std::string CONSUMER_NAME {"content-manager-testtool"};
static const char* const PASSWORD_ENV {"CM_TESTTOOL_PASSWORD"};
static constexpr unsigned long MIN_TIMEOUT_SECONDS {1};
static constexpr unsigned long MAX_TIMEOUT_SECONDS {86400};

static const char* const USAGE =
    "Usage: content_manager_test_tool --hosts URL[,URL...] --user U (--password-file FILE | --password P)\n"
    "         [--ca FILE]... [--cert FILE --key FILE] [--index NAME]... [--readiness-index NAME --readiness-id ID]\n"
    "         [--state-dir DIR] [--full] [--timeout S]\n"
    "       content_manager_test_tool --help\n"
    "\n"
    "  --hosts URL[,URL...]    Indexer nodes (repeatable). Required.\n"
    "  --user U                Indexer user. Required: the client library refuses to start without credentials.\n"
    "  --password-file FILE    Read the password from the first line of FILE.\n"
    "  --password P            The password itself. It is visible to every local user in /proc/<pid>/cmdline\n"
    "                          and in `ps`; prefer --password-file or the CM_TESTTOOL_PASSWORD variable.\n"
    "                          With neither option, the password is read from CM_TESTTOOL_PASSWORD.\n"
    "  --ca FILE               CA bundle to verify the indexer with (repeatable).\n"
    "  --cert FILE --key FILE  Client certificate and key.\n"
    "  --index NAME            Content index (repeatable; default .wazuh-threatintel-vulnerabilities).\n"
    "  --readiness-index NAME --readiness-id ID\n"
    "                          Consumer document that gates the download.\n"
    "  --state-dir DIR         RocksDB state directory (default /tmp/content_updater/rocksdb).\n"
    "  --full                  Request a full reload instead of an incremental cycle.\n"
    "  --timeout S             Seconds to wait for the requested cycle, 1-86400 (default 120).\n"
    "  --help                  Print this help and exit 0.\n";

struct ToolOptions
{
    std::vector<std::string> hosts;
    std::string user;
    std::string password;
    std::vector<std::string> certificateAuthorities;
    std::string certificate;
    std::string key;
    std::vector<std::string> indices;
    std::string readinessIndex;
    std::string readinessId;
    std::string stateDir {"/tmp/content_updater/rocksdb"};
    bool fullReload {false};
    std::chrono::seconds timeout {120};
    bool help {false};
};

/// @return The first line of @p path, without its line terminator.
static std::string readPasswordFile(const std::string& path)
{
    std::ifstream file {path};
    if (!file)
    {
        throw std::invalid_argument("cannot read --password-file " + path);
    }
    std::string line;
    std::getline(file, line);
    if (!line.empty() && line.back() == '\r')
    {
        line.pop_back();
    }
    if (line.empty())
    {
        throw std::invalid_argument("--password-file " + path + " has an empty first line");
    }
    return line;
}

/// @return @p text as a timeout, refused unless it is a plain decimal in [MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS].
static std::chrono::seconds parseTimeout(const std::string& text)
{
    const auto invalid = [&]
    {
        return std::invalid_argument("--timeout must be an integer between " + std::to_string(MIN_TIMEOUT_SECONDS) +
                                     " and " + std::to_string(MAX_TIMEOUT_SECONDS) + " seconds, got '" + text + "'");
    };
    // stoul() accepts a sign and wraps "-1" around, so only digits get that far.
    if (text.empty() || text.size() > 6 || text.find_first_not_of("0123456789") != std::string::npos)
    {
        throw invalid();
    }
    const auto seconds = std::stoul(text);
    if (seconds < MIN_TIMEOUT_SECONDS || seconds > MAX_TIMEOUT_SECONDS)
    {
        throw invalid();
    }
    return std::chrono::seconds {seconds};
}

static std::vector<std::string> splitList(const std::string& value)
{
    std::vector<std::string> items;
    std::stringstream stream {value};
    std::string item;
    while (std::getline(stream, item, ','))
    {
        if (!item.empty())
        {
            items.push_back(item);
        }
    }
    return items;
}

static ToolOptions parseArgs(int argc, char* argv[])
{
    ToolOptions options;
    std::optional<std::string> password;
    std::optional<std::string> passwordFile;
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg {argv[i]};
        const auto value = [&]() -> std::string
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("missing value for " + arg);
            }
            return argv[++i];
        };

        if (arg == "--help" || arg == "-h")
        {
            options.help = true;
            return options;
        }
        if (arg == "--hosts")
        {
            for (auto& host : splitList(value()))
            {
                options.hosts.push_back(std::move(host));
            }
        }
        else if (arg == "--user")
        {
            options.user = value();
        }
        else if (arg == "--password")
        {
            password = value();
        }
        else if (arg == "--password-file")
        {
            passwordFile = value();
        }
        else if (arg == "--ca")
        {
            options.certificateAuthorities.push_back(value());
        }
        else if (arg == "--cert")
        {
            options.certificate = value();
        }
        else if (arg == "--key")
        {
            options.key = value();
        }
        else if (arg == "--index")
        {
            options.indices.push_back(value());
        }
        else if (arg == "--readiness-index")
        {
            options.readinessIndex = value();
        }
        else if (arg == "--readiness-id")
        {
            options.readinessId = value();
        }
        else if (arg == "--state-dir")
        {
            options.stateDir = value();
        }
        else if (arg == "--full")
        {
            options.fullReload = true;
        }
        else if (arg == "--timeout")
        {
            options.timeout = parseTimeout(value());
        }
        else
        {
            throw std::invalid_argument("unknown argument " + arg);
        }
    }

    if (options.hosts.empty())
    {
        throw std::invalid_argument("--hosts is required");
    }
    if (options.user.empty())
    {
        throw std::invalid_argument("--user is required");
    }
    if (password && passwordFile)
    {
        throw std::invalid_argument("--password and --password-file are mutually exclusive");
    }
    if (passwordFile)
    {
        options.password = readPasswordFile(*passwordFile);
    }
    else if (password)
    {
        options.password = *password;
    }
    else if (const char* const fromEnv = std::getenv(PASSWORD_ENV); fromEnv != nullptr && *fromEnv != '\0')
    {
        options.password = fromEnv;
    }
    else
    {
        throw std::invalid_argument(std::string("a password is required: --password-file FILE, ") + PASSWORD_ENV +
                                    " or --password P");
    }
    if (options.readinessIndex.empty() != options.readinessId.empty())
    {
        throw std::invalid_argument("--readiness-index and --readiness-id go together");
    }
    if (options.indices.empty())
    {
        options.indices.emplace_back(".wazuh-threatintel-vulnerabilities");
    }
    return options;
}

/// The registration, built the way a host builds one (D2).
static content_manager::TopicSpec topicSpec(const ToolOptions& options)
{
    content_manager::TopicSpec spec;
    spec.schedule.intervalSeconds = 30;
    spec.source.indices = options.indices;
    if (!options.readinessIndex.empty())
    {
        spec.readiness = content_manager::Readiness {options.readinessIndex, options.readinessId};
    }
    spec.detection = content_manager::CursorDetection {};
    spec.state.databasePath = options.stateDir;
    return spec;
}

/// The <indexer> section the runtime parses: hosts and, when given, the TLS material.
static std::string indexerSection(const ToolOptions& options)
{
    nlohmann::json section {{"hosts", options.hosts}};
    nlohmann::json ssl = nlohmann::json::object();
    if (!options.certificateAuthorities.empty())
    {
        ssl["certificate_authorities"] = options.certificateAuthorities;
    }
    if (!options.certificate.empty())
    {
        ssl["certificate"] = options.certificate;
    }
    if (!options.key.empty())
    {
        ssl["key"] = options.key;
    }
    if (!ssl.empty())
    {
        section["ssl"] = std::move(ssl);
    }
    return section.dump();
}

// Enable/Disable logging verbosity.
static const auto VERBOSE {true};

/**
 * @brief Log function callback used on the Content Manager test tool.
 *
 * @param logLevel Log level.
 * @param tag Log tag.
 * @param file File from where the logger is called.
 * @param line Line from where the logger is called.
 * @param func Function from where the logger is called.
 * @param message Message to log.
 * @param args Message arguments.
 */
void logFunction(const int logLevel,
                 const char* tag,
                 const char* file,
                 const int line,
                 const char* func,
                 const char* message,
                 va_list args)
{
    auto pos {std::string(file).find_last_of('/')};
    if (pos != std::string::npos)
    {
        pos++;
    }
    const auto fileName {std::string(file).substr(pos, std::string(file).size() - pos)};

    // Set log level tag.
    static const std::map<int, std::string> LOG_LEVEL_TAGS {{Log::LOGLEVEL_DEBUG_VERBOSE, "DEBUG_VERBOSE"},
                                                            {Log::LOGLEVEL_DEBUG, "DEBUG"},
                                                            {Log::LOGLEVEL_INFO, "INFO"},
                                                            {Log::LOGLEVEL_WARNING, "WARNING"},
                                                            {Log::LOGLEVEL_ERROR, "ERROR"},
                                                            {Log::LOGLEVEL_CRITICAL, "CRITICAL"}};
    const auto levelTag {"[" + LOG_LEVEL_TAGS.at(logLevel) + "]"};

    constexpr std::size_t LOG_BUFFER_SIZE {65536};
    char formattedStr[LOG_BUFFER_SIZE] = {0};
    vsnprintf(formattedStr, LOG_BUFFER_SIZE, message, args);

    if (logLevel == Log::LOGLEVEL_ERROR || logLevel == Log::LOGLEVEL_CRITICAL)
    {
        // Error logs.
        std::cerr << tag << ":" << levelTag << ": " << formattedStr << std::endl;
    }
    else if (logLevel == Log::LOGLEVEL_INFO || logLevel == Log::LOGLEVEL_WARNING)
    {
        // Info and warning logs.
        std::cout << tag << ":" << levelTag << ": " << formattedStr << std::endl;
    }
    else
    {
        // Debug logs.
        if (VERBOSE)
        {
            std::cout << tag << ":" << levelTag << ":" << fileName << ":" << line << " " << func << ": " << formattedStr
                      << std::endl;
        }
    }
}

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

/**
 * @brief A sink that accepts everything and prints what it was given.
 */
class PrintingSink final : public content_manager::IContentSink
{
public:
    content_manager::SessionDecision beginSession(const content_manager::SessionInfo& info) noexcept override
    {
        std::cout << "beginSession topic=" << info.topic << " kind=" << static_cast<int>(info.kind) << " remoteToken='"
                  << info.remoteToken << "'" << std::endl;
        return content_manager::SessionDecision::Proceed;
    }

    content_manager::PageAck acceptPage(const content_manager::ContentPage& page) noexcept override
    {
        std::cout << "acceptPage hits=" << (page.hits != nullptr ? page.hits->size() : 0) << " token='"
                  << page.pageToken << "'" << std::endl;
        return content_manager::PageAck {content_manager::PageStatus::Durable, {}};
    }

    content_manager::CommitResult commit(const content_manager::CommitInfo& info) noexcept override
    {
        std::cout << "commit topic=" << info.topic << " documents=" << info.documentsDelivered << " finalToken='"
                  << info.finalToken << "'" << std::endl;
        return content_manager::CommitResult {content_manager::CommitStatus::Committed, {}};
    }

    void abort(content_manager::AbortReason reason, const std::string& detail) noexcept override
    {
        std::cout << "abort reason=" << static_cast<int>(reason) << " detail=" << detail << std::endl;
    }

    void cycleFinished(const content_manager::CycleOutcome& outcome) noexcept override
    {
        std::cout << "cycleFinished status=" << static_cast<int>(outcome.status) << " token='" << outcome.token
                  << "' detail=" << outcome.detail << std::endl;
    }
};

int main(int argc, char* argv[])
{
    ToolOptions options;
    try
    {
        options = parseArgs(argc, argv);
    }
    catch (const std::exception& e)
    {
        std::cerr << "content_manager_test_tool: " << e.what() << std::endl << USAGE;
        return 2;
    }
    if (options.help)
    {
        std::cout << USAGE;
        return EXIT_SUCCESS;
    }

    content_manager::setLogFunction(logFunction, "content-manager-testtool");
    // Installed before start(): the library ignores a log function set while a runtime runs.
    indexer_client::setLogFunction(logFunction);

    auto exitCode {EXIT_FAILURE};
    try
    {
        auto source = indexer_client::KeyValueConfigSource::parse(
            "", indexerSection(options), indexer_client::Credentials {options.user, options.password});
        if (!source.ok())
        {
            throw std::runtime_error("invalid indexer client configuration (" +
                                     std::string(indexer_client::toString(source.cause)) + "): " + source.reason);
        }
        auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
        if (!started.ok())
        {
            throw std::runtime_error("could not start the indexer client runtime (" +
                                     std::string(indexer_client::toString(started.cause)) + "): " + started.reason);
        }

        // A read-only consumer: no buckets, only the query handle the adapter uses.
        auto client = started.value.client(CONSUMER_NAME, {});
        if (!client.ok() || !client.value)
        {
            throw std::runtime_error("the indexer client refused the consumer (" +
                                     std::string(indexer_client::toString(client.cause)) + "): " + client.reason);
        }

        {
            ContentRegister registerer {TOPIC_NAME,
                                        topicSpec(options),
                                        std::make_shared<PrintingSink>(),
                                        content_manager::makeContentIndexer(client.value)};

            // The driver thread runs a cycle at start; a request made while it runs is answered AlreadyRunning, so
            // retry until the request itself ran or the timeout expires.
            const auto deadline = std::chrono::steady_clock::now() + options.timeout;
            std::optional<content_manager::OnDemandResult> outcome;
            while (std::chrono::steady_clock::now() < deadline)
            {
                // Shared: on a timeout the registration's destructor still answers the request (ShuttingDown).
                auto requested = std::make_shared<std::promise<content_manager::OnDemandResult>>();
                auto result = requested->get_future();
                registerer.requestRun(content_manager::RunRequest {options.fullReload},
                                      [requested](content_manager::OnDemandResult answer)
                                      { requested->set_value(std::move(answer)); });
                if (result.wait_until(deadline) != std::future_status::ready)
                {
                    break;
                }
                outcome = result.get();
                if (outcome->code != content_manager::OnDemandCode::AlreadyRunning)
                {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (outcome)
            {
                std::cout << "requested cycle: code=" << static_cast<int>(outcome->code)
                          << " detail=" << outcome->detail << std::endl;
                exitCode = outcome->code == content_manager::OnDemandCode::Completed ? EXIT_SUCCESS : EXIT_FAILURE;
            }
            else
            {
                std::cout << "requested cycle: no result within " << options.timeout.count() << " s" << std::endl;
            }
            std::cout << "current token: '" << registerer.currentToken() << "'" << std::endl;

            // The host's obligation: close the Client's admission before stopping the registration, so a call in
            // flight returns at once instead of at its deadline.
            client.value->requestClose();
        }
        client.value.reset();
    }
    catch (const std::exception& e)
    {
        std::cout << "Exception: " << e.what() << std::endl;
        exitCode = EXIT_FAILURE;
    }

    if (indexer_client::RuntimeOwner::running())
    {
        indexer_client::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + std::chrono::seconds(5));
        indexer_client::RuntimeOwner::shutdown();
    }
    return exitCode;
}
