#include "cmdArgParser.hpp"
#include "keyStore.hpp"
#include "logging_helper.h"
#include <chrono>
#include <indexerConnector.hpp>
#include <iomanip>
#include <iostream>
#include <random>
#include <thread>

auto constexpr MAX_LEN {65536};
static std::random_device RD;
static std::mt19937 ENG(RD());

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

// ─── Random data helpers ──────────────────────────────────────────────────────

std::string generateRandomString(size_t length)
{
    const char alphanum[] = "0123456789"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);
    std::uniform_int_distribution<> distr(0, sizeof(alphanum) - 2);
    for (size_t i = 0; i < length; ++i) result += alphanum[distr(ENG)];
    return result;
}

float generateRandomFloat(float min, float max)
{
    std::uniform_real_distribution<float> distr(min, max);
    return distr(ENG);
}

int generateRandomInt(int min, int max)
{
    std::uniform_int_distribution distr(min, max);
    return distr(ENG);
}

std::string generateTimestamp()
{
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

nlohmann::json fillWithRandomData(const nlohmann::json& templateJson)
{
    nlohmann::json result;
    for (auto& [key, value] : templateJson.items())
    {
        if (value.is_object())
        {
            if (key == "properties")
                result.merge_patch(fillWithRandomData(value));
            else
                result[key] = fillWithRandomData(value);
        }
        else if (key == "type")
        {
            const auto& typeStr = value.get<std::string>();
            if (typeStr == "keyword")
                result = generateRandomString(10);
            else if (typeStr == "long")
                result = generateRandomInt(0, 1000);
            else if (typeStr == "float")
                result = generateRandomFloat(0.0, 100.0);
            else if (typeStr == "date")
                result = generateTimestamp();
        }
    }
    return result;
}

// ─── Logging helper ───────────────────────────────────────────────────────────

using LoggingFn =
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;

LoggingFn makeLoggingFunction(std::ofstream& logFile)
{
    return [&logFile](const int logLevel,
                      const char* tag,
                      const char* file,
                      const int line,
                      const char* func,
                      const char* message,
                      va_list args)
    {
        const auto fileStr = std::string(file);
        const auto pos = fileStr.find_last_of('/');
        const auto fileName = (pos != std::string::npos) ? fileStr.substr(pos + 1) : fileStr;

        char formattedStr[MAX_LEN] = {0};
        vsnprintf(formattedStr, MAX_LEN, message, args);

        auto& stream = (logLevel == LOG_ERROR) ? std::cerr : std::cout;
        stream << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";

        if (logFile.is_open())
        {
            logFile << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";
            logFile.flush();
        }
    };
}

// ─── Credentials helper ───────────────────────────────────────────────────────

/**
 * @brief Seeds indexer credentials into the keystore from the config JSON.
 *
 * If the config contains "username" and/or "password" fields they are written
 * into the keystore (column "indexer") before any connector is constructed.
 */
void seedCredentials(const nlohmann::json& config)
{
    if (config.contains("username") && config["username"].is_string())
        Keystore::put("indexer", "username", config["username"].get<std::string>());
    if (config.contains("password") && config["password"].is_string())
        Keystore::put("indexer", "password", config["password"].get<std::string>());
}

// ─── Usage ────────────────────────────────────────────────────────────────────

void printUsage()
{
    std::cout << "\nUsage: indexer_connector_tool [<subcommand>] [options]\n"
              << "Subcommands:\n"
              << "  push-events            Push test events to an index or data stream (default)\n"
              << "  export-policy          Export all policy documents for a space to a JSON file\n"
              << "  generate-full-policy   Generate a full_policy asset (kvdbs, decoders, filters, etc.)\n"
              << "\nOmitting the subcommand defaults to push-events (legacy behaviour).\n"
              << "\nexport-policy / generate-full-policy options:\n"
              << "  -c CONFIG_FILE    Indexer configuration file (required)\n"
              << "  -s SPACE_NAME     Policy space name (required)\n"
              << "  -l OUTPUT_FILE    Output file path (default: exported_policy.json / full_policy_asset.json)\n"
              << "\nRun '<subcommand> -h' or omit subcommand and pass -h for option details.\n";
}

// ─── Subcommand: push-events ──────────────────────────────────────────────────

int runPushEvents(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);

        std::ifstream configurationFile(args.getConfigurationFilePath());
        if (!configurationFile.is_open())
            throw std::runtime_error("Could not open configuration file: " + args.getConfigurationFilePath());
        const auto configuration = nlohmann::json::parse(configurationFile);

        std::ofstream logFile;
        if (!args.getLogFilePath().empty())
        {
            logFile.open(args.getLogFilePath());
            if (!logFile.is_open())
                throw std::runtime_error("Failed to open log file: " + args.getLogFilePath());
        }

        auto loggingFunction = makeLoggingFunction(logFile);
        const bool useAsync = args.getAsyncMode();

        // Seed credentials from config JSON into the keystore before constructing any connector
        seedCredentials(configuration);

        // Multi-instance async mode: enabled when -I is given together with -m async.
        // Each instance gets its own isolated RocksDB queue: queue/indexer/tool-1, tool-2, ...
        const auto& extraConfigs = args.getExtraConfigPaths();
        if (useAsync && !extraConfigs.empty())
        {
            std::vector<std::pair<std::string, std::string>> instanceDefs; // (configPath, queueId)
            instanceDefs.push_back({args.getConfigurationFilePath(), "tool-1"});
            for (size_t i = 0; i < extraConfigs.size(); ++i)
                instanceDefs.push_back({extraConfigs[i], "tool-" + std::to_string(i + 2)});

            std::cout << "Creating " << instanceDefs.size() << " IndexerConnectorAsync instances...\n";

            std::vector<std::unique_ptr<IndexerConnectorAsync>> connectors;
            std::vector<std::string> indexNames;
            for (const auto& [cfgPath, queueId] : instanceDefs)
            {
                std::ifstream cfgFile(cfgPath);
                if (!cfgFile.is_open())
                    throw std::runtime_error("Could not open configuration file: " + cfgPath);
                const auto cfg = nlohmann::json::parse(cfgFile);

                connectors.push_back(std::make_unique<IndexerConnectorAsync>(cfg, queueId, loggingFunction));

                const std::string idxName = (cfg.contains("index") && cfg["index"].is_string())
                                                ? cfg["index"].get<std::string>()
                                                : "wazuh-test";
                indexNames.push_back(idxName);

                std::cout << "  [" << queueId << "] config=" << cfgPath << ", index=" << idxName
                          << ", queue=queue/indexer/" << queueId << "\n";
            }

            if (!args.getEventsFilePath().empty())
            {
                std::ifstream eventsFile(args.getEventsFilePath());
                if (!eventsFile.is_open())
                    throw std::runtime_error("Could not open events file: " + args.getEventsFilePath());
                const nlohmann::json events = nlohmann::json::parse(eventsFile);

                std::cerr << "Indexing " << events.size() << " events to each of " << connectors.size()
                          << " instances...\n";
                for (size_t ci = 0; ci < connectors.size(); ++ci)
                {
                    size_t idx = 0;
                    for (const auto& event : events)
                        connectors[ci]->index("doc-" + std::to_string(idx++), indexNames[ci], event.dump());
                }

                std::cout << "Waiting for all async queues to drain...\n";
                const auto waitInterval = std::chrono::milliseconds(100);
                const int timeoutMs = std::max(static_cast<int>(events.size() / 1000 * 10000), 5000);
                int cumulativeWait = 0;
                int retries = 1;
                while (true)
                {
                    size_t totalPending = 0;
                    for (const auto& c : connectors) totalPending += c->getQueueSize();
                    if (totalPending == 0)
                        break;

                    std::this_thread::sleep_for(waitInterval * retries);
                    cumulativeWait += static_cast<int>(waitInterval.count()) * retries;
                    if (cumulativeWait > timeoutMs)
                    {
                        std::cerr << "Timeout waiting for async queues. Remaining:";
                        for (size_t ci = 0; ci < connectors.size(); ++ci)
                            std::cerr << " " << instanceDefs[ci].second << "=" << connectors[ci]->getQueueSize();
                        std::cerr << "\n";
                        break;
                    }
                    ++retries;
                }
                std::cerr << "Done!\n";
            }

            if (args.getWaitTime() > 0)
                std::this_thread::sleep_for(std::chrono::seconds(args.getWaitTime()));
            else
            {
                std::cout << "Press enter to stop the indexer connector tool...\n";
                std::cin.get();
            }
            return 0;
        }

        // Single-instance mode (sync or async)
        std::unique_ptr<IndexerConnectorSync> syncConnector;
        std::unique_ptr<IndexerConnectorAsync> asyncConnector;

        if (useAsync)
        {
            std::cout << "Using Indexer Connector ASYNC implementation.\n";
            asyncConnector = std::make_unique<IndexerConnectorAsync>(configuration, "tool", loggingFunction);
        }
        else
        {
            std::cout << "Using Indexer Connector SYNC implementation.\n";
            syncConnector = std::make_unique<IndexerConnectorSync>(configuration, loggingFunction);
        }

        const std::string indexName = (configuration.contains("index") && configuration["index"].is_string())
                                          ? configuration["index"].get<std::string>()
                                          : "wazuh-test";

        if (!args.getEventsFilePath().empty())
        {
            std::ifstream eventsFile(args.getEventsFilePath());
            if (!eventsFile.is_open())
                throw std::runtime_error("Could not open events file: " + args.getEventsFilePath());
            const nlohmann::json events = nlohmann::json::parse(eventsFile);

            auto indexEvent = [&](const std::string& docId, const std::string& payload)
            {
                if (useAsync)
                    asyncConnector->index(docId, indexName, payload);
                else
                    syncConnector->bulkIndex(docId, indexName, payload);
            };

            if (args.getAutoGenerated())
            {
                const auto numberOfEvents = args.getNumberOfEvents();
                std::cerr << "Generating and indexing " << numberOfEvents << " events...\n";
                for (size_t i = 0; i < numberOfEvents; ++i)
                    indexEvent("doc-" + std::to_string(i), fillWithRandomData(events).dump());
            }
            else
            {
                std::cerr << "Indexing " << events.size() << " events from file...\n";
                size_t idx = 0;
                for (const auto& event : events) indexEvent("doc-" + std::to_string(idx++), event.dump());
            }

            if (!useAsync)
            {
                std::cerr << "Flushing bulk operations...\n";
                syncConnector->flush();
            }
            else
            {
                std::cout << "Waiting for async queue to be empty...\n";
                const auto waitInterval = std::chrono::milliseconds(100);
                const int timeoutMs = static_cast<int>(events.size() / 1000) * 10000;
                int cumulativeWait = 0;
                int retries = 1;
                while (asyncConnector->getQueueSize() > 0)
                {
                    std::this_thread::sleep_for(waitInterval * retries);
                    cumulativeWait += static_cast<int>(waitInterval.count()) * retries;
                    if (timeoutMs > 0 && cumulativeWait > timeoutMs)
                    {
                        std::cerr << "Timeout waiting for async queue. Remaining size: "
                                  << asyncConnector->getQueueSize() << "\n";
                        break;
                    }
                    ++retries;
                }
            }
            std::cerr << "Done!\n";
        }

        // Optional flush loop (sync only)
        if (args.getLoopSyncCount() > 0)
        {
            if (useAsync)
            {
                std::cerr << "Loop flush (-L) is not supported in async mode and will be ignored.\n";
            }
            else
            {
                const auto loopCount = args.getLoopSyncCount();
                const auto loopDelay = args.getLoopDelaySeconds();
                std::cerr << "Running " << loopCount << " flush() calls with " << loopDelay << "s delay...\n";
                for (uint64_t i = 0; i < loopCount; ++i)
                {
                    std::cerr << "Flush call " << (i + 1) << "/" << loopCount << "\n";
                    syncConnector->flush();
                    if (i < loopCount - 1)
                        std::this_thread::sleep_for(std::chrono::seconds(loopDelay));
                }
            }
        }

        if (args.getWaitTime() > 0)
            std::this_thread::sleep_for(std::chrono::seconds(args.getWaitTime()));
        else
        {
            std::cout << "Press enter to stop the indexer connector tool...\n";
            std::cin.get();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}

// ─── Subcommand: export-policy ─────────────────────────────────────────

int runExportPolicy(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);

        const std::string space = args.getAgentIdSyncEvent();
        if (space.empty())
            throw std::runtime_error("Space name is required: use -s <space>");

        std::ifstream configFile(args.getConfigurationFilePath());
        if (!configFile.is_open())
            throw std::runtime_error("Could not open configuration file: " + args.getConfigurationFilePath());
        const auto configuration = nlohmann::json::parse(configFile);

        std::ofstream logFile;
        auto loggingFunction = makeLoggingFunction(logFile);
        seedCredentials(configuration);
        IndexerConnectorSync connector(configuration, loggingFunction);

        const std::string outputPath = args.getLogFilePath().empty() ? "exported_policy.json" : args.getLogFilePath();
        std::ofstream out(outputPath);
        if (!out.is_open())
            throw std::runtime_error("Failed to open output file: " + outputPath);

        // Query wazuh-threatintel-policies for the given space with full pagination
        nlohmann::json searchQuery = {
            {"query", {{"bool", {{"filter", nlohmann::json::array({{{"term", {{"space.name", space}}}}})}}}}},
            {"sort", nlohmann::json::array({{{"_id", "asc"}}})},
            {"size", 1000}};

        nlohmann::json docs = nlohmann::json::array();
        connector.executeSearchQueryWithPagination("wazuh-threatintel-policies",
                                                   searchQuery,
                                                   [&docs](const nlohmann::json& response)
                                                   {
                                                       if (!response.contains("hits") ||
                                                           !response["hits"].contains("hits"))
                                                           return;
                                                       for (const auto& hit : response["hits"]["hits"])
                                                       {
                                                           if (hit.contains("_source"))
                                                               docs.push_back(hit["_source"]);
                                                       }
                                                   });

        if (docs.empty())
            std::cerr << "[export-policy] Warning: no policy documents found for space '" << space << "'\n";

        out << docs.dump(4) << "\n";
        std::cout << "[export-policy] " << docs.size() << " document(s) exported to: " << outputPath << "\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}

// ─── Subcommand: generate-full-policy ────────────────────────────────────────

int runGenerateFullPolicy(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs args(argc, argv);

        const std::string space = args.getAgentIdSyncEvent();
        if (space.empty())
            throw std::runtime_error("Space name is required: use -s <space>");

        std::ifstream configFile(args.getConfigurationFilePath());
        if (!configFile.is_open())
            throw std::runtime_error("Could not open configuration file: " + args.getConfigurationFilePath());
        const auto configuration = nlohmann::json::parse(configFile);

        std::ofstream logFile;
        auto loggingFunction = makeLoggingFunction(logFile);
        seedCredentials(configuration);
        IndexerConnectorSync connector(configuration, loggingFunction);

        const std::string outputPath = args.getLogFilePath().empty() ? "full_policy_asset.json" : args.getLogFilePath();
        std::ofstream out(outputPath);
        if (!out.is_open())
            throw std::runtime_error("Failed to open output file: " + outputPath);

        // Create a consistent PIT snapshot across all policy aliases
        const std::vector<std::string> POLICY_ALIASES = {"wazuh-threatintel-kvdbs",
                                                         "wazuh-threatintel-decoders",
                                                         "wazuh-threatintel-filters",
                                                         "wazuh-threatintel-integrations",
                                                         "wazuh-threatintel-policies"};

        auto pit = connector.createPointInTime(POLICY_ALIASES, "5m", true);
        // RAII guard to always delete the PIT
        auto pitGuard = std::unique_ptr<PointInTime, std::function<void(PointInTime*)>>(
            &pit,
            [&connector](PointInTime* p)
            {
                try
                {
                    connector.deletePointInTime(*p);
                }
                catch (const std::exception& e)
                {
                    std::cerr << "[generate-full-policy] Warning: failed to delete PIT: " << e.what() << "\n";
                }
            });

        nlohmann::json spaceFilter;
        spaceFilter["bool"]["filter"] = nlohmann::json::array();
        spaceFilter["bool"]["filter"].push_back({{"term", {{"space.name", space}}}});
        const nlohmann::json sort = nlohmann::json::array({{{"_shard_doc", "asc"}}, {{"_id", "asc"}}});

        nlohmann::json fullPolicy = {{"space", space},
                                     {"kvdbs", nlohmann::json::array()},
                                     {"decoders", nlohmann::json::array()},
                                     {"filters", nlohmann::json::array()},
                                     {"integration", nlohmann::json::array()},
                                     {"policy", nullptr}};

        std::optional<nlohmann::json> searchAfter = std::nullopt;
        bool moreHits = true;
        size_t totalRetrieved = 0;

        while (moreHits)
        {
            auto hits = connector.search(pit, 1000, spaceFilter, sort, searchAfter);

            if (!hits.contains("hits") || !hits["hits"].is_array() || hits["hits"].empty())
                break;

            const auto& hitsArray = hits["hits"];
            for (const auto& hit : hitsArray)
            {
                if (!hit.contains("_source") || !hit["_source"].contains("document"))
                    continue;

                const auto& doc = hit["_source"]["document"];
                const std::string indexName = hit.value("_index", "");

                if (indexName.find("-policies") != std::string::npos)
                    fullPolicy["policy"] = doc;
                else if (indexName.find("-kvdbs") != std::string::npos)
                    fullPolicy["kvdbs"].push_back(doc);
                else if (indexName.find("-decoders") != std::string::npos)
                    fullPolicy["decoders"].push_back(doc);
                else if (indexName.find("-filters") != std::string::npos)
                    fullPolicy["filters"].push_back(doc);
                else if (indexName.find("-integrations") != std::string::npos)
                    fullPolicy["integration"].push_back(doc);
            }

            totalRetrieved += hitsArray.size();

            // Check if there are more hits to retrieve
            size_t totalHits = 0;
            if (hits.contains("total") && hits["total"].contains("value"))
                totalHits = hits["total"]["value"].get<size_t>();
            else if (hits.contains("total") && hits["total"].is_number())
                totalHits = hits["total"].get<size_t>();

            moreHits = totalRetrieved < totalHits;
            if (moreHits)
                searchAfter = hitsArray.back().at("sort");
        }

        std::cerr << "[generate-full-policy] Retrieved " << totalRetrieved << " document(s) for space '" << space
                  << "'\n";

        out << fullPolicy.dump(4) << "\n";
        std::cout << "[generate-full-policy] Full policy asset generated at: " << outputPath << "\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}

// ─── Entry point ─────────────────────────────────────────────────────────────

int main(const int argc, const char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    const std::string first = argv[1];

    if (first == "push-events")
        return runPushEvents(argc - 1, argv + 1);
    else if (first == "export-policy")
        return runExportPolicy(argc - 1, argv + 1);
    else if (first == "generate-full-policy")
        return runGenerateFullPolicy(argc - 1, argv + 1);
    else if (first == "-h" || first == "--help")
    {
        printUsage();
        return 0;
    }
    else if (first[0] == '-')
    {
        // Backward-compatible: no subcommand given, treat all args as push-events
        return runPushEvents(argc, argv);
    }

    std::cerr << "Unknown subcommand: " << first << "\n";
    printUsage();
    return 1;
}
