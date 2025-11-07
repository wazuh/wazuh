#include "cmdArgParser.hpp"
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

std::string generateRandomString(size_t length)
{
    const char alphanum[] = "0123456789"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);

    std::uniform_int_distribution<> distr(0, sizeof(alphanum) - 2);

    for (size_t i = 0; i < length; ++i)
    {
        result += alphanum[distr(ENG)];
    }

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

// Generate timestamp.
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
            {
                result.merge_patch(fillWithRandomData(value));
            }
            else
            {
                result[key] = fillWithRandomData(value);
            }
        }
        else if (key == "type")
        {
            if (value.get<std::string>() == "keyword")
            {
                result = generateRandomString(10);
            }
            else if (value.get<std::string>() == "long")
            {
                result = generateRandomInt(0, 1000);
            }
            else if (value.get<std::string>() == "float")
            {
                result = generateRandomFloat(0.0, 100.0);
            }
            else if (value.get<std::string>() == "date")
            {
                result = generateTimestamp();
            }
        }
    }

    return result;
}

int main(const int argc, const char* argv[])
{
    try
    {
        CmdLineArgs cmdArgParser(argc, argv);

        // --- Read configuration file ---
        std::ifstream configurationFile(cmdArgParser.getConfigurationFilePath());
        if (!configurationFile.is_open())
        {
            throw std::runtime_error("Could not open configuration file.");
        }
        const auto configuration = nlohmann::json::parse(configurationFile);

        // --- Open log file ---
        std::ofstream logFile;
        if (!cmdArgParser.getLogFilePath().empty())
        {
            logFile.open(cmdArgParser.getLogFilePath());
            if (!logFile.is_open())
            {
                throw std::runtime_error("Failed to open log file: " + cmdArgParser.getLogFilePath());
            }
        }

        // --- Create IndexerConnectorSync ---
        IndexerConnectorSync indexerConnector(
            configuration,
            [&logFile](const int logLevel,
                       const char* tag,
                       const char* file,
                       const int line,
                       const char* func,
                       const char* message,
                       va_list args)
            {
                auto fileStr = std::string(file);
                auto pos = fileStr.find_last_of('/');
                std::string fileName;
                if (pos != std::string::npos)
                {
                    fileName = fileStr.substr(pos + 1);
                }
                else
                {
                    fileName = fileStr;
                }

                char formattedStr[MAX_LEN] = {0};
                vsnprintf(formattedStr, MAX_LEN, message, args);

                if (logLevel != LOG_ERROR)
                    std::cout << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";
                else
                    std::cerr << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";

                if (logFile.is_open())
                {
                    logFile << tag << ":" << fileName << ":" << line << " " << func << " : " << formattedStr << "\n";
                    logFile.flush();
                }
            });
        // Get index name from configuration
        std::string indexName = "wazuh-test";
        if (configuration.contains("index") && configuration["index"].is_string())
        {
            indexName = configuration["index"].get<std::string>();
        }

        // Publish or autogenerate events
        if (!cmdArgParser.getEventsFilePath().empty())
        {
            std::ifstream eventsFile(cmdArgParser.getEventsFilePath());
            if (!eventsFile.is_open())
            {
                throw std::runtime_error("Could not open events file.");
            }

            // Read events and publish them
            nlohmann::json events = nlohmann::json::parse(eventsFile);

            if (cmdArgParser.getAutoGenerated())
            {
                // Auto-generate random data based on template
                nlohmann::json templateData = events;
                const auto numberOfEvents = cmdArgParser.getNumberOfEvents();

                std::cerr << "Generating and indexing " << numberOfEvents << " events...\n";
                for (size_t i = 0; i < numberOfEvents; ++i)
                {
                    auto randomData = fillWithRandomData(templateData);
                    std::string docId = "doc-" + std::to_string(i);
                    indexerConnector.bulkIndex(docId, indexName, randomData.dump());
                }
            }
            else
            {
                // Publish events from file
                std::cerr << "Indexing " << events.size() << " events from file...\n";
                size_t idx = 0;
                for (const auto& event : events)
                {
                    std::string docId = "doc-" + std::to_string(idx++);
                    indexerConnector.bulkIndex(docId, indexName, event.dump());
                }
            }

            // Flush to ensure all events are sent
            std::cerr << "Flushing bulk operations...\n";
            indexerConnector.flush();
            std::cerr << "Done!\n";
        }

        // Run flush operations in a loop if specified
        if (cmdArgParser.getLoopSyncCount() > 0)
        {
            const auto loopCount = cmdArgParser.getLoopSyncCount();
            const auto loopDelaySeconds = cmdArgParser.getLoopDelaySeconds();

            std::cerr << "Running " << loopCount << " flush() calls with " << loopDelaySeconds
                      << "s delay between calls\n";

            for (uint64_t i = 0; i < loopCount; ++i)
            {
                std::cerr << "Flush call " << (i + 1) << "/" << loopCount << "\n";
                indexerConnector.flush();

                if (i < loopCount - 1) // Don't sleep after last iteration
                {
                    std::this_thread::sleep_for(std::chrono::seconds(loopDelaySeconds));
                }
            }
        }

        // Wait or hold interactive mode
        if (cmdArgParser.getWaitTime() > 0)
        {
            std::this_thread::sleep_for(std::chrono::seconds(cmdArgParser.getWaitTime()));
        }
        else
        {
            std::cout << "Press enter to stop the indexer connector tool... \n";
            std::cin.get();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
