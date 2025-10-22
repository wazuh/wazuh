#include "cmdArgParser.hpp"
#include "logging_helper.h"
#include <indexerConnector.hpp>
#include <iomanip>
#include <iostream>
#include <random>

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

        // --- Create IndexerConnector ---
        IndexerConnector indexerConnector(
            configuration,
            cmdArgParser.getTemplateFilePath(),
            cmdArgParser.getUpdateMappingsFilePath(),
            true, // Use seek for delete operation
            [&logFile](const int logLevel,
                       const std::string& tag,
                       const std::string& file,
                       const int line,
                       const std::string& func,
                       const std::string& message,
                       va_list args)
            {
                auto pos = file.find_last_of('/');
                std::string fileName;
                if (pos != std::string::npos)
                {
                    fileName = file.substr(pos + 1);
                }
                else
                {
                    fileName = file;
                }

                char formattedStr[MAX_LEN] = {0};
                vsnprintf(formattedStr, MAX_LEN, message.c_str(), args);

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
        // Publish or autogenerate events BEFORE running sync
        if (!cmdArgParser.getEventsFilePath().empty())
        {
            std::ifstream eventsFile(cmdArgParser.getEventsFilePath());
            if (!eventsFile.is_open())
            {
                throw std::runtime_error("Could not open events file.");
            }

            const auto events = nlohmann::json::parse(eventsFile);
            if (events.is_array())
            {
                for (const auto& event : events)
                {
                    indexerConnector.publish(event.dump());
                }
            }
            else
            {
                indexerConnector.publish(events.dump());
            }
        }
        else if (cmdArgParser.getAutoGenerated())
        {
            const auto eventsNumber = cmdArgParser.getNumberOfEvents();

            std::ifstream templateFile(cmdArgParser.getTemplateFilePath());
            if (!templateFile.is_open())
            {
                throw std::runtime_error("Could not open template file.");
            }

            nlohmann::json templateData;
            templateFile >> templateData;

            if (eventsNumber == 0)
            {
                throw std::runtime_error("Number of events must be greater than 0.");
            }

            for (size_t i = 0; i < eventsNumber; ++i)
            {
                nlohmann::json randomData =
                    fillWithRandomData(templateData.at("template").at("mappings").at("properties"));

                nlohmann::json event;
                event["id"] = generateRandomString(20);
                event["operation"] = "INSERT";
                event["data"] = std::move(randomData);

                indexerConnector.publish(event.dump());
            }
        }

        // Trigger sync AFTER publishing
        if (!cmdArgParser.getAgentIdSyncEvent().empty())
        {
            const auto agentId = cmdArgParser.getAgentIdSyncEvent();
            const int loopCount = cmdArgParser.getLoopSyncCount();
            const int loopDelaySeconds = cmdArgParser.getLoopDelaySeconds(); // NEW PARAMETER

            if (loopCount > 0)
            {
                std::this_thread::sleep_for(std::chrono::seconds(10)); // Wait for events to be published
                std::cerr << "Running " << loopCount << " sync() calls for agent '" << agentId << "' with "
                          << loopDelaySeconds << "s delay between calls\n";

                for (int i = 0; i < loopCount; ++i)
                {
                    std::cerr << "Sync call " << (i + 1) << "/" << loopCount << "\n";
                    indexerConnector.sync(agentId);

                    if (i < loopCount - 1) // Don't sleep after last iteration
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(loopDelaySeconds));
                    }
                }
            }
            else
            {
                indexerConnector.sync(agentId);
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
