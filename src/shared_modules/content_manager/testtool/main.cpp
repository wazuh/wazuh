#include "contentManager.hpp"
#include "contentOnDemand.hpp"
#include "contentRegister.hpp"
#include "contentSink.hpp"
#include "contentTypes.hpp"
#include "defs.h"
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <thread>

/*
 * Test tool for the Content Manager.
 *
 * Registers one topic against a live Wazuh Indexer, lets the library's driver thread run a couple
 * of cycles, then triggers one on-demand update through the same seam a host's HTTP route
 * dispatches into. The sink below only prints what it is given, which makes this the shortest way
 * to see the exact shape of the delivery contract.
 */
static const nlohmann::json CONFIG_PARAMETERS =
    R"(
        {
            "topicName": "test",
            "interval": 30,
            "ondemand": true,
            "configData":
            {
                "consumerName": "ContentManagerTestTool",
                "changeDetection": "cursor",
                "databasePath": "/tmp/content_updater/rocksdb",
                "indexer":
                {
                    "hosts": ["https://localhost:9200"],
                    "username": "admin",
                    "password": "admin",
                    "index": ".wazuh-threatintel-vulnerabilities",
                    "consumerStatusIndex": ".wazuh-cti-consumers",
                    "consumerStatusId": "cti:catalog:consumer:vulnerabilities",
                    "cursorField": "offset",
                    "pageSize": 100,
                    "numSlices": 1
                }
            }
        }
        )"_json;

// Enable/Disable logging verbosity.
static const auto VERBOSE {true};

// Enable/Disable the forced full-reload on-demand request.
static const auto FORCE_FULL_RELOAD {false};

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
    static const std::map<int, std::string> LOG_LEVEL_TAGS {{LOGLEVEL_DEBUG_VERBOSE, "DEBUG_VERBOSE"},
                                                            {LOGLEVEL_DEBUG, "DEBUG"},
                                                            {LOGLEVEL_INFO, "INFO"},
                                                            {LOGLEVEL_WARNING, "WARNING"},
                                                            {LOGLEVEL_ERROR, "ERROR"},
                                                            {LOGLEVEL_CRITICAL, "CRITICAL"}};
    const auto levelTag {"[" + LOG_LEVEL_TAGS.at(logLevel) + "]"};

    char formattedStr[OS_MAXSTR] = {0};
    vsnprintf(formattedStr, OS_MAXSTR, message, args);

    if (logLevel == LOGLEVEL_ERROR || logLevel == LOGLEVEL_CRITICAL)
    {
        // Error logs.
        std::cerr << tag << ":" << levelTag << ": " << formattedStr << std::endl;
    }
    else if (logLevel == LOGLEVEL_INFO || logLevel == LOGLEVEL_WARNING)
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
        std::cout << "beginSession topic=" << info.topic << " kind=" << static_cast<int>(info.kind)
                  << " localToken='" << info.localToken << "' remoteToken='" << info.remoteToken
                  << "' onDemand=" << info.onDemand << std::endl;
        return content_manager::SessionDecision::Proceed;
    }

    content_manager::PageAck acceptPage(const content_manager::ContentPage& page) noexcept override
    {
        std::cout << "acceptPage slice=" << page.sliceId << " index=" << page.pageIndex
                  << " hits=" << (page.hits != nullptr ? page.hits->size() : 0) << " token='" << page.pageToken << "'"
                  << std::endl;
        return content_manager::PageAck {content_manager::PageStatus::Durable, {}};
    }

    content_manager::CommitResult commit(const content_manager::CommitInfo& info) noexcept override
    {
        std::cout << "commit topic=" << info.topic << " documents=" << info.documentsDelivered << " finalToken='"
                  << info.finalToken << "' changed=" << info.changed << std::endl;
        return content_manager::CommitResult {content_manager::CommitStatus::Committed, {}};
    }

    void abort(content_manager::AbortReason reason, const std::string& detail) noexcept override
    {
        std::cout << "abort reason=" << static_cast<int>(reason) << " detail=" << detail << std::endl;
    }
};

int main()
{
    auto& instance = ContentModule::instance();
    instance.start(logFunction);

    try
    {
        const auto topicName = CONFIG_PARAMETERS.at("topicName").get<std::string>();
        ContentRegister registerer {topicName, CONFIG_PARAMETERS, std::make_shared<PrintingSink>()};

        std::this_thread::sleep_for(std::chrono::seconds(5));

        content_manager::requestOnDemand(topicName,
                                         content_manager::RunRequest {FORCE_FULL_RELOAD, true},
                                         [](content_manager::OnDemandResult result)
                                         {
                                             std::cout << "on-demand result: code=" << static_cast<int>(result.code)
                                                       << " detail=" << result.detail << std::endl;
                                         });

        std::this_thread::sleep_for(std::chrono::seconds(60));

        std::cout << "current token: '" << registerer.currentToken() << "'" << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cout << "Exception: " << e.what() << std::endl;
    }

    instance.stop();

    return 0;
}
