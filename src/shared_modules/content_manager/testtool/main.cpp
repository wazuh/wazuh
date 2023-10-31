#include "contentManager.hpp"
#include "contentRegister.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "utils/timeHelper.h"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

/*
 * @brief Configuration parameters for the content provider.
 *
 * @topicName: Name of the topic.
 * @interval: Interval in seconds to execute the content provider.
 * @ondemand: If true, the content provider will be executed on demand.
 * @createDatabase: If true, the RocksDB database will be initialized automatically. If false, the database is assumed
 * to be already initialized.
 * @initialOffset: Offset to be inserted in the database. Only used when @createDatabase is true.
 * @configData: Configuration data to create the orchestration of the content provider.
 * @contentSource: Source of the content.
 * @compressionType: Compression type of the content.
 * @versionedContent: Type of versioned content. If false, the content must not be versioned.
 * @deleteDownloadedContent: If true, the downloaded content will be deleted.
 * @url: URL where the content is located.
 * @outputFolder: if defined, the content will be downloaded to this folder.
 * @dataFormat: Format of the content downloaded or after decompression.
 * @contentFileName: Name for the downloaded file (unless using the 'offline' or 'file' contentSource).
 */
static const nlohmann::json CONFIG_PARAMETERS =
    R"(
        {
            "topicName": "test",
            "interval": 10,
            "ondemand": true,
            "createDatabase": true,
            "initialOffset": "0",
            "configData":
            {
                "contentSource": "api",
                "compressionType": "raw",
                "versionedContent": "false",
                "deleteDownloadedContent": true,
                "url": "https://jsonplaceholder.typicode.com/todos/1",
                "outputFolder": "/tmp/testProvider",
                "dataFormat": "json",
                "contentFileName": "example.json",
                "databasePath": "/tmp/content_updater/rocksdb"
            }
        }
        )"_json;

int main()
{
    if (CONFIG_PARAMETERS.at("createDatabase"))
    {
        // Create RocksDB database if needed.
        const auto& initialOffset {CONFIG_PARAMETERS.at("initialOffset").get_ref<const std::string&>()};
        const auto& databasePath {CONFIG_PARAMETERS.at("configData").at("databasePath").get_ref<const std::string&>()};

        Utils::RocksDBWrapper rocksDbConnector(databasePath);
        rocksDbConnector.put(Utils::getCompactTimestamp(std::time(nullptr)), initialOffset);
    }

    auto& instance = ContentModule::instance();

    // Server
    instance.start([](const modules_log_level_t logLevel, const std::string& message)
                   { std::cout << message << std::endl; });

    // CLiente -> vulnenability  detector
    ContentRegister registerer {CONFIG_PARAMETERS.at("topicName").get<std::string>(), CONFIG_PARAMETERS};
    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "changing interval" << std::endl;
    registerer.changeSchedulerInterval(10);
    // End client

    std::this_thread::sleep_for(std::chrono::seconds(60));

    // Stop server
    instance.stop();

    return 0;
}
