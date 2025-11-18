/*
 * Wazuh Vulnerability scanner - InventorySync Integration Test Tool
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "epollWrapper.hpp"
#include "external/nlohmann/json.hpp"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/include/inventorySync_generated.h"
#include "inventorySync.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "socketServer.hpp"
#include "vulnerabilityScannerFacade.hpp"
#include "wazuh_modules/vulnerability_scanner/src/vulnerabilityScannerFacade.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

constexpr auto MAX_LEN = 65536;
constexpr auto DEFAULT_QUEUE_PATH = "queue/sockets/queue";
constexpr auto DEFAULT_SOCKETS_PATH = "queue/sockets";

// Command line arguments structure
struct TestConfig
{
    std::string agentId;
    std::string mode;   // "full" or "delta"
    std::string option; // "VDFirst", "VDSync", "VDClean"
    std::string osDataFile;
    std::string packagesFile;
    std::string hotfixesFile;
    std::string configFile;
    uint32_t waitTime = 10; // seconds to wait after sending messages
    bool verbose = false;
};

// Simple command line parser
TestConfig parseArgs(int argc, char* argv[])
{
    TestConfig config;

    if (argc < 4)
    {
        throw std::runtime_error("Usage: " + std::string(argv[0]) +
                                 " <agent_id> <mode> <option> [--os <file>] [--packages <file>] [--hotfixes <file>] "
                                 "[--config <file>] [--wait <seconds>] [--verbose]");
    }

    config.agentId = argv[1];
    config.mode = argv[2];
    config.option = argv[3];

    for (int i = 4; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--os" && i + 1 < argc)
        {
            config.osDataFile = argv[++i];
        }
        else if (arg == "--packages" && i + 1 < argc)
        {
            config.packagesFile = argv[++i];
        }
        else if (arg == "--hotfixes" && i + 1 < argc)
        {
            config.hotfixesFile = argv[++i];
        }
        else if (arg == "--config" && i + 1 < argc)
        {
            config.configFile = argv[++i];
        }
        else if (arg == "--wait" && i + 1 < argc)
        {
            config.waitTime = std::stoul(argv[++i]);
        }
        else if (arg == "--verbose")
        {
            config.verbose = true;
        }
    }

    return config;
}

// Fake report server to capture VD alerts
class FakeReportServer
{
private:
    int m_socketServer;
    std::thread m_serverThread;
    std::atomic<bool> m_shouldStop {false};
    char m_buffer[MAX_LEN] {0};
    std::string m_path;
    struct sockaddr_un m_serverAddr {.sun_family = AF_UNIX, .sun_path = {}};
    socklen_t m_clientSize;

public:
    explicit FakeReportServer(std::string path)
        : m_path(std::move(path))
    {
        m_socketServer = socket(AF_UNIX, SOCK_DGRAM, 0);
        m_clientSize = sizeof(sockaddr_un);
    }

    ~FakeReportServer()
    {
        stop();
        waitForStop();
    }

    void start()
    {
        if (m_socketServer < 0)
        {
            throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
        }

        if (std::filesystem::exists(m_path))
        {
            std::filesystem::remove(m_path);
        }

        m_serverThread = std::thread(
            [this]()
            {
                std::snprintf(m_serverAddr.sun_path, sizeof(m_serverAddr.sun_path), "%s", m_path.c_str());

                if (bind(m_socketServer, (struct sockaddr*)&m_serverAddr, sizeof(m_serverAddr)) < 0)
                {
                    throw std::runtime_error("Failed to bind socket: " + std::string(strerror(errno)));
                }

                struct sockaddr_un clientAddr;
                socklen_t clientSize = sizeof(clientAddr);

                while (!m_shouldStop.load())
                {
                    auto bytesReceived =
                        recvfrom(m_socketServer, m_buffer, MAX_LEN - 1, 0, (struct sockaddr*)&clientAddr, &clientSize);

                    if (bytesReceived > 0)
                    {
                        m_buffer[bytesReceived] = '\0';
                        std::cout << "[ALERT] " << std::string(m_buffer, bytesReceived) << std::endl;
                    }
                }
            });
    }

    void stop()
    {
        m_shouldStop.store(true);
    }

    void waitForStop()
    {
        if (m_serverThread.joinable())
        {
            m_serverThread.join();
        }

        if (m_socketServer != -1)
        {
            close(m_socketServer);
            m_socketServer = -1;
        }

        if (std::filesystem::exists(m_path))
        {
            std::filesystem::remove(m_path);
        }
    }
};

// Message builder helpers
class MessageBuilder
{
public:
    // Build Start message
    static std::vector<uint8_t> buildStart(const std::string& agentId,
                                           Wazuh::SyncSchema::Mode mode,
                                           Wazuh::SyncSchema::Option option,
                                           uint64_t size,
                                           const std::vector<std::string>& indices)
    {
        flatbuffers::FlatBufferBuilder builder;

        // Create indices vector
        std::vector<flatbuffers::Offset<flatbuffers::String>> indexVec;
        for (const auto& idx : indices)
        {
            indexVec.push_back(builder.CreateString(idx));
        }
        auto indicesOffset = builder.CreateVector(indexVec);

        // Create Start message
        auto startBuilder = Wazuh::SyncSchema::StartBuilder(builder);
        startBuilder.add_size(size);
        startBuilder.add_mode(mode);
        startBuilder.add_option(option);
        startBuilder.add_index(indicesOffset);
        auto startOffset = startBuilder.Finish();

        auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_Start, startOffset.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    // Build DataValue message
    static std::vector<uint8_t> buildDataValue(uint64_t session,
                                               uint64_t seq,
                                               const std::string& index,
                                               const std::string& id,
                                               const std::string& jsonData,
                                               Wazuh::SyncSchema::Operation operation)
    {
        flatbuffers::FlatBufferBuilder builder;

        auto indexStr = builder.CreateString(index);
        auto idStr = builder.CreateString(id);
        auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(jsonData.data()), jsonData.size());

        auto dataBuilder = Wazuh::SyncSchema::DataValueBuilder(builder);
        dataBuilder.add_session(session);
        dataBuilder.add_seq(seq);
        dataBuilder.add_operation(operation);
        dataBuilder.add_index(indexStr);
        dataBuilder.add_id(idStr);
        dataBuilder.add_data(dataVec);
        auto dataOffset = dataBuilder.Finish();

        auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_DataValue, dataOffset.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    // Build End message
    static std::vector<uint8_t> buildEnd(uint64_t session)
    {
        flatbuffers::FlatBufferBuilder builder;

        auto endBuilder = Wazuh::SyncSchema::EndBuilder(builder);
        endBuilder.add_session(session);
        auto endOffset = endBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_End, endOffset.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }
};

// Load JSON file
nlohmann::json loadJsonFile(const std::string& filepath)
{
    if (filepath.empty() || !std::filesystem::exists(filepath))
    {
        return nlohmann::json::array();
    }

    std::ifstream file(filepath);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file: " + filepath);
    }

    return nlohmann::json::parse(file);
}

int main(int argc, char* argv[])
{
    try
    {
        // Parse command line arguments
        auto config = parseArgs(argc, argv);

        std::cout << "=== InventorySync + VD Integration Test ===" << std::endl;
        std::cout << "Agent ID: " << config.agentId << std::endl;
        std::cout << "Mode: " << config.mode << std::endl;
        std::cout << "Option: " << config.option << std::endl;

        // Initialize modules
        auto& routerModule = RouterModule::instance();
        routerModule.start();

        auto routerProvider = RouterProvider("inventory-states", true);
        routerProvider.start();

        // Setup fake report server for VD alerts
        if (!std::filesystem::exists(DEFAULT_SOCKETS_PATH))
        {
            std::filesystem::create_directories(DEFAULT_SOCKETS_PATH);
        }
        FakeReportServer fakeReportServer(DEFAULT_QUEUE_PATH);
        fakeReportServer.start();

        // Setup socket to receive session ID
        auto socketServer =
            SocketServer<Socket<OSPrimitives, AppendHeaderProtocol>, EpollWrapper>("queue/alerts/execq");
        uint64_t sessionId = 0;
        std::promise<void> promise;
        auto future = promise.get_future();

        socketServer.listen(
            [&sessionId, &promise](const int, const char* data, uint32_t size, const char*, uint32_t)
            {
                auto message = Wazuh::SyncSchema::GetMessage(data);
                if (message->content_type() == Wazuh::SyncSchema::MessageType_StartAck)
                {
                    auto startAck = message->content_as<Wazuh::SyncSchema::StartAck>();
                    sessionId = startAck->session();
                    std::cout << "[INFO] Received session ID: " << sessionId << std::endl;
                    promise.set_value();
                }
            });

        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Initialize InventorySync
        auto& inventorySync = InventorySync::instance();
        inventorySync.start(
            [&config](const int logLevel,
                      const std::string& tag,
                      const std::string& file,
                      const int line,
                      const std::string& func,
                      const std::string& message,
                      va_list args)
            {
                if (config.verbose)
                {
                    char buffer[MAX_LEN];
                    vsnprintf(buffer, sizeof(buffer), message.c_str(), args);
                    std::cout << "[" << tag << "] " << buffer << std::endl;
                }
            },
            nlohmann::json::object());

        // Initialize VulnerabilityScanner
        auto& vulnerabilityScanner = VulnerabilityScannerFacade::instance();
        nlohmann::json vdConfig;
        if (!config.configFile.empty())
        {
            vdConfig = nlohmann::json::parse(std::ifstream(config.configFile));
        }
        else
        {
            // Default config
            vdConfig = R"({
                "vulnerability_detector": {
                    "enabled": true,
                    "content_source": "cti",
                    "update_interval": 3600
                }
            })"_json;
        }

        vulnerabilityScanner.start(
            [&config](const int logLevel,
                      const char* tag,
                      const char* file,
                      const int line,
                      const char* func,
                      const char* message,
                      va_list args)
            {
                if (config.verbose)
                {
                    char buffer[MAX_LEN];
                    vsnprintf(buffer, sizeof(buffer), message, args);
                    std::cout << "[VD:" << tag << "] " << buffer << std::endl;
                }
            },
            vdConfig,
            false,
            true,
            true);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Load test data
        auto osData = loadJsonFile(config.osDataFile);
        auto packagesData = loadJsonFile(config.packagesFile);
        auto hotfixesData = loadJsonFile(config.hotfixesFile);

        // Determine mode and option
        Wazuh::SyncSchema::Mode mode =
            (config.mode == "full") ? Wazuh::SyncSchema::Mode_ModuleFull : Wazuh::SyncSchema::Mode_ModuleDelta;

        Wazuh::SyncSchema::Option option;
        if (config.option == "VDFirst")
        {
            option = Wazuh::SyncSchema::Option_VDFirst;
        }
        else if (config.option == "VDSync")
        {
            option = Wazuh::SyncSchema::Option_VDSync;
        }
        else if (config.option == "VDClean")
        {
            option = Wazuh::SyncSchema::Option_VDClean;
        }
        else
        {
            option = Wazuh::SyncSchema::Option_Sync;
        }

        // Calculate total messages
        uint64_t totalMessages = 0;
        if (!osData.empty())
            totalMessages++;
        totalMessages += packagesData.size();
        if (!hotfixesData.empty())
            totalMessages += hotfixesData.size();

        std::cout << "[INFO] Total messages to send: " << totalMessages << std::endl;

        // Build indices
        std::vector<std::string> indices;
        if (!osData.empty())
            indices.push_back("wazuh-states-inventory-system");
        if (!packagesData.empty())
            indices.push_back("wazuh-states-inventory-packages");
        if (!hotfixesData.empty())
            indices.push_back("wazuh-states-inventory-hotfixes");

        // === Step 1: Send START message ===
        std::cout << "[SEND] Start message..." << std::endl;
        auto startMsg = MessageBuilder::buildStart(config.agentId, mode, option, totalMessages, indices);
        routerProvider.send(std::vector<char>(startMsg.begin(), startMsg.end()));

        // Wait for StartAck
        if (future.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
        {
            throw std::runtime_error("Timeout waiting for StartAck");
        }

        // === Step 2: Send DATA messages ===
        uint64_t seq = 0;

        // Send OS data
        if (!osData.empty())
        {
            std::cout << "[SEND] OS data (seq=" << seq << ")..." << std::endl;
            auto msg = MessageBuilder::buildDataValue(sessionId,
                                                      seq++,
                                                      "wazuh-states-inventory-system",
                                                      config.agentId,
                                                      osData.dump(),
                                                      Wazuh::SyncSchema::Operation_Upsert);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        // Send packages data
        for (const auto& pkg : packagesData)
        {
            std::cout << "[SEND] Package data (seq=" << seq << ")..." << std::endl;

            // Determine operation from JSON or default to Upsert
            Wazuh::SyncSchema::Operation op = Wazuh::SyncSchema::Operation_Upsert;
            if (pkg.contains("operation"))
            {
                std::string opStr = pkg["operation"];
                if (opStr == "DELETED")
                    op = Wazuh::SyncSchema::Operation_Delete;
                else if (opStr == "INSERTED")
                    op = Wazuh::SyncSchema::Operation_Upsert;
            }

            auto msg = MessageBuilder::buildDataValue(sessionId,
                                                      seq++,
                                                      "wazuh-states-inventory-packages",
                                                      pkg.value("id", config.agentId + "_pkg_" + std::to_string(seq)),
                                                      pkg.dump(),
                                                      op);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        // Send hotfixes data
        for (const auto& hotfix : hotfixesData)
        {
            std::cout << "[SEND] Hotfix data (seq=" << seq << ")..." << std::endl;
            auto msg = MessageBuilder::buildDataValue(sessionId,
                                                      seq++,
                                                      "wazuh-states-inventory-hotfixes",
                                                      hotfix.value("hotfix", "KB" + std::to_string(seq)),
                                                      hotfix.dump(),
                                                      Wazuh::SyncSchema::Operation_Upsert);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        // === Step 3: Send END message ===
        std::cout << "[SEND] End message..." << std::endl;
        auto endMsg = MessageBuilder::buildEnd(sessionId);
        routerProvider.send(std::vector<char>(endMsg.begin(), endMsg.end()));

        // Wait for processing
        std::cout << "[INFO] Waiting " << config.waitTime << " seconds for processing..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(config.waitTime));

        // Cleanup
        std::cout << "[INFO] Stopping modules..." << std::endl;
        vulnerabilityScanner.stop();
        inventorySync.stop();
        fakeReportServer.stop();
        routerProvider.stop();
        routerModule.stop();

        std::cout << "[INFO] Test completed successfully!" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}
