/*
 * Wazuh Vulnerability scanner - InventorySync Integration Test Tool
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "external/nlohmann/json.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "inventorySync.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "scanContext.hpp"
#include "vulnerabilityScannerFacade.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <thread>
#include <vector>

constexpr auto MAX_LEN = 65536;
constexpr auto DEFAULT_QUEUE_PATH = "queue/sockets/queue";
constexpr auto DEFAULT_SOCKETS_PATH = "queue/sockets";

constexpr auto ARQUEUE = "queue/alerts/ar";
constexpr auto IS_TOPIC = "inventory-states";
constexpr auto MIN_ARGS = 4;

/**
 * @brief Struct to hold test configuration
 */
struct TestConfig
{
    std::string agentId;
    std::string mode;       ///< "full" or "delta"
    std::string option;     ///< "VDFirst", "VDSync", "VDClean"
    std::string inputFile;  ///< JSON file with agent data
    std::string configFile; ///< VD configuration file
    uint32_t waitTime = 30; ///< seconds to wait after sending messages
    bool verbose = false;   ///< verbose logging
};

/**
 * @brief Struct to hold agent test data in the new format
 */
struct AgentTestData
{
    std::string scanType;                     ///< Scan type (VDFirst, VDSync, VDClean)
    std::string agentId;                      ///< Agent identifier
    std::vector<nlohmann::json> dataValues;   ///< Array of data_values
    std::vector<nlohmann::json> dataContexts; ///< Array of data_context

    /**
     * @brief Load agent test data from JSON file (new format)
     *
     * Expected format:
     * {
     *   "type": "VDSync",
     *   "agent": {"id": "001"},
     *   "data_values": [
     *     {
     *       "operation": "upsert|delete",
     *       "payload": {
     *         "_index": "wazuh-states-inventory-packages",
     *         "_id": "...",
     *         "_source": { ... actual package/os/hotfix data ... }
     *       }
     *     }
     *   ],
     *   "data_context": [
     *     {
     *       "payload": {
     *         "_index": "wazuh-states-inventory-packages",
     *         "_source": { ... }
     *       }
     *     }
     *   ]
     * }
     */
    static AgentTestData loadFromFile(const std::string& filepath)
    {
        AgentTestData data;

        if (!std::filesystem::exists(filepath))
        {
            throw std::runtime_error("Input file not found: " + filepath);
        }

        std::ifstream file(filepath);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open file: " + filepath);
        }

        nlohmann::json root = nlohmann::json::parse(file);

        // Extract metadata
        data.scanType = root.value("type", "VDSync");
        data.agentId = root.value("agent", nlohmann::json::object()).value("id", "000");

        // Extract data_values array
        if (root.contains("data_values") && root["data_values"].is_array())
        {
            data.dataValues = root["data_values"].get<std::vector<nlohmann::json>>();
        }

        // Extract data_context array
        if (root.contains("data_context") && root["data_context"].is_array())
        {
            data.dataContexts = root["data_context"].get<std::vector<nlohmann::json>>();
        }

        return data;
    }
};

/**
 * @brief Lightweight fake report server for capturing VD alerts during integration tests.
 *
 * This test component simulates the Wazuh manager's alert-receiver socket.
 * It binds to a UNIX datagram socket and prints every alert message received.
 */
class FakeReportServer
{
private:
    int m_socketServer = -1;
    std::thread m_serverThread;
    std::atomic<bool> m_shouldStop {false};
    std::string m_path;

public:
    explicit FakeReportServer(std::string path)
        : m_path(std::move(path))
    {
        m_socketServer = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (m_socketServer < 0)
        {
            throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
        }
    }

    ~FakeReportServer()
    {
        stop();
        waitForStop();
    }

    void start()
    {
        if (std::filesystem::exists(m_path))
        {
            std::filesystem::remove(m_path);
        }

        m_serverThread = std::thread(
            [this]()
            {
                struct sockaddr_un serverAddr
                {
                };
                serverAddr.sun_family = AF_UNIX;
                std::snprintf(serverAddr.sun_path, sizeof(serverAddr.sun_path), "%s", m_path.c_str());

                if (bind(m_socketServer, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
                {
                    throw std::runtime_error("Failed to bind socket: " + std::string(strerror(errno)));
                }

                char buffer[MAX_LEN];
                struct sockaddr_un clientAddr
                {
                };
                socklen_t clientSize = sizeof(clientAddr);

                while (!m_shouldStop.load())
                {
                    auto bytesReceived =
                        recvfrom(m_socketServer, buffer, MAX_LEN - 1, 0, (struct sockaddr*)&clientAddr, &clientSize);

                    if (bytesReceived > 0)
                    {
                        buffer[bytesReceived] = '\0';
                        std::cout << "[ALERT] " << std::string(buffer, bytesReceived) << std::endl;
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

        if (m_socketServer >= 0)
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

/**
 * @brief Response server for receiving StartAck/EndAck/ReqRet messages.
 */
class ResponseServer
{
private:
    int m_socketFd = -1;
    std::thread m_serverThread;
    std::atomic<bool> m_shouldStop {false};
    std::string m_path;

    uint64_t& m_sessionId;
    std::promise<void>& m_startAckPromise;
    std::promise<void>& m_endAckPromise;
    std::atomic<bool>& m_receivedStartAck;
    std::atomic<bool>& m_receivedEndAck;
    bool m_verbose;

public:
    ResponseServer(std::string path,
                   uint64_t& sessionId,
                   std::promise<void>& startAckPromise,
                   std::promise<void>& endAckPromise,
                   std::atomic<bool>& receivedStartAck,
                   std::atomic<bool>& receivedEndAck,
                   bool verbose = false)
        : m_path(std::move(path))
        , m_sessionId(sessionId)
        , m_startAckPromise(startAckPromise)
        , m_endAckPromise(endAckPromise)
        , m_receivedStartAck(receivedStartAck)
        , m_receivedEndAck(receivedEndAck)
        , m_verbose(verbose)
    {
        m_socketFd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (m_socketFd < 0)
        {
            throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
        }
    }

    ~ResponseServer()
    {
        stop();
        waitForStop();
    }

    void start()
    {
        if (std::filesystem::exists(m_path))
        {
            std::filesystem::remove(m_path);
        }

        m_serverThread = std::thread(
            [this]()
            {
                struct sockaddr_un serverAddr
                {
                };
                serverAddr.sun_family = AF_UNIX;
                std::snprintf(serverAddr.sun_path, sizeof(serverAddr.sun_path), "%s", m_path.c_str());

                if (bind(m_socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
                {
                    throw std::runtime_error("Failed to bind socket to " + m_path + ": " +
                                             std::string(strerror(errno)));
                }

                std::cout << "[INFO] Response server listening on " << m_path << std::endl;

                char buffer[MAX_LEN];
                struct sockaddr_un clientAddr
                {
                };
                socklen_t clientSize = sizeof(clientAddr);

                while (!m_shouldStop.load())
                {
                    ssize_t bytesReceived =
                        recvfrom(m_socketFd, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddr, &clientSize);

                    if (bytesReceived > 0)
                    {
                        handleMessage(buffer, bytesReceived);
                    }
                    else if (bytesReceived < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        if (!m_shouldStop.load())
                        {
                            std::cerr << "[ERROR] recvfrom error: " << strerror(errno) << std::endl;
                        }
                        break;
                    }
                }
            });
    }

    void stop()
    {
        m_shouldStop.store(true);
        if (m_socketFd >= 0)
        {
            shutdown(m_socketFd, SHUT_RDWR);
        }
    }

    void waitForStop()
    {
        if (m_serverThread.joinable())
        {
            m_serverThread.join();
        }

        if (m_socketFd >= 0)
        {
            close(m_socketFd);
            m_socketFd = -1;
        }

        if (std::filesystem::exists(m_path))
        {
            std::filesystem::remove(m_path);
        }
    }

private:
    void handleMessage(const char* data, size_t size)
    {
        try
        {
            std::string_view messageView(data, size);

            if (messageView.starts_with("(msg_to_agent)"))
            {
                handleManagerMessage(data, size);
            }
            else
            {
                handleFlatBufferMessage(data, size);
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "[ERROR] Exception handling message: " << e.what() << std::endl;
        }
    }

    void handleManagerMessage(const char* data, size_t size)
    {
        std::string_view messageView(data, size);

        size_t syncPos = messageView.find("_sync ");
        if (syncPos == std::string_view::npos)
        {
            std::cerr << "[ERROR] No '_sync ' marker in manager message" << std::endl;
            return;
        }

        size_t sizeEnd = messageView.rfind(' ', syncPos - 1);
        size_t sizeStart = messageView.rfind(' ', sizeEnd - 1);
        std::string sizeStr(messageView.substr(sizeStart + 1, sizeEnd - sizeStart - 1));
        size_t expectedFbSize = std::stoull(sizeStr);

        size_t fbStart = syncPos + 7;

        if (fbStart >= size)
        {
            std::cerr << "[ERROR] No FlatBuffer payload after '_sync '" << std::endl;
            return;
        }

        const uint8_t* fbData = reinterpret_cast<const uint8_t*>(data + fbStart);
        size_t fbSize = std::min(expectedFbSize, size - fbStart);

        if (m_verbose)
        {
            std::cout << "[DEBUG] Manager message - Expected FB size: " << expectedFbSize << ", Actual: " << fbSize
                      << " bytes" << std::endl;
        }

        handleFlatBufferMessage(reinterpret_cast<const char*>(fbData), fbSize);
    }

    void handleFlatBufferMessage(const char* data, size_t size)
    {
        flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(data), size);
        if (!Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
        {
            std::cerr << "[ERROR] Invalid FlatBuffer message" << std::endl;
            return;
        }

        auto message = Wazuh::SyncSchema::GetMessage(data);

        switch (message->content_type())
        {
            case Wazuh::SyncSchema::MessageType_StartAck: handleStartAck(message->content_as_StartAck()); break;
            case Wazuh::SyncSchema::MessageType_EndAck: handleEndAck(message->content_as_EndAck()); break;
            case Wazuh::SyncSchema::MessageType_ReqRet: handleReqRet(message->content_as_ReqRet()); break;
            default:
                std::cout << "[WARN] Unknown message type: " << static_cast<int>(message->content_type()) << std::endl;
        }
    }

    void handleStartAck(const Wazuh::SyncSchema::StartAck* startAck)
    {
        m_sessionId = startAck->session();

        std::cout << "[INFO] ✓ StartAck received" << std::endl;
        std::cout << "       Session: " << m_sessionId << std::endl;
        std::cout << "       Status: " << static_cast<int>(startAck->status()) << std::endl;

        if (!m_receivedStartAck.exchange(true))
        {
            try
            {
                m_startAckPromise.set_value();
            }
            catch (const std::future_error&)
            {
            }
        }
    }

    void handleEndAck(const Wazuh::SyncSchema::EndAck* endAck)
    {
        std::cout << "[INFO] ✓ EndAck received" << std::endl;
        std::cout << "       Session: " << endAck->session() << std::endl;
        std::cout << "       Status: " << static_cast<int>(endAck->status()) << std::endl;

        if (!m_receivedEndAck.exchange(true))
        {
            try
            {
                m_endAckPromise.set_value();
            }
            catch (const std::future_error&)
            {
            }
        }
    }

    void handleReqRet(const Wazuh::SyncSchema::ReqRet* reqRet)
    {
        std::cout << "[INFO] ✓ ReqRet received - Session: " << reqRet->session();
        if (reqRet->seq())
        {
            std::cout << ", Missing ranges: " << reqRet->seq()->size();
        }
        std::cout << std::endl;
    }
};

/**
 * @brief MessageBuilder for creating FlatBuffer messages from the new JSON format.
 *
 * The new format stores complete Indexer documents in data_values/data_context,
 * where each message contains the entire _source payload as raw JSON bytes.
 */
class MessageBuilder
{
public:
    /**
     * @brief Build Start message (unchanged from before).
     */
    static std::vector<uint8_t> buildStart(const std::string& agentId,
                                           Wazuh::SyncSchema::Mode mode,
                                           Wazuh::SyncSchema::Option option,
                                           uint64_t size,
                                           const std::vector<std::string>& indices)
    {
        flatbuffers::FlatBufferBuilder builder;

        auto module = builder.CreateString("syscollector");
        auto agentIdStr = builder.CreateString(agentId);
        auto agentName = builder.CreateString("test-agent-" + agentId);
        auto agentVersion = builder.CreateString("5.0.0");

        std::vector<flatbuffers::Offset<flatbuffers::String>> indexVec;
        for (const auto& idx : indices)
        {
            indexVec.push_back(builder.CreateString(idx));
        }
        auto indicesOffset = builder.CreateVector(indexVec);

        // Default agent metadata
        auto architecture = builder.CreateString("x86_64");
        auto hostname = builder.CreateString("test-host");
        auto osname = builder.CreateString("Ubuntu");
        auto ostype = builder.CreateString("linux");
        auto osplatform = builder.CreateString("ubuntu");
        auto osversion = builder.CreateString("22.04");

        std::vector<flatbuffers::Offset<flatbuffers::String>> groups_vec;
        groups_vec.push_back(builder.CreateString("default"));
        auto groups = builder.CreateVector(groups_vec);

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_module_(module);
        startBuilder.add_mode(mode);
        startBuilder.add_size(size);
        startBuilder.add_index(indicesOffset);
        startBuilder.add_option(option);
        startBuilder.add_agentid(agentIdStr);
        startBuilder.add_agentname(agentName);
        startBuilder.add_agentversion(agentVersion);
        startBuilder.add_architecture(architecture);
        startBuilder.add_hostname(hostname);
        startBuilder.add_osname(osname);
        startBuilder.add_ostype(ostype);
        startBuilder.add_osplatform(osplatform);
        startBuilder.add_osversion(osversion);
        startBuilder.add_groups(groups);

        auto startOffset = startBuilder.Finish();
        auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_Start, startOffset.Union());

        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    /**
     * @brief Build DataValue message from payload JSON.
     *
     * @param session Session ID from StartAck
     * @param seq Sequence number
     * @param payload Complete JSON payload with _index, _id, _source
     * @param operation Upsert or Delete
     */
    static std::vector<uint8_t> buildDataValue(uint64_t session,
                                               uint64_t seq,
                                               const nlohmann::json& payload,
                                               Wazuh::SyncSchema::Operation operation)
    {
        flatbuffers::FlatBufferBuilder builder;

        // Extract index and id from payload
        std::string index = payload.value("_index", "");
        std::string id = payload.value("_id", "");

        // Serialize entire _source as JSON bytes
        std::string sourceJson = payload.value("_source", nlohmann::json::object()).dump();

        auto indexStr = builder.CreateString(index);
        auto idStr = builder.CreateString(id);
        auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(sourceJson.data()), sourceJson.size());

        Wazuh::SyncSchema::DataValueBuilder dataBuilder(builder);
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

    /**
     * @brief Build DataContext message from payload JSON.
     *
     * @param session Session ID from StartAck
     * @param seq Sequence number
     * @param payload Complete JSON payload with _index, _source
     */
    static std::vector<uint8_t> buildDataContext(uint64_t session, uint64_t seq, const nlohmann::json& payload)
    {
        flatbuffers::FlatBufferBuilder builder;

        // Extract index and id from payload
        std::string index = payload.value("_index", "");
        std::string id = payload.value("_id", "");

        // Serialize entire _source as JSON bytes
        std::string sourceJson = payload.value("_source", nlohmann::json::object()).dump();

        auto indexStr = builder.CreateString(index);
        auto idStr = builder.CreateString(id);
        auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(sourceJson.data()), sourceJson.size());

        Wazuh::SyncSchema::DataContextBuilder dataBuilder(builder);
        dataBuilder.add_session(session);
        dataBuilder.add_seq(seq);
        dataBuilder.add_index(indexStr);
        dataBuilder.add_id(idStr);
        dataBuilder.add_data(dataVec);

        auto dataOffset = dataBuilder.Finish();
        auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_DataContext, dataOffset.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    /**
     * @brief Build End message (unchanged).
     */
    static std::vector<uint8_t> buildEnd(uint64_t session)
    {
        flatbuffers::FlatBufferBuilder builder;

        Wazuh::SyncSchema::EndBuilder endBuilder(builder);
        endBuilder.add_session(session);
        auto endOffset = endBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_End, endOffset.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }
};

// Command line parser
TestConfig parseArgs(int argc, char* argv[])
{
    TestConfig config;

    if (argc < MIN_ARGS)
    {
        throw std::runtime_error(
            "Usage: " + std::string(argv[0]) +
            " <agent_id> <mode> <option> [--input <file>] [--config <file>] [--wait <seconds>] [--verbose]\n");
    }

    config.agentId = argv[1];
    config.mode = argv[2];
    config.option = argv[3];

    for (int i = MIN_ARGS; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--input" && i + 1 < argc)
        {
            config.inputFile = argv[++i];
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

// Main
int main(int argc, char* argv[])
{
    try
    {
        auto config = parseArgs(argc, argv);

        std::cout << "\n=== InventorySync + VD testtool ===" << std::endl;
        std::cout << "Mode: " << config.mode << "    Option: " << config.option << std::endl;

        // Load test data (new format)
        AgentTestData testData;
        if (!config.inputFile.empty())
        {
            std::cout << "Loading test data from: " << config.inputFile << std::endl;
            testData = AgentTestData::loadFromFile(config.inputFile);
            std::cout << "  Data values: " << testData.dataValues.size() << std::endl;
            std::cout << "  Data contexts: " << testData.dataContexts.size() << std::endl;
        }
        else
        {
            throw std::runtime_error("Input file is required");
        }

        // Initialize modules
        auto& routerModule = RouterModule::instance();
        routerModule.start();

        auto routerProvider = RouterProvider(IS_TOPIC, true);
        routerProvider.start();

        if (!std::filesystem::exists(DEFAULT_SOCKETS_PATH))
        {
            std::filesystem::create_directories(DEFAULT_SOCKETS_PATH);
        }
        FakeReportServer fakeReportServer(DEFAULT_QUEUE_PATH);
        fakeReportServer.start();

        uint64_t sessionId = 0;
        std::promise<void> startAckPromise;
        auto startAckFuture = startAckPromise.get_future();
        std::atomic<bool> receivedStartAck {false};

        std::promise<void> endAckPromise;
        auto endAckFuture = endAckPromise.get_future();
        std::atomic<bool> receivedEndAck {false};

        ResponseServer responseServer(
            ARQUEUE, sessionId, startAckPromise, endAckPromise, receivedStartAck, receivedEndAck, config.verbose);
        responseServer.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Load config
        nlohmann::json vdConfig;
        if (!config.configFile.empty())
        {
            std::cout << "\n[INFO] Loading config from: " << config.configFile << std::endl;
            vdConfig = nlohmann::json::parse(std::ifstream(config.configFile));
        }

        std::cout << "\n[INFO] Initializing modules..." << std::endl;

        auto& inventorySync = InventorySync::instance();
        inventorySync.start(
            [](const int,
               const std::string&,
               const std::string&,
               const int,
               const std::string&,
               const std::string& message,
               va_list args)
            {
                char buffer[MAX_LEN];
                vsnprintf(buffer, sizeof(buffer), message.c_str(), args);
                std::cout << "[IS] " << buffer << std::endl;
            },
            vdConfig);

        auto& vulnerabilityScanner = VulnerabilityScannerFacade::instance();
        vulnerabilityScanner.start(
            [](const int, const char*, const char*, const int, const char*, const char* message, va_list args)
            {
                char buffer[MAX_LEN];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::cout << "[VD] " << buffer << std::endl;
            },
            vdConfig,
            false,
            true,
            true);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Parse sync mode/option
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

        // Calculate total messages and indices
        uint64_t totalMessages = testData.dataValues.size() + testData.dataContexts.size();

        std::set<std::string> uniqueIndices;
        for (const auto& dv : testData.dataValues)
        {
            if (dv.contains("payload") && dv["payload"].contains("_index"))
            {
                uniqueIndices.insert(dv["payload"]["_index"].get<std::string>());
            }
        }
        for (const auto& dc : testData.dataContexts)
        {
            if (dc.contains("payload") && dc["payload"].contains("_index"))
            {
                uniqueIndices.insert(dc["payload"]["_index"].get<std::string>());
            }
        }

        std::vector<std::string> indices(uniqueIndices.begin(), uniqueIndices.end());

        std::cout << "\n[INFO] Sending " << totalMessages << " messages across " << indices.size() << " indices..."
                  << std::endl;

        // Send START
        std::cout << "[SEND] Start message" << std::endl;
        auto startMsg = MessageBuilder::buildStart(config.agentId, mode, option, totalMessages, indices);
        routerProvider.send(std::vector<char>(startMsg.begin(), startMsg.end()));

        if (startAckFuture.wait_for(std::chrono::seconds(10)) == std::future_status::timeout)
        {
            throw std::runtime_error("Timeout waiting for StartAck");
        }

        // Send DataValue messages
        uint64_t seq = 0;
        for (const auto& dataValue : testData.dataValues)
        {
            std::string operation = dataValue.value("operation", "upsert");
            auto op =
                (operation == "delete") ? Wazuh::SyncSchema::Operation_Delete : Wazuh::SyncSchema::Operation_Upsert;

            auto payload = dataValue.value("payload", nlohmann::json::object());
            std::string pkgName = "unknown";
            if (payload.contains("_source") && payload["_source"].contains("package"))
            {
                pkgName = payload["_source"]["package"].value("name", "unknown");
            }

            std::cout << "[SEND] DataValue (seq=" << seq << "): " << operation << " - " << pkgName << std::endl;

            auto msg = MessageBuilder::buildDataValue(sessionId, seq++, payload, op);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        // Send DataContext messages
        for (const auto& dataContext : testData.dataContexts)
        {
            auto payload = dataContext.value("payload", nlohmann::json::object());
            std::string pkgName = "unknown";
            if (payload.contains("_source") && payload["_source"].contains("package"))
            {
                pkgName = payload["_source"]["package"].value("name", "unknown");
            }

            std::cout << "[SEND] DataContext (seq=" << seq << "): " << pkgName << std::endl;

            auto msg = MessageBuilder::buildDataContext(sessionId, seq++, payload);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        // Send END
        std::cout << "[SEND] End message" << std::endl;
        auto endMsg = MessageBuilder::buildEnd(sessionId);
        routerProvider.send(std::vector<char>(endMsg.begin(), endMsg.end()));

        std::cout << "\n[INFO] Waiting " << config.waitTime << " seconds for VD processing..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(config.waitTime));

        // Cleanup
        std::cout << "\n[INFO] Stopping modules..." << std::endl;
        vulnerabilityScanner.stop();
        inventorySync.stop();
        fakeReportServer.stop();
        routerProvider.stop();
        routerModule.stop();

        std::cout << "[INFO] Test completed successfully!\n" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "\n[ERROR] " << e.what() << std::endl;
        return 1;
    }
}
