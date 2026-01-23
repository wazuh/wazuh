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
#include <set>
#include <thread>
#include <vector>

constexpr auto MAX_LEN = 65536;
constexpr auto DEFAULT_SOCKETS_PATH = "queue/sockets";
constexpr auto DEFAULT_QUEUE_PATH = "queue/sockets/queue";
constexpr auto DEFAULT_ARQUEUE_DIR = "queue/alerts";
constexpr auto DEFAULT_ARQUEUE = "queue/alerts/ar";
constexpr auto IS_TOPIC = "inventory-states";
constexpr auto MIN_ARGS = 3;

/**
 * @brief Struct to hold test configuration
 */
struct TestConfig
{
    std::string input;      ///< JSON file or directory with Start + data_values + data_context
    std::string configFile; ///< VD configuration file
    uint32_t waitTime = 30; ///< seconds to wait after sending messages
    bool verbose = false;   ///< verbose logging
    std::string logFile;    ///< log file path
};

/**
 * @brief Struct to hold agent test data in the new format
 */
struct AgentTestData
{
    nlohmann::json start;                     ///< Start message description
    std::vector<nlohmann::json> dataValues;   ///< Array of data_values
    std::vector<nlohmann::json> dataContexts; ///< Array of data_context

    /**
     * @brief Load agent test data from JSON file (new format)
     *
     * Expected format:
     * {
     *   "Start": {
     *     "agentid": "001",
     *     "mode": "full|delta",    // optional, defaults to "delta"
     *     "option": "VDFirst|VDSync|Sync", // optional, defaults to "VDSync"
     *
     *     // Optional agent / OS metadata (defaults provided if omitted)
     *     "agentname": "test-agent-001",
     *     "agentversion": "5.0.0",
     *     "architecture": "x86_64",
     *     "hostname": "test-host",
     *     "osname": "Ubuntu",
     *     "osplatform": "ubuntu",
     *     "ostype": "linux",
     *     "osversion": "22.04",
     *     "groups": ["default", "extra-group"],
     *
     *     // Optional; if omitted, indices and size are computed automatically
     *     "indices": [
     *       "wazuh-states-inventory-packages",
     *       "wazuh-states-inventory-system",
     *       "wazuh-states-inventory-hotfixes"
     *     ],
     *     "size": 5
     *   },
     *   "data_values": [
     *     {
     *       "operation": "upsert|delete",
     *       "index": "wazuh-states-inventory-packages", // optional, auto-detected if omitted
     *       "id": "document-id-1",                       // optional
     *       "payload": {
     *         "checksum": { ... },
     *         "package": { ... },
     *         "state": { ... }
     *       }
     *     }
     *   ],
     *   "data_context": [
     *     {
     *       "index": "wazuh-states-inventory-system",    // optional, auto-detected if omitted
     *       "id": "document-id-2",                       // optional
     *       "payload": {
     *         "checksum": { ... },
     *         "host": { ... },
     *         "state": { ... }
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

        // Start is mandatory in the new format
        if (!root.contains("Start") || !root["Start"].is_object())
        {
            throw std::runtime_error("Input JSON must contain a 'Start' object");
        }

        data.start = root["Start"];

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
                sockaddr_un serverAddr {};
                serverAddr.sun_family = AF_UNIX;
                std::snprintf(serverAddr.sun_path, sizeof(serverAddr.sun_path), "%s", m_path.c_str());

                if (bind(m_socketServer, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
                {
                    throw std::runtime_error("Failed to bind socket: " + std::string(strerror(errno)));
                }

                char buffer[MAX_LEN];
                sockaddr_un clientAddr {};
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
        if (m_socketServer >= 0)
        {
            shutdown(m_socketServer, SHUT_RDWR);
        }
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
                sockaddr_un serverAddr {};
                serverAddr.sun_family = AF_UNIX;
                std::snprintf(serverAddr.sun_path, sizeof(serverAddr.sun_path), "%s", m_path.c_str());

                if (bind(m_socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
                {
                    throw std::runtime_error("Failed to bind socket to " + m_path + ": " +
                                             std::string(strerror(errno)));
                }

                std::cout << "[INFO] Response server listening on " << m_path << std::endl;

                char buffer[MAX_LEN];
                sockaddr_un clientAddr {};
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
 * @brief Helper to map string mode -> Wazuh::SyncSchema::Mode
 */
inline Wazuh::SyncSchema::Mode parseMode(const std::string& modeStr)
{
    if (modeStr == "full" || modeStr == "ModuleFull")
    {
        return Wazuh::SyncSchema::Mode_ModuleFull;
    }
    if (modeStr == "delta" || modeStr == "ModuleDelta")
    {
        return Wazuh::SyncSchema::Mode_ModuleDelta;
    }
    // Default to delta
    return Wazuh::SyncSchema::Mode_ModuleDelta;
}

/**
 * @brief Helper to map string option -> Wazuh::SyncSchema::Option
 */
inline Wazuh::SyncSchema::Option parseOption(const std::string& opt)
{
    if (opt == "VDFirst")
        return Wazuh::SyncSchema::Option_VDFirst;
    if (opt == "VDSync")
        return Wazuh::SyncSchema::Option_VDSync;
    if (opt == "Sync")
        return Wazuh::SyncSchema::Option_Sync;
    return Wazuh::SyncSchema::Option_VDSync;
}

/**
 * @brief Infer index from entry payload if not explicitly set.
 *
 * Rules:
 *  - If entry["index"] exists → use it.
 *  - Else if payload.package.hotfix → HOTFIX_INDEX
 *  - Else if payload.package → PACKAGE_INDEX
 *  - Else if payload.host → OS_INDEX
 *  - Else → empty string (caller must handle)
 */
inline std::string inferIndex(const nlohmann::json& entry)
{
    if (entry.contains("index") && entry["index"].is_string())
    {
        return entry["index"].get<std::string>();
    }

    if (!entry.contains("payload") || !entry["payload"].is_object())
    {
        return {};
    }

    const auto& payload = entry["payload"];

    if (payload.contains("package") && payload["package"].is_object())
    {
        const auto& pkg = payload["package"];
        if (pkg.contains("hotfix"))
        {
            return std::string(HOTFIX_INDEX);
        }

        return std::string(PACKAGE_INDEX);
    }

    if (payload.contains("host"))
    {
        return std::string(OS_INDEX);
    }

    return {};
}

/**
 * @brief MessageBuilder for creating FlatBuffer messages from the new JSON format.
 *
 * The new format stores complete inventory documents in data_values/data_context,
 * where each message contains the entire payload as raw JSON bytes.
 */
class MessageBuilder
{
public:
    /**
     * @brief Build Start message from JSON description.
     *
     * @param startJson   "Start" object from the input file.
     * @param defaultSize Number of messages (data_values + data_context) if size is not set in JSON.
     * @param defaultIndices Indices inferred from data_values/data_context if not set in JSON.
     */
    static std::vector<uint8_t>
    buildStart(const nlohmann::json& startJson, uint64_t defaultSize, const std::vector<std::string>& defaultIndices)
    {
        flatbuffers::FlatBufferBuilder builder;

        // Module and basic fields
        std::string moduleStr = startJson.value("module", std::string("syscollector"));
        auto module = builder.CreateString(moduleStr);

        std::string agentId = startJson.value("agentid", std::string("000"));
        auto agentIdStr = builder.CreateString(agentId);

        std::string agentNameStr = startJson.value("agentname", "test-agent-" + agentId);
        auto agentName = builder.CreateString(agentNameStr);

        std::string agentVersionStr = startJson.value("agentversion", std::string("5.0.0"));
        auto agentVersion = builder.CreateString(agentVersionStr);

        std::string modeStr = startJson.value("mode", std::string("delta"));
        auto mode = parseMode(modeStr);

        std::string optionStr = startJson.value("option", std::string("VDSync"));
        auto option = parseOption(optionStr);

        uint64_t size = startJson.value("size", defaultSize);

        // Indices: either provided in Start or inferred from messages
        std::vector<std::string> indices;
        if (startJson.contains("indices") && startJson["indices"].is_array())
        {
            for (const auto& idx : startJson["indices"])
            {
                if (idx.is_string())
                {
                    indices.push_back(idx.get<std::string>());
                }
            }
        }
        else
        {
            indices = defaultIndices;
        }

        std::vector<flatbuffers::Offset<flatbuffers::String>> indexVec;
        indexVec.reserve(indices.size());
        for (const auto& idx : indices)
        {
            indexVec.push_back(builder.CreateString(idx));
        }
        auto indicesOffset = builder.CreateVector(indexVec);

        // Agent / OS metadata (with defaults)
        auto architecture = builder.CreateString(startJson.value("architecture", std::string("x86_64")));
        auto hostname = builder.CreateString(startJson.value("hostname", std::string("test-host")));
        auto osname = builder.CreateString(startJson.value("osname", std::string("Ubuntu")));
        auto ostype = builder.CreateString(startJson.value("ostype", std::string("linux")));
        auto osplatform = builder.CreateString(startJson.value("osplatform", std::string("ubuntu")));
        auto osversion = builder.CreateString(startJson.value("osversion", std::string("22.04")));

        // Groups
        std::vector<flatbuffers::Offset<flatbuffers::String>> groupsVec;
        if (startJson.contains("groups") && startJson["groups"].is_array())
        {
            for (const auto& g : startJson["groups"])
            {
                if (g.is_string())
                {
                    groupsVec.push_back(builder.CreateString(g.get<std::string>()));
                }
            }
        }
        else
        {
            groupsVec.push_back(builder.CreateString("default"));
        }
        auto groups = builder.CreateVector(groupsVec);

        // Build Start
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
     * @param session   Session ID from StartAck
     * @param seq       Sequence number
     * @param payload   Complete JSON payload (checksum/package/host/state...)
     * @param index     Index name (wazuh-states-inventory-packages/system/hotfixes)
     * @param id        Document ID (may be empty)
     * @param operation Upsert or Delete
     */
    static std::vector<uint8_t> buildDataValue(uint64_t session,
                                               uint64_t seq,
                                               const nlohmann::json& payload,
                                               const std::string& index,
                                               const std::string& id,
                                               Wazuh::SyncSchema::Operation operation)
    {
        flatbuffers::FlatBufferBuilder builder;

        std::string sourceJson = payload.dump();

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
     * @param session   Session ID from StartAck
     * @param seq       Sequence number
     * @param payload   Complete JSON payload
     * @param index     Index name
     * @param id        Document ID (may be empty)
     */
    static std::vector<uint8_t> buildDataContext(
        uint64_t session, uint64_t seq, const nlohmann::json& payload, const std::string& index, const std::string& id)
    {
        flatbuffers::FlatBufferBuilder builder;

        std::string sourceJson = payload.dump();

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
     * @brief Build End message.
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

    // At least the input file and configuration file are required
    if (argc < MIN_ARGS)
    {
        throw std::runtime_error("Usage: " + std::string(argv[0]) +
                                 " <input.json>|<directory> [--config <file>] [--wait <seconds>] [--verbose]\n");
    }

    config.input = argv[1];

    for (int i = MIN_ARGS - 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc)
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
        else if (arg == "--logFile")
        {
            config.logFile = argv[++i];
        }
    }

    return config;
}

void sendEvent(bool verbose,
               const std::string& input,
               uint32_t waitTime,
               RouterProvider& routerProvider,
               FakeReportServer& fakeReportServer,
               uint64_t& sessionId,
               std::promise<void>& startAckPromise,
               std::promise<void>& endAckPromise,
               std::atomic<bool>& receivedStartAck,
               std::atomic<bool>& receivedEndAck)
{
    // Reset promises for new iteration
    startAckPromise = std::promise<void>();
    endAckPromise = std::promise<void>();
    receivedStartAck = false;
    receivedEndAck = false;
    sessionId = 0;

    auto startAckFuture = startAckPromise.get_future();
    auto endAckFuture = endAckPromise.get_future();

    // Load test data
    AgentTestData testData;
    {
        testData = AgentTestData::loadFromFile(input);

        const auto agentId = testData.start.value("agentid", std::string("000"));
        const auto modeStr = testData.start.value("mode", std::string("delta"));
        const auto optStr = testData.start.value("option", std::string("VDSync"));
    }

    // Calculate total messages
    uint64_t totalMessages = testData.dataValues.size() + testData.dataContexts.size();

    // Collect unique indices from data_values/data_context (auto-detection)
    std::set<std::string> uniqueIndices;
    for (const auto& dv : testData.dataValues)
    {
        const auto idx = inferIndex(dv);
        if (!idx.empty())
        {
            uniqueIndices.insert(idx);
        }
    }
    for (const auto& dc : testData.dataContexts)
    {
        const auto idx = inferIndex(dc);
        if (!idx.empty())
        {
            uniqueIndices.insert(idx);
        }
    }

    std::vector<std::string> indices(uniqueIndices.begin(), uniqueIndices.end());

    std::cout << "\n[INFO] Sending " << totalMessages << " messages across " << indices.size() << " indices..."
              << std::endl;

    // Send START
    std::cout << "[SEND] Start message" << std::endl;
    auto startMsg = MessageBuilder::buildStart(testData.start, totalMessages, indices);
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
        auto op = (operation == "delete") ? Wazuh::SyncSchema::Operation_Delete : Wazuh::SyncSchema::Operation_Upsert;

        auto payload = dataValue.value("payload", nlohmann::json::object());
        std::string index = inferIndex(dataValue);
        std::string id = dataValue.value("id", std::string());

        if (index.empty())
        {
            std::cerr << "[WARN] DataValue without index could not be inferred, skipping" << std::endl;
            continue;
        }

        std::string pkgName = "unknown";
        if (payload.contains("package") && payload["package"].is_object())
        {
            pkgName = payload["package"].value("name", "unknown");
        }

        std::cout << "[SEND] DataValue (seq=" << seq << ", index=" << index << "): " << operation << " - " << pkgName
                  << std::endl;

        auto msg = MessageBuilder::buildDataValue(sessionId, seq++, payload, index, id, op);
        routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
    }

    // Send DataContext messages
    for (const auto& dataContext : testData.dataContexts)
    {
        auto payload = dataContext.value("payload", nlohmann::json::object());
        std::string index = inferIndex(dataContext);
        std::string id = dataContext.value("id", std::string());

        if (index.empty())
        {
            std::cerr << "[WARN] DataContext without index could not be inferred, skipping" << std::endl;
            continue;
        }

        std::string pkgName = "unknown";
        if (payload.contains("package") && payload["package"].is_object())
        {
            pkgName = payload["package"].value("name", "unknown");
        }

        std::cout << "[SEND] DataContext (seq=" << seq << ", index=" << index << "): " << pkgName << std::endl;

        auto msg = MessageBuilder::buildDataContext(sessionId, seq++, payload, index, id);
        routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
    }

    // Send END
    std::cout << "[SEND] End message" << std::endl;
    auto endMsg = MessageBuilder::buildEnd(sessionId);
    routerProvider.send(std::vector<char>(endMsg.begin(), endMsg.end()));

    std::cout << "\n[INFO] Waiting " << waitTime << " seconds for VD processing..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(waitTime));
}

// Main
int main(int argc, char* argv[])
{
    try
    {
        // Parse command line arguments
        auto config = parseArgs(argc, argv);

        std::cout << "\n=== InventorySync + VD testtool ===" << std::endl;
        std::cout << "Loading test data from: " << config.input << std::endl;

        // Initialize router
        auto& routerModule = RouterModule::instance();
        routerModule.start();

        auto routerProvider = RouterProvider(IS_TOPIC, true);
        routerProvider.start();

        if (!std::filesystem::exists(DEFAULT_SOCKETS_PATH))
        {
            std::filesystem::create_directories(DEFAULT_SOCKETS_PATH);
        }
        if (!std::filesystem::exists(DEFAULT_ARQUEUE_DIR))
        {
            std::filesystem::create_directories(DEFAULT_ARQUEUE_DIR);
        }

        // Load config
        nlohmann::json vdConfig;
        if (!config.configFile.empty())
        {
            std::cout << "\n[INFO] Loading config from: " << config.configFile << std::endl;
            vdConfig = nlohmann::json::parse(std::ifstream(config.configFile));
        }

        std::cout << "\n[INFO] Initializing modules..." << std::endl;

        std::ofstream logFile;
        if (!config.logFile.empty())
        {
            logFile.open(config.logFile, std::ios::out | std::ios::app);
            if (!logFile.is_open())
            {
                throw std::runtime_error("Failed to open log file: " + config.logFile);
            }
        }

        // Initialize InventorySync
        auto& inventorySync = InventorySync::instance();
        inventorySync.start(
            [&logFile](
                const int, const char* tag, const char*, const int, const char* func, const char* message, va_list args)
            {
                char buffer[MAX_LEN];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::cout << "[IS] " << buffer << std::endl;

                if (logFile.is_open())
                {
                    if (strcmp(tag, WM_VULNSCAN_LOGTAG) == 0)
                    {
                        logFile << func << "():" << buffer << std::endl;
                    }
                }
                logFile.flush();
            },
            vdConfig);

        // Initialize VulnerabilityDetector
        auto& vulnerabilityScanner = VulnerabilityScannerFacade::instance();
        vulnerabilityScanner.start(
            [&logFile](
                const int, const char* tag, const char*, const int, const char* func, const char* message, va_list args)
            {
                char buffer[MAX_LEN];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::cout << "[VD] " << buffer << std::endl;

                if (logFile.is_open())
                {
                    if (strcmp(tag, WM_VULNSCAN_LOGTAG) == 0)
                    {
                        logFile << func << "():" << buffer << std::endl;
                    }
                }
                logFile.flush();
            },
            vdConfig,
            false,
            true,
            true);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        struct stat info;
        if (stat(config.input.c_str(), &info) != 0)
        {
            throw std::runtime_error("Cannot access input: " + config.input);
        }

        FakeReportServer fakeReportServer(DEFAULT_QUEUE_PATH);
        fakeReportServer.start();

        uint64_t sessionId = 0;
        std::promise<void> startAckPromise;
        std::promise<void> endAckPromise;
        std::atomic<bool> receivedStartAck {false};
        std::atomic<bool> receivedEndAck {false};

        ResponseServer responseServer(DEFAULT_ARQUEUE,
                                      sessionId,
                                      startAckPromise,
                                      endAckPromise,
                                      receivedStartAck,
                                      receivedEndAck,
                                      config.verbose);
        responseServer.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (info.st_mode & S_IFDIR)
        {
            // Directory: process all .json files
            for (const auto& entry : std::filesystem::directory_iterator(config.input))
            {
                if (entry.is_regular_file() && entry.path().extension() == ".json")
                {
                    std::cout << "\n[INFO] Processing file: " << entry.path().string() << std::endl;
                    sendEvent(config.verbose,
                              entry.path().string(),
                              config.waitTime,
                              routerProvider,
                              fakeReportServer,
                              sessionId,
                              startAckPromise,
                              endAckPromise,
                              receivedStartAck,
                              receivedEndAck);
                }
            }
        }
        else
        {
            // Single file
            sendEvent(config.verbose,
                      config.input,
                      config.waitTime,
                      routerProvider,
                      fakeReportServer,
                      sessionId,
                      startAckPromise,
                      endAckPromise,
                      receivedStartAck,
                      receivedEndAck);
        }

        // Cleanup
        std::cout << "\n[INFO] Cleaning up servers..." << std::endl;
        fakeReportServer.stop();
        responseServer.stop();
        fakeReportServer.waitForStop();
        responseServer.waitForStop();
        std::cout << "\n[INFO] Stopping modules..." << std::endl;
        vulnerabilityScanner.stop();
        inventorySync.stop();
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
