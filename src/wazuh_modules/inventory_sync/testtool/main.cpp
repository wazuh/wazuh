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
 * @brief Struct to hold agent test data
 */

struct AgentTestData
{
    nlohmann::json os;       ///< OS data
    nlohmann::json packages; ///< Packages data
    nlohmann::json hotfixes; ///< Hotfixes data
    std::string scanType;    ///< Scan type
    std::string agentId;     ///< Agent identifier

    /**
     * @brief Load agent test data from JSON file
     * @param filepath Path to JSON file
     * @return AgentTestData struct with loaded data
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

        // Extract data from structured format
        data.scanType = root.value("type", "TYPE_SCAN");
        data.agentId = root.value("agent", nlohmann::json::object()).value("id", "000");
        data.os = root.value("os", nlohmann::json::object());
        data.packages = root.value("packages", nlohmann::json::array());
        data.hotfixes = root.value("hotfixes", nlohmann::json::array());

        return data;
    }
};

/**
 * @brief Lightweight fake report server for capturing VD alerts during integration tests.
 *
 * This test component simulates the Wazuh manager's alert-receiver socket.
 * It binds to a UNIX datagram socket and prints every alert message received.
 *
 * The class manages its own thread and socket lifetime:
 *  - `start()` spawns the receiver thread and binds the socket.
 *  - `stop()` requests thread termination.
 *  - `waitForStop()` joins the thread and cleans up the socket path.
 *
 * Thread-safety notes:
 *  - Only `m_shouldStop` is atomic; all other state is managed by the owner thread.
 *  - The receiver thread blocks on `recvfrom()` until data arrives or stop() is called.
 */
class FakeReportServer
{
private:
    /**
     * @brief File descriptor of the UNIX datagram socket.
     *
     * Initialized in the constructor. Becomes -1 after cleanup.
     */
    int m_socketServer = -1;

    /**
     * @brief Background thread responsible for blocking recvfrom() calls.
     */
    std::thread m_serverThread;

    /**
     * @brief Stop flag controlling the lifetime of the receive loop.
     *
     * When set to true, the thread exits the loop and shutdown begins.
     */
    std::atomic<bool> m_shouldStop {false};

    /**
     * @brief Filesystem path where the UNIX socket will be created.
     *
     * Removed and recreated at server startup; deleted on shutdown.
     */
    std::string m_path;

public:
    /**
     * @brief Constructs the fake report server and creates the UNIX socket.
     *
     * @param path Path of the AF_UNIX datagram socket to bind.
     *
     * @throws std::runtime_error if the socket cannot be created.
     */
    explicit FakeReportServer(std::string path)
        : m_path(std::move(path))
    {
        m_socketServer = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (m_socketServer < 0)
        {
            throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
        }
    }

    /**
     * @brief Destructor. Ensures clean shutdown, thread join, and socket removal.
     */
    ~FakeReportServer()
    {
        stop();
        waitForStop();
    }

    /**
     * @brief Starts the receiving thread and binds the AF_UNIX socket.
     *
     * Removes any stale socket file at the target path.
     * Spawns a thread that:
     *   - binds to @ref m_path
     *   - receives alert messages via recvfrom()
     *   - prints them to stdout
     *
     * @throws std::runtime_error if binding fails.
     */
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

    /**
     * @brief Signals the server thread to stop receiving.
     *
     * Does not block; caller must invoke @ref waitForStop() to join.
     */
    void stop()
    {
        m_shouldStop.store(true);
    }

    /**
     * @brief Joins the server thread and removes the UNIX socket.
     *
     * Safe to call multiple times.
     * Performs:
     *   - thread join
     *   - socket close
     *   - unlink of @ref m_path
     */
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
 * @brief Response server used in InventorySync/VD integration tests.
 *
 * This component emulates the Wazuh manager's response socket and receives:
 *  - StartAck
 *  - EndAck
 *  - ReqRet
 *
 * It binds an AF_UNIX datagram socket and listens asynchronously on a
 * dedicated thread. Incoming FlatBuffer messages are decoded and the
 * corresponding synchronization promises are fulfilled.
 *
 * Responsibilities:
 *  - Bind to a UNIX socket path.
 *  - Receive agent→manager responses triggered by ResponseDispatcherImpl.
 *  - Parse FlatBuffer messages and trigger synchronization events.
 *
 * Threading Model:
 *  - `start()` spawns the receiver thread and performs socket bind().
 *  - `stop()` signals termination (atomic flag + shutdown()).
 *  - `waitForStop()` joins the thread and cleans up the socket.
 *
 * Constraints:
 *  - Only one server instance may bind to a given socket path.
 *  - Socket file is removed and recreated on each start() call.
 */
class ResponseServer
{
private:
    /** @brief AF_UNIX datagram socket file descriptor. */
    int m_socketFd = -1;

    /** @brief Worker thread responsible for running recvfrom() loop. */
    std::thread m_serverThread;

    /** @brief Atomic stop flag used to terminate receive loop. */
    std::atomic<bool> m_shouldStop {false};

    /** @brief Filesystem path to bind the UNIX socket. */
    std::string m_path;

    /** @brief References updated when StartAck is received. */
    uint64_t& m_sessionId;

    /** @brief Promises satisfied on StartAck and EndAck. */
    std::promise<void>& m_startAckPromise;
    std::promise<void>& m_endAckPromise;

    /** @brief Flags indicating whether StartAck/EndAck were already received. */
    std::atomic<bool>& m_receivedStartAck;
    std::atomic<bool>& m_receivedEndAck;

    /** @brief Enables verbose debug logging. */
    bool m_verbose;

public:
    /**
     * @brief Construct a ResponseServer and allocate its socket.
     *
     * @param path UNIX domain socket path to bind.
     * @param sessionId Reference updated when StartAck arrives.
     * @param startAckPromise Promise signaled when StartAck is received.
     * @param endAckPromise Promise signaled when EndAck is received.
     * @param receivedStartAck Atomic flag set on StartAck.
     * @param receivedEndAck Atomic flag set on EndAck.
     * @param verbose Enables debug printing for message traffic.
     *
     * @throws std::runtime_error if socket creation fails.
     */
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

    /**
     * @brief Ensures orderly shutdown, thread termination, and socket cleanup.
     */
    ~ResponseServer()
    {
        stop();
        waitForStop();
    }

    /**
     * @brief Bind the UNIX socket and start the asynchronous receive thread.
     *
     * Removes any leftover socket file at the given path, then binds and
     * enters a recvfrom() loop on a dedicated thread.
     *
     * @throws std::runtime_error if bind() fails.
     */
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

    /**
     * @brief Signals the server thread to stop and shuts down the socket.
     */
    void stop()
    {
        m_shouldStop.store(true);

        if (m_socketFd >= 0)
        {
            shutdown(m_socketFd, SHUT_RDWR);
        }
    }

    /**
     * @brief Joins the server thread and cleans up the socket file.
     *
     * Safe to call repeatedly. Ensures:
     *  - thread has finished
     *  - socket is closed
     *  - filesystem entry is removed
     */
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

        // Find "_sync " marker
        size_t syncPos = messageView.find("_sync ");
        if (syncPos == std::string_view::npos)
        {
            std::cerr << "[ERROR] No '_sync ' marker in manager message" << std::endl;
            return;
        }

        // Parse size from header
        size_t sizeEnd = messageView.rfind(' ', syncPos - 1);
        size_t sizeStart = messageView.rfind(' ', sizeEnd - 1);
        std::string sizeStr(messageView.substr(sizeStart + 1, sizeEnd - sizeStart - 1));
        size_t expectedFbSize = std::stoull(sizeStr);

        // FlatBuffer starts after "_sync " (6 chars) plus the space = 7 chars total
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
 * @brief Utility class for constructing FlatBuffer-encoded InventorySync messages.
 *
 * This class provides static helper functions used by the InventorySync/VD
 * integration test tool to generate:
 *   - Start            (initial synchronization metadata)
 *   - DataValue        (per-element inventory payloads)
 *   - End              (finalization of agent batch)
 *
 * The resulting objects are complete, verified FlatBuffer messages
 * compatible with Wazuh::SyncSchema::Message.
 *
 * Design Notes:
 *  - Stateless: No internal storage; safe for concurrent use.
 *  - Each method constructs its own FlatBufferBuilder to ensure
 *    message lifetimes are independent.
 *  - All returned buffers contain an entire serialized Message.
 */
class MessageBuilder
{
public:
    /**
     * @brief Build a Start message containing agent metadata and inventory indices.
     *
     * The Start message is the first step of the sync cycle. It declares:
     *   - The number of DataValue messages that will follow (`size`).
     *   - Which inventory indices this sync operation will affect.
     *   - Agent OS/platform metadata used by VD.
     *   - The sync type (full, delta) and processing option (Sync, VDFirst, etc).
     *
     * @param agentId   Agent identifier string (usually numeric).
     * @param mode      Sync mode (ModuleFull, ModuleDelta, etc).
     * @param option    Sync option (VDFirst, VDSync, VDClean, Sync).
     * @param size      Number of expected DataValue messages in this batch.
     * @param indices   List of inventory indices to be synced
     *                  (e.g., "wazuh-states-inventory-packages").
     * @param osData    JSON dictionary containing agent OS metadata.
     *
     * Required OS fields (if missing, defaults are applied):
     *   - hostname
     *   - architecture
     *   - name
     *   - platform
     *   - version
     *
     * @return Serialized FlatBuffer `Message` buffer containing Start.
     */
    static std::vector<uint8_t> buildStart(const std::string& agentId,
                                           Wazuh::SyncSchema::Mode mode,
                                           Wazuh::SyncSchema::Option option,
                                           uint64_t size,
                                           const std::vector<std::string>& indices,
                                           const nlohmann::json& osData)
    {
        flatbuffers::FlatBufferBuilder builder;

        // Module: always "syscollector" for inventory sync
        auto module = builder.CreateString("syscollector");

        // Inventory indices encoded as vector<string>
        std::vector<flatbuffers::Offset<flatbuffers::String>> indexVec;
        indexVec.reserve(indices.size());
        for (const auto& idx : indices)
        {
            indexVec.push_back(builder.CreateString(idx));
        }
        auto indicesOffset = builder.CreateVector(indexVec);

        // Agent metadata from JSON (with fallbacks)
        auto agentIdStr = builder.CreateString(agentId);
        auto agentName = builder.CreateString(osData.value("hostname", "test-agent-" + agentId));
        auto agentVersion = builder.CreateString("5.0.0");
        auto architecture = builder.CreateString(osData.value("architecture", "x86_64"));
        auto hostname = builder.CreateString(osData.value("hostname", "test-host"));
        auto osname = builder.CreateString(osData.value("name", "Ubuntu"));
        auto ostype = builder.CreateString("linux");
        auto osplatform = builder.CreateString(osData.value("platform", "ubuntu"));
        auto osversion = builder.CreateString(osData.value("version", "22.04"));

        // Default group
        std::vector<flatbuffers::Offset<flatbuffers::String>> groups_vec;
        groups_vec.push_back(builder.CreateString("default"));
        auto groups = builder.CreateVector(groups_vec);

        // Build Start object
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

        // Wrap into Message union
        auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_Start, startOffset.Union());

        builder.Finish(message);

        // Return full serialized buffer
        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    /**
     * @brief Build a DataValue message containing one inventory element.
     *
     * Represents a single package / hotfix / OS entry.
     *
     * The payload (`jsonData`) is stored as raw bytes in the FlatBuffer and
     * is later decoded by the manager's inventory processing pipeline.
     *
     * @param session     Session ID provided in StartAck.
     * @param seq         Sequence number for ordering within this batch.
     * @param index       Inventory index (e.g. "wazuh-states-inventory-packages").
     * @param id          Unique document identifier for this element.
     * @param jsonData    JSON payload encoded as string.
     * @param operation   Upsert | Delete.
     *
     * @return FlatBuffer-encoded Message containing DataValue.
     */
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

        // Store JSON raw bytes as vector<int8_t>.
        // This is required because FlatBuffers does not store arbitrary-length strings
        // in unions directly.
        auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(jsonData.data()), jsonData.size());

        Wazuh::SyncSchema::DataValueBuilder dataBuilder(builder);
        dataBuilder.add_session(session);
        dataBuilder.add_seq(seq);
        dataBuilder.add_operation(operation);
        dataBuilder.add_index(indexStr);
        dataBuilder.add_id(idStr);
        dataBuilder.add_data(dataVec);

        auto dataOffset = dataBuilder.Finish();

        // Wrap into Message union
        auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_DataValue, dataOffset.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    /**
     * @brief Build an End message signaling the end of the sync sequence.
     *
     * The End message must be sent once all DataValue messages are flushed.
     * The manager responds with EndAck.
     *
     * @param session Session identifier (must match StartAck).
     *
     * @return Serialized FlatBuffer `Message` containing End.
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

// Simple command line parser
TestConfig parseArgs(int argc, char* argv[])
{
    TestConfig config;

    if (argc < MIN_ARGS)
    {
        throw std::runtime_error(
            "Usage: " + std::string(argv[0]) +
            " <agent_id> <mode> <option> [--input <file>] [--config <file>] [--wait <seconds>] [--verbose]\n"
            "\n"
            "Arguments:\n"
            "  agent_id       Agent identifier (e.g., 001)\n"
            "  mode           Sync mode: 'full' or 'delta'\n"
            "  option         VD option: 'VDFirst', 'VDSync', 'VDClean', or 'Sync'\n"
            "\n"
            "Options:\n"
            "  --input <file>   JSON file with agent data (os, packages, hotfixes)\n"
            "  --config <file>  VD configuration file\n"
            "  --wait <secs>    Seconds to wait after sending messages (default: 10)\n"
            "  --verbose        Enable verbose logging\n"
            "\n"
            "Example:\n"
            "  " +
            std::string(argv[0]) + " 001 full VDFirst --input agent_001.json --config vd_config.json --verbose\n");
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
        else
        {
            throw std::runtime_error("Unknown argument: " + arg);
        }
    }

    return config;
}

// -- Main testtool -- //
int main(int argc, char* argv[])
{
    try
    {
        auto config = parseArgs(argc, argv);

        std::cout << "\n=== InventorySync + VD testtool ===" << std::endl;
        std::cout << "Mode: " << config.mode << "    Option: " << config.option << std::endl;

        // Load agent test data
        AgentTestData testData;
        if (!config.inputFile.empty())
        {
            std::cout << "Loading test data from: " << config.inputFile << std::endl;
            testData = AgentTestData::loadFromFile(config.inputFile);
            std::cout << "  OS: " << testData.os.value("name", "Unknown") << std::endl;
            std::cout << "  Packages: " << testData.packages.size() << std::endl;
            std::cout << "  Hotfixes: " << testData.hotfixes.size() << std::endl;
        }
        else
        {
            std::cout << "[ERROR] No input file specified" << std::endl;
            throw std::runtime_error("Input file is required");
        }

        auto& routerModule = RouterModule::instance();
        routerModule.start();

        auto routerProvider = RouterProvider(IS_TOPIC, true);
        routerProvider.start();

        // Setup fake report server
        if (!std::filesystem::exists(DEFAULT_SOCKETS_PATH))
        {
            std::filesystem::create_directories(DEFAULT_SOCKETS_PATH);
        }
        FakeReportServer fakeReportServer(DEFAULT_QUEUE_PATH);
        fakeReportServer.start();

        // Setup response server
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

        // Load VD config
        nlohmann::json vdConfig;
        if (!config.configFile.empty())
        {
            std::cout << "\n[INFO] Loading config from: " << config.configFile << std::endl;
            vdConfig = nlohmann::json::parse(std::ifstream(config.configFile));
        }

        // Initialize modules
        std::cout << "\n[INFO] Initializing modules..." << std::endl;

        // Initialize InventorySync
        auto& inventorySync = InventorySync::instance();
        inventorySync.start(
            [&config](const int,
                      const std::string&,
                      const std::string&,
                      const int,
                      const std::string&,
                      const std::string& message,
                      va_list args)
            {
                char buffer[MAX_LEN];
                vsnprintf(buffer, sizeof(buffer), message.c_str(), args);
                std::cout << "[TESTTOOL] " << buffer << std::endl;
            },
            vdConfig);

        // Initialize VulnerabilityScanner
        auto& vulnerabilityScanner = VulnerabilityScannerFacade::instance();
        vulnerabilityScanner.start(
            [&config](const int, const char*, const char*, const int, const char*, const char* message, va_list args)
            {
                char buffer[MAX_LEN];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::cout << "[TESTTOOL] " << buffer << std::endl;
            },
            vdConfig,
            false,
            true,
            true);

        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Prepare sync parameters
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
        if (!testData.os.empty())
        {
            totalMessages++;
        }
        totalMessages += testData.packages.size();
        totalMessages += testData.hotfixes.size();

        // Build indices
        std::vector<std::string> indices;
        if (!testData.os.empty())
        {
            indices.emplace_back(OS_INDEX);
        }
        if (!testData.packages.empty())
        {
            indices.emplace_back(PACKAGE_INDEX);
        }
        if (!testData.hotfixes.empty())
        {
            indices.emplace_back(HOTFIX_INDEX);
        }

        std::cout << "\n[INFO] Sending " << totalMessages << " messages..." << std::endl;

        // Send START
        std::cout << "[SEND] Start message" << std::endl;
        auto startMsg = MessageBuilder::buildStart(config.agentId, mode, option, totalMessages, indices, testData.os);
        routerProvider.send(std::vector<char>(startMsg.begin(), startMsg.end()));

        if (startAckFuture.wait_for(std::chrono::seconds(10)) == std::future_status::timeout)
        {
            throw std::runtime_error("Timeout waiting for StartAck");
        }

        // Send DATA
        uint64_t seq = 0;

        if (!testData.os.empty())
        {
            std::cout << "[SEND] OS data (seq=" << seq << ")" << std::endl;
            auto msg = MessageBuilder::buildDataValue(sessionId,
                                                      seq++,
                                                      "wazuh-states-inventory-system",
                                                      config.agentId,
                                                      testData.os.dump(),
                                                      Wazuh::SyncSchema::Operation_Upsert);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        for (const auto& pkg : testData.packages)
        {
            std::cout << "[SEND] Package: " << pkg.value("name", "unknown") << " (seq=" << seq << ")" << std::endl;
            auto msg = MessageBuilder::buildDataValue(sessionId,
                                                      seq++,
                                                      "wazuh-states-inventory-packages",
                                                      config.agentId + "_pkg_" + std::to_string(seq),
                                                      pkg.dump(),
                                                      Wazuh::SyncSchema::Operation_Upsert);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        for (const auto& hotfix : testData.hotfixes)
        {
            std::cout << "[SEND] Hotfix (seq=" << seq << ")" << std::endl;
            auto msg = MessageBuilder::buildDataValue(sessionId,
                                                      seq++,
                                                      "wazuh-states-inventory-hotfixes",
                                                      config.agentId + "_hf_" + std::to_string(seq),
                                                      hotfix.dump(),
                                                      Wazuh::SyncSchema::Operation_Upsert);
            routerProvider.send(std::vector<char>(msg.begin(), msg.end()));
        }

        // Send END
        std::cout << "[SEND] End message" << std::endl;
        auto endMsg = MessageBuilder::buildEnd(sessionId);
        routerProvider.send(std::vector<char>(endMsg.begin(), endMsg.end()));

        // Wait for processing
        std::cout << "\n[INFO] Waiting " << config.waitTime << " seconds for VD processing..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(config.waitTime));

        // Cleanup
        std::cout << "\n[INFO] Stopping modules..." << std::endl;
        vulnerabilityScanner.stop();
        inventorySync.stop();
        fakeReportServer.stop();
        routerProvider.stop();
        routerModule.stop();

        std::cout << "[INFO] Completed successfully!\n" << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "\n[ERROR] " << e.what() << std::endl;
        return 1;
    }
}
