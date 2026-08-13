/*
 * Wazuh inventory sync server + VD integration test tool
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Drives the vulnerability-detection integration workflow through the NEW ingestion path: it
 * starts the real vulnerability scanner and the real inventory_sync_server, converts each
 * input_*.json (the same format the legacy inventory_sync_testtool consumed) into ONE FlatBuffers
 * Message{FullSession}, and POSTs it to the server's UDS /stateful route with option
 * VDFirst/VDSync -- exactly the bytes remoted would forward for an agent.
 *
 * Everything the legacy tool needed is gone by design: no router, no acks, no End, no response
 * sockets. The HTTP status IS the outcome, and D22 makes a 200 mean "scan ran AND the inventory
 * was flushed", so there is no scan-completion polling either. A 503 with Retry-After (the CVE
 * feed still downloading) is retried until --feed-timeout expires.
 *
 * CLI (kept compatible with the legacy tool so the QA driver changes only the binary name):
 *   inventory_sync_server_testtool <input.json>|<directory> [--config <file>]
 *                                  [--logFile <file>] [--wait <seconds>] [--verbose]
 *
 * It is also the QA suite's server harness: --serve boots the modules and keeps the socket
 * open until SIGTERM/SIGINT (no inputs), and --no-vd skips the vulnerability scanner facade --
 * the server's scanner seam degrades gracefully (feedReady() passes, scans report a legitimate
 * skip), so plain ingestion scenarios run without paying the CVE feed bring-up.
 */

#include "flatbuffers/include/inventorySync_generated.h"
#include "inventory_sync_server.h"
#include "vulnerabilityScannerFacade.hpp"

#include "external/nlohmann/json.hpp"
#include <cJSON.h>

#include <csignal>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

// Testtool-only override for the weak hook in vulnerabilityScannerFacade.cpp: skip the automatic
// full re-scan a feed update triggers, so the log only contains the scans the inputs asked for.
extern "C" bool vdTesttoolSkipPostUpdateScan()
{
    return true;
}

namespace
{
    constexpr auto DEFAULT_SOCKET_PATH = "queue/sockets/inventory-sync.sock";
    constexpr auto PACKAGE_INDEX = "wazuh-states-inventory-packages";
    constexpr auto HOTFIX_INDEX = "wazuh-states-inventory-hotfixes";
    constexpr auto OS_INDEX = "wazuh-states-inventory-system";

    struct TestConfig
    {
        std::string input;
        std::string configFile;
        std::string logFile;
        uint32_t waitTime = 3;          ///< settle time after the last session (VD's async indexing)
        uint32_t feedTimeoutSecs = 300; ///< how long to retry 503 "feed not ready" answers
        bool verbose = false;
        bool serve = false; ///< boot the modules and wait for SIGTERM/SIGINT instead of feeding inputs
        bool noVd = false;  ///< do not start the vulnerability scanner facade (QA ingestion runs)
    };

    TestConfig parseArgs(int argc, char* argv[])
    {
        if (argc < 2)
        {
            throw std::runtime_error("Usage: " + std::string(argv[0]) +
                                     " <input.json>|<directory> [--config <file>] [--logFile <file>]"
                                     " [--wait <seconds>] [--feed-timeout <seconds>] [--verbose]\n"
                                     "       " +
                                     std::string(argv[0]) + " --serve [--no-vd] [--config <file>] [--logFile <file>]");
        }

        TestConfig config;
        int first = 1;
        if (std::string(argv[1]).rfind("--", 0) != 0)
        {
            config.input = argv[1];
            first = 2;
        }
        for (int i = first; i < argc; ++i)
        {
            const std::string arg = argv[i];
            if (arg == "--config" && i + 1 < argc)
            {
                config.configFile = argv[++i];
            }
            else if (arg == "--logFile" && i + 1 < argc)
            {
                config.logFile = argv[++i];
            }
            else if (arg == "--wait" && i + 1 < argc)
            {
                config.waitTime = std::stoul(argv[++i]);
            }
            else if (arg == "--feed-timeout" && i + 1 < argc)
            {
                config.feedTimeoutSecs = std::stoul(argv[++i]);
            }
            else if (arg == "--verbose")
            {
                config.verbose = true;
            }
            else if (arg == "--serve")
            {
                config.serve = true;
            }
            else if (arg == "--no-vd")
            {
                config.noVd = true;
            }
        }
        if (config.input.empty() && !config.serve)
        {
            throw std::runtime_error("An input file/directory is required unless --serve is given");
        }
        return config;
    }

    // ---- Log sink ------------------------------------------------------------------------------
    //
    // Plain function (not a capturing lambda): inventory_sync_server_start() takes a C function
    // pointer. The VD-tagged lines land in --logFile as "function():message" -- the exact format
    // the QA's expected_*.json files grep for, inherited from the legacy tool.

    std::ofstream gLogFile;
    std::mutex gLogMutex;

    volatile std::sig_atomic_t gStopRequested = 0;

    void onStopSignal(int)
    {
        gStopRequested = 1;
    }

    void logSink(int /*level*/,
                 const char* tag,
                 const char* /*file*/,
                 int /*line*/,
                 const char* func,
                 const char* message,
                 va_list args)
    {
        char buffer[65536];
        vsnprintf(buffer, sizeof(buffer), message, args);

        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cout << "[" << (tag ? tag : "?") << "] " << buffer << std::endl;
        if (gLogFile.is_open() && tag && strcmp(tag, WM_VULNSCAN_LOGTAG) == 0)
        {
            gLogFile << (func ? func : "?") << "():" << buffer << std::endl;
            gLogFile.flush();
        }
    }

    // ---- Input format (unchanged from the legacy tool) ------------------------------------------

    struct AgentTestData
    {
        nlohmann::json start;
        std::vector<nlohmann::json> dataValues;
        std::vector<nlohmann::json> dataContexts;
    };

    AgentTestData loadInput(const std::string& filepath)
    {
        std::ifstream file(filepath);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open input file: " + filepath);
        }

        nlohmann::json root = nlohmann::json::parse(file);
        if (!root.contains("Start") || !root["Start"].is_object())
        {
            throw std::runtime_error("Input JSON must contain a 'Start' object: " + filepath);
        }

        AgentTestData data;
        data.start = root["Start"];
        if (root.contains("data_values") && root["data_values"].is_array())
        {
            data.dataValues = root["data_values"].get<std::vector<nlohmann::json>>();
        }
        if (root.contains("data_context") && root["data_context"].is_array())
        {
            data.dataContexts = root["data_context"].get<std::vector<nlohmann::json>>();
        }
        return data;
    }

    std::string inferIndex(const nlohmann::json& entry)
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
            return payload["package"].contains("hotfix") ? HOTFIX_INDEX : PACKAGE_INDEX;
        }
        if (payload.contains("host"))
        {
            return OS_INDEX;
        }
        return {};
    }

    Wazuh::SyncSchema::Option parseOption(const std::string& opt)
    {
        if (opt == "VDFirst")
        {
            return Wazuh::SyncSchema::Option_VDFirst;
        }
        if (opt == "Sync")
        {
            return Wazuh::SyncSchema::Option_Sync;
        }
        return Wazuh::SyncSchema::Option_VDSync;
    }

    Wazuh::SyncSchema::Mode parseMode(const std::string& mode)
    {
        // The FullSession contract has no ModuleFull (D19): a legacy "full" input degrades to the
        // delta mode, which is what the scan path treats it as anyway.
        if (mode == "check" || mode == "ModuleCheck")
        {
            return Wazuh::SyncSchema::Mode_ModuleCheck;
        }
        return Wazuh::SyncSchema::Mode_ModuleDelta;
    }

    // ---- FullSession building --------------------------------------------------------------------

    /// One whole session as one buffer: Message{FullSession{Start, SyncData{values, contexts}}}.
    ///
    /// @param defaultFeedOffset Used verbatim UNLESS the input JSON's Start sets its own
    /// "feed_offset" -- fixtures that mean to exercise a deliberate mismatch (e.g. a stale-offset
    /// 409 test) can still hardcode one. Every other fixture predates the feed_offset gate
    /// (vdScanLane.cpp) entirely, so the caller passes the scanner's actual current offset here;
    /// hardcoding fixtures to a fixed value would silently drift the moment vd_reduced_feed.json's
    /// offsets change.
    std::vector<uint8_t>
    buildFullSession(const AgentTestData& testData, const std::string& clusterName, uint64_t defaultFeedOffset)
    {
        flatbuffers::FlatBufferBuilder builder;
        const auto& startJson = testData.start;

        // Data first (their strings must exist before the Start/SyncData tables reference them).
        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::DataValue>> values;
        std::set<std::string> seenIndices;
        for (const auto& entry : testData.dataValues)
        {
            const auto index = inferIndex(entry);
            if (index.empty())
            {
                std::cerr << "[WARN] data_values entry without inferable index, skipping" << std::endl;
                continue;
            }
            seenIndices.insert(index);

            const auto payload = entry.value("payload", nlohmann::json::object()).dump();
            const auto operation = entry.value("operation", std::string("upsert")) == "delete"
                                       ? Wazuh::SyncSchema::Operation_Delete
                                       : Wazuh::SyncSchema::Operation_Upsert;
            values.push_back(Wazuh::SyncSchema::CreateDataValue(
                builder,
                operation,
                builder.CreateString(entry.value("id", std::string())),
                builder.CreateString(index),
                0,
                builder.CreateVector(reinterpret_cast<const int8_t*>(payload.data()), payload.size())));
        }

        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::DataContext>> contexts;
        for (const auto& entry : testData.dataContexts)
        {
            const auto index = inferIndex(entry);
            if (index.empty())
            {
                std::cerr << "[WARN] data_context entry without inferable index, skipping" << std::endl;
                continue;
            }
            seenIndices.insert(index);

            const auto payload = entry.value("payload", nlohmann::json::object()).dump();
            contexts.push_back(Wazuh::SyncSchema::CreateDataContext(
                builder,
                builder.CreateString(entry.value("id", std::string())),
                builder.CreateString(index),
                builder.CreateVector(reinterpret_cast<const int8_t*>(payload.data()), payload.size())));
        }

        const auto payloadOffset =
            Wazuh::SyncSchema::CreateSyncData(builder, builder.CreateVector(values), builder.CreateVector(contexts));

        // Start.index: explicit list or whatever the data actually touched.
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
            indices.assign(seenIndices.begin(), seenIndices.end());
        }
        std::vector<flatbuffers::Offset<flatbuffers::String>> indexOffsets;
        indexOffsets.reserve(indices.size());
        for (const auto& idx : indices)
        {
            indexOffsets.push_back(builder.CreateString(idx));
        }
        const auto indicesOffset = builder.CreateVector(indexOffsets);

        std::vector<flatbuffers::Offset<flatbuffers::String>> groupOffsets;
        if (startJson.contains("groups") && startJson["groups"].is_array())
        {
            for (const auto& group : startJson["groups"])
            {
                if (group.is_string())
                {
                    groupOffsets.push_back(builder.CreateString(group.get<std::string>()));
                }
            }
        }
        else
        {
            groupOffsets.push_back(builder.CreateString("default"));
        }
        const auto groupsOffset = builder.CreateVector(groupOffsets);

        const auto agentId = startJson.value("agentid", std::string("001"));
        const auto module = builder.CreateString(startJson.value("module", std::string("syscollector")));
        const auto agentIdOffset = builder.CreateString(agentId);
        const auto agentName = builder.CreateString(startJson.value("agentname", "test-agent-" + agentId));
        const auto agentVersion = builder.CreateString(startJson.value("agentversion", std::string("5.0.0")));
        const auto architecture = builder.CreateString(startJson.value("architecture", std::string("x86_64")));
        const auto hostname = builder.CreateString(startJson.value("hostname", std::string("test-host")));
        const auto osname = builder.CreateString(startJson.value("osname", std::string("Ubuntu")));
        const auto osplatform = builder.CreateString(startJson.value("osplatform", std::string("ubuntu")));
        const auto ostype = builder.CreateString(startJson.value("ostype", std::string("linux")));
        const auto osversion = builder.CreateString(startJson.value("osversion", std::string("22.04")));
        // The server enforces Start.cluster_name == its own (403 on mismatch), so this comes from
        // the SAME config value the server was started with.
        const auto clusterNameOffset = builder.CreateString(clusterName);
        const auto feedOffset = startJson.value("feed_offset", defaultFeedOffset);

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_module_(module);
        startBuilder.add_mode(parseMode(startJson.value("mode", std::string("delta"))));
        startBuilder.add_index(indicesOffset);
        startBuilder.add_option(parseOption(startJson.value("option", std::string("VDSync"))));
        startBuilder.add_feed_offset(feedOffset);
        startBuilder.add_architecture(architecture);
        startBuilder.add_hostname(hostname);
        startBuilder.add_osname(osname);
        startBuilder.add_osplatform(osplatform);
        startBuilder.add_ostype(ostype);
        startBuilder.add_osversion(osversion);
        startBuilder.add_agentversion(agentVersion);
        startBuilder.add_agentname(agentName);
        startBuilder.add_agentid(agentIdOffset);
        startBuilder.add_groups(groupsOffset);
        startBuilder.add_cluster_name(clusterNameOffset);
        const auto startOffset = startBuilder.Finish();

        const auto fullSession = Wazuh::SyncSchema::CreateFullSession(
            builder, startOffset, Wazuh::SyncSchema::SessionPayload_SyncData, payloadOffset.Union());
        const auto message =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_FullSession, fullSession.Union());
        builder.Finish(message);

        return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
    }

    // ---- Minimal HTTP/1.1-over-UDS client --------------------------------------------------------

    struct HttpResult
    {
        int status = 0;
        std::string retryAfter;
        std::string body;
    };

    HttpResult postSession(const std::string& socketPath, const std::string& agentId, const std::vector<uint8_t>& body)
    {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            throw std::runtime_error("socket(): " + std::string(strerror(errno)));
        }

        sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socketPath.c_str());
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            const int err = errno;
            ::close(fd);
            throw std::runtime_error("connect(" + socketPath + "): " + strerror(err));
        }

        std::string head =
            "POST /stateful HTTP/1.1\r\nHost: localhost\r\nX-Wazuh-Agent-Id: " + agentId +
            "\r\nContent-Type: application/octet-stream\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\nConnection: close\r\n\r\n";

        auto writeAll = [fd](const char* data, size_t len)
        {
            size_t sent = 0;
            while (sent < len)
            {
                const ssize_t n = ::write(fd, data + sent, len - sent);
                if (n <= 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    throw std::runtime_error("write(): " + std::string(strerror(errno)));
                }
                sent += static_cast<size_t>(n);
            }
        };

        HttpResult result;
        try
        {
            writeAll(head.data(), head.size());
            writeAll(reinterpret_cast<const char*>(body.data()), body.size());

            std::string response;
            char buffer[8192];
            ssize_t n = 0;
            while ((n = ::read(fd, buffer, sizeof(buffer))) > 0)
            {
                response.append(buffer, static_cast<size_t>(n));
            }

            if (response.rfind("HTTP/1.1 ", 0) == 0 && response.size() > 12)
            {
                result.status = std::stoi(response.substr(9, 3));
            }
            // Case-insensitive not needed: the server emits the canonical form.
            const auto retryPos = response.find("Retry-After: ");
            if (retryPos != std::string::npos)
            {
                const auto end = response.find('\r', retryPos);
                result.retryAfter = response.substr(retryPos + 13, end - retryPos - 13);
            }
            const auto bodyPos = response.find("\r\n\r\n");
            if (bodyPos != std::string::npos)
            {
                result.body = response.substr(bodyPos + 4);
            }
        }
        catch (...)
        {
            ::close(fd);
            throw;
        }
        ::close(fd);
        return result;
    }

    bool waitForFile(const std::string& path, uint32_t timeoutSecs)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSecs);
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (std::filesystem::exists(path))
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        return false;
    }
} // namespace

int main(int argc, char* argv[])
{
    // RAII-less by design: on any failure we print and exit non-zero; the QA treats a missing
    // log.out or a non-zero exit as the test failure it is.
    try
    {
        const auto config = parseArgs(argc, argv);

        std::cout << "\n=== inventory_sync_server + VD testtool ===" << std::endl;
        std::cout << "Input: " << config.input << std::endl;

        if (!config.logFile.empty())
        {
            gLogFile.open(config.logFile, std::ios::out | std::ios::app);
            if (!gLogFile.is_open())
            {
                throw std::runtime_error("Failed to open log file: " + config.logFile);
            }
        }

        nlohmann::json moduleConfig = nlohmann::json::object();
        if (!config.configFile.empty())
        {
            moduleConfig = nlohmann::json::parse(std::ifstream(config.configFile));
        }
        const auto clusterName = moduleConfig.value("clusterName", std::string("cluster01"));

        std::filesystem::create_directories("queue/sockets");

        // VD first: the server's start registers its scan coordinator and resolves the production
        // scanner adapter against the running facade. Under --no-vd the facade never starts and
        // the server's adapter degrades to "skip legitimately, index anyway" (D22's skip row).
        auto& vulnerabilityScanner = VulnerabilityScannerFacade::instance();
        if (!config.noVd)
        {
            std::cout << "[INFO] Starting vulnerability scanner..." << std::endl;
            vulnerabilityScanner.start(logSink, moduleConfig, true, true);
        }

        // The server: cluster identity + the <indexer> block, verbatim, as cJSON. The socket only
        // opens once its indexer session and connectors are up, so waiting for the file IS the
        // readiness probe.
        std::cout << "[INFO] Starting inventory sync server..." << std::endl;
        inventory_sync_server_config_t serverConfig {};
        std::snprintf(serverConfig.cluster_name, sizeof(serverConfig.cluster_name), "%s", clusterName.c_str());
        cJSON* indexerJson = nullptr;
        if (moduleConfig.contains("indexer"))
        {
            indexerJson = cJSON_Parse(moduleConfig["indexer"].dump().c_str());
            serverConfig.indexer = indexerJson;
        }

        if (inventory_sync_server_start(logSink, &serverConfig) != 0)
        {
            throw std::runtime_error("inventory_sync_server_start() failed");
        }
        if (!waitForFile(DEFAULT_SOCKET_PATH, 60))
        {
            throw std::runtime_error("The server socket never appeared (is the indexer reachable?)");
        }

        if (config.serve)
        {
            // QA harness mode: the suite talks to the socket itself; this process only keeps the
            // modules alive. The marker line is the suite's readiness probe (the socket file
            // already existed at this point, so "marker printed" implies "accepting").
            std::signal(SIGTERM, onStopSignal);
            std::signal(SIGINT, onStopSignal);
            std::cout << "[INFO] SERVING on " << DEFAULT_SOCKET_PATH << " (SIGTERM to stop)" << std::endl;
            while (gStopRequested == 0)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            std::cout << "\n[INFO] Stopping modules..." << std::endl;
            inventory_sync_server_stop();
            if (!config.noVd)
            {
                vulnerabilityScanner.stop();
            }
            if (indexerJson != nullptr)
            {
                cJSON_Delete(indexerJson);
            }
            return 0;
        }

        // Collect the input files (a single file, or every *.json in a directory, sorted).
        std::vector<std::string> inputs;
        if (std::filesystem::is_directory(config.input))
        {
            for (const auto& entry : std::filesystem::directory_iterator(config.input))
            {
                if (entry.is_regular_file() && entry.path().extension() == ".json")
                {
                    inputs.push_back(entry.path().string());
                }
            }
            std::sort(inputs.begin(), inputs.end());
        }
        else
        {
            inputs.push_back(config.input);
        }

        bool allOk = true;
        for (const auto& input : inputs)
        {
            std::cout << "\n[INFO] Session from: " << input << std::endl;
            const auto testData = loadInput(input);
            const auto agentId = testData.start.value("agentid", std::string("001"));

            // 503 + Retry-After = the CVE feed is still downloading (D17): re-POST until ready.
            // The session is rebuilt on EVERY attempt, not just the first: while this loop
            // sleeps, the feed can finish loading and its offset can move off the 0 it had at
            // the first attempt, so a stale session built before the wait would now get rejected
            // with 409 version_mismatch instead of the retry ever landing.
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(config.feedTimeoutSecs);
            HttpResult result;
            while (true)
            {
                const auto session = buildFullSession(testData, clusterName, vulnerabilityScanner.currentFeedOffset());
                result = postSession(DEFAULT_SOCKET_PATH, agentId, session);
                if (result.status != 503 || result.retryAfter.empty() || std::chrono::steady_clock::now() >= deadline)
                {
                    break;
                }
                const auto delay = std::max(1, std::min(30, std::atoi(result.retryAfter.c_str())));
                std::cout << "[INFO] Feed not ready (503, Retry-After " << result.retryAfter << "); retrying in "
                          << delay << " s..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(delay));
            }

            std::cout << "[INFO] HTTP " << result.status << " " << result.body << std::endl;
            if (result.status != 200)
            {
                std::cerr << "[ERROR] Session was not applied (HTTP " << result.status << ")" << std::endl;
                allOk = false;
            }
        }

        // D22 already guarantees scan+ingest behind each 200; this only lets VD's own async
        // indexing (the vulnerability documents) drain before teardown.
        std::this_thread::sleep_for(std::chrono::seconds(config.waitTime));

        std::cout << "\n[INFO] Stopping modules..." << std::endl;
        inventory_sync_server_stop();
        if (!config.noVd)
        {
            vulnerabilityScanner.stop();
        }
        if (indexerJson != nullptr)
        {
            cJSON_Delete(indexerJson);
        }

        std::cout << (allOk ? "[INFO] Test completed successfully!\n" : "[ERROR] Some sessions failed.\n") << std::endl;
        return allOk ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "\n[ERROR] " << e.what() << std::endl;
        return 1;
    }
}
