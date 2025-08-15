/*
 * Wazuh Inventory Sync
 * Copyright (C) 2015, Wazuh Inc.
 * August 13, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "argsParser.hpp"
#include "epollWrapper.hpp"
#include "external/nlohmann/json.hpp"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/include/agentInfo_generated.h"
#include "flatbuffers/include/inventorySync_generated.h"
#include "inventorySync.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "socketServer.hpp"
#include <chrono>
#include <ctime>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <syslog.h>
#include <thread>
#include <vector>

std::mutex G_MUTEX;
auto constexpr MAX_LEN {65536};

enum class InputType : std::uint8_t
{
    InventorySync,
    Json,
    Invalid
};

int main(const int argc, const char* argv[])
{
    try
    {
        auto& routerModule = RouterModule::instance();
        const auto& inventorySync = InventorySync::instance();
        CmdLineArgs cmdLineArgs(argc, argv);

        // Read json configuration file
        auto configuration = nlohmann::json::parse(std::ifstream(cmdLineArgs.getConfigurationFilePath()));

        routerModule.start();

        auto routerProviderInventoryStates = RouterProvider("inventory-states", true);
        routerProviderInventoryStates.start();

        // Open file to write log.
        std::ofstream logFile;
        if (!cmdLineArgs.getLogFilePath().empty())
        {
            logFile.open(cmdLineArgs.getLogFilePath());
            if (!logFile.is_open())
            {
                throw std::runtime_error("Failed to open log file: " + cmdLineArgs.getLogFilePath());
            }
        }

        const auto logFunction = [&logFile](const int logLevel,
                                            const std::string& tag,
                                            const std::string& file,
                                            const int line,
                                            const std::string& func,
                                            const std::string& message,
                                            va_list args)
        {
            auto pos = file.find_last_of('/');
            if (pos != std::string::npos)
            {
                pos++;
            }
            else
            {
                pos = 0;
            }
            std::string fileName = file.substr(pos, file.size() - pos);
            char formattedStr[MAX_LEN] = {0};
            vsnprintf(formattedStr, MAX_LEN, message.c_str(), args);

            std::lock_guard lock(G_MUTEX);
            // Create a timestamp for the log
            std::time_t t = std::time(nullptr);
            auto timestamp = std::put_time(std::localtime(&t), "%H:%M:%S");

            if (logLevel != LOG_ERROR)
            {
                std::cout << timestamp << " " << tag << ":" << fileName << ":" << line << " " << func << " : "
                          << formattedStr << "\n";
            }
            else
            {
                std::cerr << timestamp << " " << tag << ":" << fileName << ":" << line << " " << func << " : "
                          << formattedStr << "\n";
            }

            if (logFile.is_open())
            {
                logFile << timestamp << " " << tag << ":" << fileName << ":" << line << " " << func << " : "
                        << formattedStr << "\n";
                logFile.flush();
            }
        };

        inventorySync.start(logFunction, configuration);

        // Start socket to receive and get the session id
        auto socketServer =
            SocketServer<Socket<OSPrimitives, AppendHeaderProtocol>, EpollWrapper>("queue/alerts/execq");
        uint64_t session_id = 0;
        std::promise<void> promise;
        auto future = promise.get_future();
        socketServer.listen(
            [&session_id, &promise](
                const int /*fd*/, const char* data, uint32_t size, const char* /*address*/, uint32_t /*address_size*/)
            {
                std::cout << "Received data: " << size << std::endl;
                auto message = Wazuh::SyncSchema::GetMessage(data);
                std::cout << "Message type: " << (int)message->content_type() << std::endl;
                if (message->content_type() == Wazuh::SyncSchema::MessageType_StartAck)
                {
                    auto start = message->content_as<Wazuh::SyncSchema::StartAck>();
                    std::cout << "Session ID: " << start->session() << std::endl;
                    session_id = start->session();
                }
                promise.set_value();
            });

        // Wait for the complete initialization and connection negotiation.
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // If no input files provided, use default test data
        if (cmdLineArgs.getInputFiles().empty())
        {
            std::cout << "No input files provided. Using default test data.\n";

            // Default test parameters
            uint32_t agent_id = 1;
            const std::string module_name = "syscollector";
            uint64_t num_messages = 5;

            // --- 1. Build and Send START message as AgentInfo ---
            {
                // First create the original sync message
                flatbuffers::FlatBufferBuilder syncBuilder;
                auto moduleOffset = syncBuilder.CreateString(module_name);
                auto startBuilder = Wazuh::SyncSchema::StartBuilder(syncBuilder);
                startBuilder.add_agent_id(agent_id);
                startBuilder.add_size(num_messages);
                startBuilder.add_module_(moduleOffset);
                startBuilder.add_mode(Wazuh::SyncSchema::Mode_Full);
                auto startOffset = startBuilder.Finish();

                auto msgOffset = Wazuh::SyncSchema::CreateMessage(
                    syncBuilder, Wazuh::SyncSchema::MessageType_Start, startOffset.Union());
                syncBuilder.Finish(msgOffset);

                // Now wrap it in AgentInfo message
                flatbuffers::FlatBufferBuilder builder;
                std::vector<uint8_t> messageVector(syncBuilder.GetBufferPointer(), 
                                                   syncBuilder.GetBufferPointer() + syncBuilder.GetSize());
                auto agentInfo = Wazuh::Sync::CreateAgentInfoDirect(builder,
                                                                    std::to_string(agent_id).c_str(),
                                                                    "test-agent",
                                                                    "127.0.0.1",
                                                                    "4.0.0",
                                                                    module_name.c_str(),
                                                                    &messageVector);
                builder.Finish(agentInfo);

                std::cout << "Sending start message" << std::endl;
                std::vector<char> message(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
                routerProviderInventoryStates.send(message);
                std::cout << "[SENT] Start message (" << message.size() << " bytes) \t ";
                for (unsigned char c : message)
                {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
                }
                std::cout << std::dec << "\n";
            }

            future.wait();

            // --- 2. Build and Send DATA messages as AgentInfo ---
            for (uint64_t i = 0; i < num_messages; ++i)
            {
                // First create the original sync message
                flatbuffers::FlatBufferBuilder syncBuilder;
                auto json_data = R"({"test":"test","sequence":)" + std::to_string(i) + "}";
                auto vector_data =
                    syncBuilder.CreateVector(reinterpret_cast<const int8_t*>(json_data.c_str()), json_data.length());
                auto index_offset = syncBuilder.CreateString("test_index");
                auto id_offset = syncBuilder.CreateString("test_id_" + std::to_string(i));

                auto data_builder = Wazuh::SyncSchema::DataBuilder(syncBuilder);
                data_builder.add_session(session_id);
                data_builder.add_seq(i);
                data_builder.add_operation(Wazuh::SyncSchema::Operation_Upsert);
                data_builder.add_index(index_offset);
                data_builder.add_id(id_offset);
                data_builder.add_data(vector_data);
                auto data_offset = data_builder.Finish();

                auto msg_offset =
                    Wazuh::SyncSchema::CreateMessage(syncBuilder, Wazuh::SyncSchema::MessageType_Data, data_offset.Union());
                syncBuilder.Finish(msg_offset);

                // Now wrap it in AgentInfo message
                flatbuffers::FlatBufferBuilder builder;
                std::vector<uint8_t> messageVector(syncBuilder.GetBufferPointer(), 
                                                   syncBuilder.GetBufferPointer() + syncBuilder.GetSize());
                auto agentInfo = Wazuh::Sync::CreateAgentInfoDirect(builder,
                                                                    std::to_string(agent_id).c_str(),
                                                                    "test-agent",
                                                                    "127.0.0.1",
                                                                    "4.0.0",
                                                                    module_name.c_str(),
                                                                    &messageVector);
                builder.Finish(agentInfo);

                std::vector<char> message(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
                routerProviderInventoryStates.send(message);
                std::cout << "[SENT] Data message " << i << ".\n";
            }

            // --- 3. Build and Send END message as AgentInfo ---
            {
                // First create the original sync message
                flatbuffers::FlatBufferBuilder syncBuilder;
                auto end_builder = Wazuh::SyncSchema::EndBuilder(syncBuilder);
                end_builder.add_session(session_id);
                auto end_offset = end_builder.Finish();

                auto msg_offset =
                    Wazuh::SyncSchema::CreateMessage(syncBuilder, Wazuh::SyncSchema::MessageType_End, end_offset.Union());
                syncBuilder.Finish(msg_offset);

                // Now wrap it in AgentInfo message
                flatbuffers::FlatBufferBuilder builder;
                std::vector<uint8_t> messageVector(syncBuilder.GetBufferPointer(), 
                                                   syncBuilder.GetBufferPointer() + syncBuilder.GetSize());
                auto agentInfo = Wazuh::Sync::CreateAgentInfoDirect(builder,
                                                                    std::to_string(agent_id).c_str(),
                                                                    "test-agent",
                                                                    "127.0.0.1",
                                                                    "4.0.0",
                                                                    module_name.c_str(),
                                                                    &messageVector);
                builder.Finish(agentInfo);

                std::vector<char> message(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
                routerProviderInventoryStates.send(message);
                std::cout << "[SENT] End message.\n";
            }
        }
        else
        {
            // Process input files
            for (const auto& inputFile : cmdLineArgs.getInputFiles())
            {
                std::cout << "Processing file: " << inputFile << "\n";

                // Parse inputFile JSON.
                auto jsonInputFile = nlohmann::json::parse(std::ifstream(inputFile));

                InputType inputType = InputType::Invalid;

                // Check if this is an inventory sync message
                if (jsonInputFile.contains("message_type") && jsonInputFile.contains("content"))
                {
                    std::cout << "Processing inventory sync message\n";
                    inputType = InputType::InventorySync;
                }
                else
                {
                    std::cout << "Processing json file\n";
                    inputType = InputType::Json;
                }

                if (inputType == InputType::InventorySync)
                {
                    // Process as inventory sync message
                    std::string messageType = jsonInputFile["message_type"];

                    if (messageType == "start")
                    {
                        auto content = jsonInputFile["content"];
                        uint32_t agent_id = content.value("agent_id", 1);
                        uint64_t size = content.value("size", 1);
                        std::string module_name = content.value("module", "syscollector");

                        // First create the original sync message
                        flatbuffers::FlatBufferBuilder syncBuilder;
                        auto module_offset = syncBuilder.CreateString(module_name);
                        auto start_builder = Wazuh::SyncSchema::StartBuilder(syncBuilder);
                        start_builder.add_agent_id(agent_id);
                        start_builder.add_size(size);
                        start_builder.add_module_(module_offset);
                        start_builder.add_mode(Wazuh::SyncSchema::Mode_Full);
                        auto start_offset = start_builder.Finish();

                        auto msg_offset = Wazuh::SyncSchema::CreateMessage(
                            syncBuilder, Wazuh::SyncSchema::MessageType_Start, start_offset.Union());
                        syncBuilder.Finish(msg_offset);

                        // Now wrap it in AgentInfo message
                        flatbuffers::FlatBufferBuilder builder;
                        std::vector<uint8_t> messageVector(syncBuilder.GetBufferPointer(), 
                                                           syncBuilder.GetBufferPointer() + syncBuilder.GetSize());
                        auto agentInfo = Wazuh::Sync::CreateAgentInfoDirect(builder,
                                                                            std::to_string(agent_id).c_str(),
                                                                            "test-agent",
                                                                            "127.0.0.1",
                                                                            "4.0.0",
                                                                            module_name.c_str(),
                                                                            &messageVector);
                        builder.Finish(agentInfo);

                        std::vector<char> message(builder.GetBufferPointer(),
                                                  builder.GetBufferPointer() + builder.GetSize());
                        routerProviderInventoryStates.send(message);

                        future.wait();
                    }
                    else if (messageType == "data")
                    {
                        auto content = jsonInputFile["content"];
                        uint64_t seq = content.value("seq", 0);
                        std::string operation = content.value("operation", "upsert");
                        std::string index = content.value("index", "default_index");
                        std::string id = content.value("id", "default_id");
                        std::string data = content.value("data", "{}");
                        uint32_t agent_id = content.value("agent_id", 1);
                        std::string module_name = content.value("module", "syscollector");

                        // First create the original sync message
                        flatbuffers::FlatBufferBuilder syncBuilder;
                        auto vector_data =
                            syncBuilder.CreateVector(reinterpret_cast<const int8_t*>(data.c_str()), data.length());
                        auto index_offset = syncBuilder.CreateString(index);
                        auto id_offset = syncBuilder.CreateString(id);

                        auto data_builder = Wazuh::SyncSchema::DataBuilder(syncBuilder);
                        data_builder.add_session(session_id);
                        data_builder.add_seq(seq);
                        data_builder.add_operation(operation == "delete" ? Wazuh::SyncSchema::Operation_Delete
                                                                         : Wazuh::SyncSchema::Operation_Upsert);
                        data_builder.add_index(index_offset);
                        data_builder.add_id(id_offset);
                        data_builder.add_data(vector_data);
                        auto data_offset = data_builder.Finish();

                        auto msg_offset = Wazuh::SyncSchema::CreateMessage(
                            syncBuilder, Wazuh::SyncSchema::MessageType_Data, data_offset.Union());
                        syncBuilder.Finish(msg_offset);

                        // Now wrap it in AgentInfo message
                        flatbuffers::FlatBufferBuilder builder;
                        std::vector<uint8_t> messageVector(syncBuilder.GetBufferPointer(), 
                                                           syncBuilder.GetBufferPointer() + syncBuilder.GetSize());
                        auto agentInfo = Wazuh::Sync::CreateAgentInfoDirect(builder,
                                                                            std::to_string(agent_id).c_str(),
                                                                            "test-agent",
                                                                            "127.0.0.1",
                                                                            "4.0.0",
                                                                            module_name.c_str(),
                                                                            &messageVector);
                        builder.Finish(agentInfo);

                        std::vector<char> message(builder.GetBufferPointer(),
                                                  builder.GetBufferPointer() + builder.GetSize());
                        routerProviderInventoryStates.send(message);
                    }
                    else if (messageType == "end")
                    {
                        auto content = jsonInputFile["content"];
                        uint32_t agent_id = content.value("agent_id", 1);
                        std::string module_name = content.value("module", "syscollector");

                        // First create the original sync message
                        flatbuffers::FlatBufferBuilder syncBuilder;
                        auto end_builder = Wazuh::SyncSchema::EndBuilder(syncBuilder);
                        end_builder.add_session(session_id);
                        auto end_offset = end_builder.Finish();

                        auto msg_offset = Wazuh::SyncSchema::CreateMessage(
                            syncBuilder, Wazuh::SyncSchema::MessageType_End, end_offset.Union());
                        syncBuilder.Finish(msg_offset);

                        // Now wrap it in AgentInfo message
                        flatbuffers::FlatBufferBuilder builder;
                        std::vector<uint8_t> messageVector(syncBuilder.GetBufferPointer(), 
                                                           syncBuilder.GetBufferPointer() + syncBuilder.GetSize());
                        auto agentInfo = Wazuh::Sync::CreateAgentInfoDirect(builder,
                                                                            std::to_string(agent_id).c_str(),
                                                                            "test-agent",
                                                                            "127.0.0.1",
                                                                            "4.0.0",
                                                                            module_name.c_str(),
                                                                            &messageVector);
                        builder.Finish(agentInfo);

                        std::vector<char> message(builder.GetBufferPointer(),
                                                  builder.GetBufferPointer() + builder.GetSize());
                        routerProviderInventoryStates.send(message);
                    }
                }
                else
                {
                    // Process as raw JSON data
                    const auto jsonData = jsonInputFile;
                    std::vector<char> buffer {jsonData.dump().begin(), jsonData.dump().end()};
                    routerProviderInventoryStates.send(buffer);
                }

                // Wait between file processing
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        std::cout << "Waiting before exit...\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));

        routerProviderInventoryStates.stop();
        inventorySync.stop();
        routerModule.stop();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << "\n";
        CmdLineArgs::showHelp();
        return 1;
    }
    return 0;
}
