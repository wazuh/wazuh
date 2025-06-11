#include "epollWrapper.hpp"
#include "external/nlohmann/json.hpp"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/include/inventorySync_generated.h"
#include "inventorySync.hpp"
#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "socketServer.hpp"
#include <chrono>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

void printUsage(const char* progName)
{
    std::cerr << "Usage: " << progName << " <agent_id> <module_name> <num_messages> <socket_path>\n"
              << "  <agent_id>:      Numeric ID of the agent (e.g., 1).\n"
              << "  <module_name>:   Name of the module (e.g., syscollector).\n"
              << "  <num_messages>:  Number of data messages to send.\n";
}

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        printUsage(argv[0]);
        return 1;
    }

    auto& routerModule = RouterModule::instance();
    routerModule.start();

    auto routerProvider = RouterProvider("inventory-states", true);
    routerProvider.start();

    uint32_t agent_id = 0;
    try
    {
        agent_id = std::stoul(argv[1]);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: Invalid agent_id '" << argv[1] << "'. Must be a number.\n";
        return 1;
    }
    const std::string module_name = argv[2];
    uint64_t num_messages = 0;
    try
    {
        num_messages = std::stoull(argv[3]);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: Invalid num_messages '" << argv[3] << "'. Must be a number.\n";
        return 1;
    }
    // Start socket to receive and get the session id
    auto socketServer = SocketServer<Socket<OSPrimitives, AppendHeaderProtocol>, EpollWrapper>("queue/alerts/execq");
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

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Initialize the inventory sync module
    auto& inventorySync = InventorySync::instance();
    inventorySync.start(
        [](const int /*logLevel*/,
           const std::string& tag,
           const std::string& file,
           const int line,
           const std::string& func,
           const std::string& message,
           va_list args)
        {
            // Simple logging function that prints to stdout
            char formattedStr[65536] = {0};
            vsnprintf(formattedStr, sizeof(formattedStr), message.c_str(), args);
            std::cout << tag << ":" << file << ":" << line << " " << func << " : " << formattedStr << "\n";
        },
        nlohmann::json::object());

    // --- 1. Build and Send START message ---
    {
        flatbuffers::FlatBufferBuilder builder;
        auto module_offset = builder.CreateString(module_name);
        auto start_builder = Wazuh::SyncSchema::StartBuilder(builder);
        start_builder.add_agent_id(agent_id);
        start_builder.add_size(num_messages);
        start_builder.add_module_(module_offset);
        start_builder.add_mode(Wazuh::SyncSchema::Mode_Full);
        auto start_offset = start_builder.Finish();

        auto msg_offset =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_Start, start_offset.Union());
        builder.Finish(msg_offset);

        std::cout << "Sending start message" << std::endl;
        std::vector<char> message(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
        routerProvider.send(message);
        std::cout << "[SENT] Start message.\n";
    }

    future.wait();

    // --- 2. Build and Send DATA messages ---
    for (uint64_t i = 0; i < num_messages; ++i)
    {
        flatbuffers::FlatBufferBuilder builder;
        auto json_data = R"({"test":"test"})";
        auto vector_data = builder.CreateVector(reinterpret_cast<const int8_t*>(json_data), strlen(json_data));
        auto index_offset = builder.CreateString("test_index");
        auto id_offset = builder.CreateString("test_id");

        auto data_builder = Wazuh::SyncSchema::DataBuilder(builder);
        data_builder.add_session(session_id);
        data_builder.add_seq(i);
        data_builder.add_operation(Wazuh::SyncSchema::Operation_Upsert);
        data_builder.add_index(index_offset);
        data_builder.add_id(id_offset);
        data_builder.add_data(vector_data);
        auto data_offset = data_builder.Finish();

        auto msg_offset =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_Data, data_offset.Union());
        builder.Finish(msg_offset);

        std::vector<char> message(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
        routerProvider.send(message);
    }

    // --- 3. Build and Send END message ---
    {
        flatbuffers::FlatBufferBuilder builder;
        auto end_builder = Wazuh::SyncSchema::EndBuilder(builder);
        end_builder.add_session(session_id);
        auto end_offset = end_builder.Finish();

        auto msg_offset =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_End, end_offset.Union());
        builder.Finish(msg_offset);

        std::vector<char> message(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
        routerProvider.send(message);
        std::cout << "[SENT] End message.\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(5));
    std::cout << "\nTest sequence finished.\n";

    inventorySync.stop();
    routerProvider.stop();
    routerModule.stop();

    return 0;
}
