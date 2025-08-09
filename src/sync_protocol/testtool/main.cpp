/*
 * Wazuh Sync Protocol Test tool
 */

#include <iostream>
#include <filesystem>
#include <chrono>

#include "agent_sync_protocol.hpp"
#include "persistent_queue.hpp"
#include "persistent_queue_storage.hpp"

static AgentSyncProtocol* g_proto = nullptr;
static uint64_t g_session = 1;

static int mq_start_stub(const char*, short, short) { return 1; }

static int mq_send_binary_stub(int, const void* msg, size_t, const char*, char) {
    auto* m = Wazuh::SyncSchema::GetMessage(reinterpret_cast<const uint8_t*>(msg));
    switch (m->content_type()) {
        case Wazuh::SyncSchema::MessageType::Start: {
            flatbuffers::FlatBufferBuilder builder;
            auto module = builder.CreateString("sync_protocol");
            Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
            startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
            startAckBuilder.add_session(g_session);
            startAckBuilder.add_module_(module);
            auto startAckOffset = startAckBuilder.Finish();
            auto message = Wazuh::SyncSchema::CreateMessage(
                builder,
                Wazuh::SyncSchema::MessageType::StartAck,
                startAckOffset.Union());
            builder.Finish(message);
            g_proto->parseResponseBuffer(builder.GetBufferPointer());
            break;
        }
        case Wazuh::SyncSchema::MessageType::End: {
            flatbuffers::FlatBufferBuilder builder;
            auto module = builder.CreateString("sync_protocol");
            Wazuh::SyncSchema::EndAckBuilder endAckBuilder(builder);
            endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
            endAckBuilder.add_session(g_session);
            endAckBuilder.add_module_(module);
            auto endAckOffset = endAckBuilder.Finish();
            auto message = Wazuh::SyncSchema::CreateMessage(
                builder,
                Wazuh::SyncSchema::MessageType::EndAck,
                endAckOffset.Union());
            builder.Finish(message);
            g_proto->parseResponseBuffer(builder.GetBufferPointer());
            break;
        }
        default: break;
    }
    return 0;
}

int main() {
    // Use an in-memory SQLite DB to avoid filesystem issues while exercising real persistence
    auto storage = std::make_shared<PersistentQueueStorage>(":memory:");
    auto queue = std::make_shared<PersistentQueue>(storage);

    MQ_Functions mq{&mq_start_stub, &mq_send_binary_stub};
    AgentSyncProtocol proto{"sync_protocol", mq, queue};
    g_proto = &proto;
  
    proto.persistDifference("id1", Operation::CREATE, "idx1", "{\"k\":\"v1\"}");
    proto.persistDifference("id2", Operation::MODIFY, "idx2", "{\"k\":\"v2\"}");
  
    bool ok = proto.synchronizeModule(Wazuh::SyncSchema::Mode::Full, std::chrono::seconds{2}, 1, 0);
    std::cout << (ok ? "OK" : "FAIL") << std::endl;
    return ok ? 0 : 1;
}
