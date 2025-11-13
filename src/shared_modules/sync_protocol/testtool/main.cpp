/*
 * Wazuh Sync Protocol Test tool
 */

#include <iostream>
#include <chrono>

#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "agent_sync_protocol_c_interface.h"

static AgentSyncProtocol* g_proto = nullptr;
static uint64_t g_session = 1;

static int mq_start_stub(const char*, short, short) { return 1; }

static int mq_send_binary_stub(int, const void* msg, size_t, const char*, char) {
    auto* m = Wazuh::SyncSchema::GetMessage(reinterpret_cast<const uint8_t*>(msg));
    switch (m->content_type()) {
        case Wazuh::SyncSchema::MessageType::Start: {
            flatbuffers::FlatBufferBuilder builder;
            Wazuh::SyncSchema::StartAckBuilder startAckBuilder(builder);
            startAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
            startAckBuilder.add_session(g_session);
            auto startAckOffset = startAckBuilder.Finish();
            auto message = Wazuh::SyncSchema::CreateMessage(
                builder,
                Wazuh::SyncSchema::MessageType::StartAck,
                startAckOffset.Union());
            builder.Finish(message);
            g_proto->parseResponseBuffer(builder.GetBufferPointer(), builder.GetSize());
            break;
        }
        case Wazuh::SyncSchema::MessageType::End: {
            flatbuffers::FlatBufferBuilder builder;
            Wazuh::SyncSchema::EndAckBuilder endAckBuilder(builder);
            endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
            endAckBuilder.add_session(g_session);
            auto endAckOffset = endAckBuilder.Finish();
            auto message = Wazuh::SyncSchema::CreateMessage(
                builder,
                Wazuh::SyncSchema::MessageType::EndAck,
                endAckOffset.Union());
            builder.Finish(message);
            g_proto->parseResponseBuffer(builder.GetBufferPointer(), builder.GetSize());
            break;
        }
        default: break;
    }
    return 0;
}

int main() {

    LoggerFunc testLogger =
    [](modules_log_level_t /*level*/, const std::string& msg) {
        std::cout << "[Test sync_protocol]: " << msg << std::endl;
    };

    MQ_Functions mq{&mq_start_stub, &mq_send_binary_stub};
    AgentSyncProtocol proto{"sync_protocol", ":memory:", mq, testLogger, nullptr};
    g_proto = &proto;

    proto.persistDifference("id1", Operation::CREATE, "idx1", "{\"k\":\"v1\"}", 1);
    proto.persistDifference("id2", Operation::MODIFY, "idx2", "{\"k\":\"v2\"}", 2);

    bool ok = proto.synchronizeModule(Mode::FULL, std::chrono::seconds{2}, 1, 0);
    std::cout << (ok ? "OK" : "FAIL") << std::endl;
    return ok ? 0 : 1;
}
