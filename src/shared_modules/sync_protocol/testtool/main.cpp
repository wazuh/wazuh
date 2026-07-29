/*
 * Wazuh Sync Protocol Test tool
 */

#include <chrono>
#include <iostream>
#include <memory>

#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"

static AgentSyncProtocol* g_proto = nullptr;
const unsigned int retries = 1;
const uint8_t timeout = 2;

/// Stands in for the queue-sync socket: takes the one FullSession message and
/// answers it the way the manager would, with an Ok EndAck for its session.
class LoopbackTransport final : public ISyncSessionTransport
{
    public:
        bool checkStatus() override
        {
            return true;
        }

        bool sendSession(uint64_t session, const std::vector<uint8_t>&) override
        {
            flatbuffers::FlatBufferBuilder builder;
            Wazuh::SyncSchema::EndAckBuilder endAckBuilder(builder);
            endAckBuilder.add_status(Wazuh::SyncSchema::Status::Ok);
            endAckBuilder.add_session(session);
            auto endAckOffset = endAckBuilder.Finish();
            auto message = Wazuh::SyncSchema::CreateMessage(
                               builder, Wazuh::SyncSchema::MessageType::EndAck, endAckOffset.Union());
            builder.Finish(message);
            g_proto->parseResponseBuffer(builder.GetBufferPointer(), builder.GetSize());
            return true;
        }
};

int main()
{
    try
    {
        LoggerFunc testLogger =
            [](modules_log_level_t /*level*/, const std::string & msg)
        {
            std::cout << "[Test sync_protocol]: " << msg << std::endl;
        };

        AgentSyncProtocol proto{"sync_protocol", ":memory:", std::move(testLogger), std::chrono::seconds(timeout), retries,
                                nullptr, std::make_shared<LoopbackTransport>()};
        g_proto = &proto;

        proto.persistDifference("id1", Operation::CREATE, "idx1", "{\"k\":\"v1\"}", 1);
        proto.persistDifference("id2", Operation::MODIFY, "idx2", "{\"k\":\"v2\"}", 2);

        bool ok = proto.synchronizeModule(Mode::FULL).success;
        std::cout << (ok ? "OK" : "FAIL") << std::endl;
        return ok ? 0 : 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[Test sync_protocol] Unhandled exception: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "[Test sync_protocol] Unknown unhandled exception" << std::endl;
        return 1;
    }
}
