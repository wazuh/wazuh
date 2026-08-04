/*
 * Wazuh Sync Protocol Test tool
 */

#include <chrono>
#include <iostream>
#include <memory>
#include <string>

#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"

static AgentSyncProtocol* g_proto = nullptr;
const unsigned int retries = 1;
const uint8_t timeout = 2;

/// Stands in for the queue-sync socket: takes the one FullSession message and
/// answers it the way the manager would, with a 200 OK /stateful HTTP result
/// for its session.
class LoopbackTransport final : public ISyncSessionTransport
{
    public:
        bool checkStatus() override
        {
            return true;
        }

        bool sendSession(uint64_t session, const std::vector<uint8_t>&) override
        {
            const std::string response = "HCRESULT:" + std::to_string(session) + ":200:";
            g_proto->parseResponseBuffer(reinterpret_cast<const uint8_t*>(response.data()), response.size());
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

        AgentSyncProtocol proto{"sync_protocol", ":memory:", std::move(testLogger),
                                nullptr, std::make_shared<LoopbackTransport>()};
        g_proto = &proto;

        proto.persistDifference("id1", Operation::CREATE, "idx1", "{\"k\":\"v1\"}", 1);
        proto.persistDifference("id2", Operation::MODIFY, "idx2", "{\"k\":\"v2\"}", 2);

        bool ok = proto.synchronizeModule(Mode::DELTA).success;
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
