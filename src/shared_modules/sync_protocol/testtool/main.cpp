/*
 * Wazuh Sync Protocol Test tool
 */

#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "metadata_provider.h"

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

/// Publishes the dummy agent metadata AgentSyncProtocol needs to build a Start
/// message (agent-info's job in a real agent) and clears it back out on scope
/// exit. Without this, waitMetadataAndBuildStart() has nothing to read and the
/// synchronization defers to its own retry cycle instead of ever sending.
class ScopedTestMetadata
{
    public:
        ScopedTestMetadata()
        {
            // metadata_provider_update() opens SHM_PATH with O_CREAT but does not create
            // its parent directory; without it the provider silently has no metadata to serve.
            std::filesystem::create_directories("var/run");

            agent_metadata_t metadata{};
            std::strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
            std::strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
            std::strncpy(metadata.agent_version, "5.0.0", sizeof(metadata.agent_version) - 1);
            std::strncpy(metadata.architecture, "x86_64", sizeof(metadata.architecture) - 1);
            std::strncpy(metadata.hostname, "test-host", sizeof(metadata.hostname) - 1);
            std::strncpy(metadata.os_name, "Linux", sizeof(metadata.os_name) - 1);
            std::strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
            std::strncpy(metadata.os_platform, "ubuntu", sizeof(metadata.os_platform) - 1);
            std::strncpy(metadata.os_version, "24.04", sizeof(metadata.os_version) - 1);
            char* groups[] = {const_cast<char*>("default")};
            metadata.groups = groups;
            metadata.groups_count = 1;
            metadata.vd_feed_offset = 1;
            metadata_provider_update(&metadata);
        }

        ~ScopedTestMetadata()
        {
            metadata_provider_reset();
            std::error_code ec;
            std::filesystem::remove_all("var", ec);
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

        ScopedTestMetadata testMetadata;

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
