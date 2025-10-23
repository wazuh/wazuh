#include <vector>
#include <string>
#include <hashHelper.h>

extern "C" {
    #include "debug_op.h" // Use the same C-style logging as the rest of FIM's code.
}

#include "recovery.h"
#include "agent_sync_protocol_c_wrapper.hpp"
#include "db.hpp"
#include "fimCommonDefs.h"
#include "stringHelper.h"
#include "ipersistent_queue.hpp"
#include "syscheck.h"

// TODO: add a description for the class
extern "C"
{
void fim_recovery_persist_table_and_resync(char* table_name, AgentSyncProtocolHandle* handle, uint32_t sync_response_timeout, long sync_max_eps){
    std::vector<nlohmann::json> recoveryItems = DB::instance().getEveryElement(table_name);
    AgentSyncProtocolWrapper* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
    Utils::HashData hash(Utils::HashType::Sha1);

    for (const nlohmann::json& item : recoveryItems) {
        // Calculate SHA1 hash to get an id for persistDifferenceInMemory()
        std::string id = item["path"];
        try
        {
            hash.update(id.c_str(), id.length());
            const std::vector<unsigned char> hashResult = hash.hash();
            id = Utils::asciiToHex(hashResult);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error{"Error calculating hash: " + std::string(e.what())};
        }
        wrapper->impl->persistDifferenceInMemory(
            id,
            Operation::CREATE,
            table_name,
            item.dump()
        );
        }
        minfo("Persisted %zu recovery items in memory", recoveryItems.size());
        minfo("Starting recovery synchronizattion...");
        bool success = wrapper->impl->synchronizeModule(
            Mode::FULL,
            std::chrono::seconds(sync_response_timeout),
            FIM_SYNC_RETRIES,
            sync_max_eps,
            false // Always false since the recovery process only happens after a succesful sync
        );
        if (success) {
            wrapper->impl->clearInMemoryData();
            minfo("Recovery completed successfully, in-memory data cleared");
        } else {
            minfo("Recovery synchronization failed, will retry later");
        }
    }
}
