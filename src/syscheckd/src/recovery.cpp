#include <cstdint>
#include <vector>
#include <string>
#include <hashHelper.h>

extern "C" {
    #include "debug_op.h" // Use the same C-style logging as the rest of FIM's code.
}

#include "recovery.h"
#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol_c_wrapper.hpp"
#include "db.hpp"
#include "fimCommonDefs.h"
#include "stringHelper.h"
#include "ipersistent_queue.hpp"
#include "syscheck.h"
#include <chrono>

int64_t getUnixTimeSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

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
        minfo("DBG Version: ", item["version"]);
        wrapper->impl->persistDifferenceInMemory(
            id,
            Operation::CREATE,
            table_name,
            item.dump(),
            item["version"]
        );
        }
        minfo("Persisted %zu recovery items in memory", recoveryItems.size());
        minfo("Starting recovery synchronizattion...");
        bool success = wrapper->impl->synchronizeModule(
            Mode::FULL,
            std::chrono::seconds(sync_response_timeout),
            FIM_SYNC_RETRIES,
            sync_max_eps
        );
        if (success) {
            wrapper->impl->clearInMemoryData();
            minfo("Recovery completed successfully, in-memory data cleared");
        } else {
            minfo("Recovery synchronization failed, will retry later");
        }

        // Update the last sync time regardless of the synchronization result since we always want to wait for intergrity_interval to try again.
        DB::instance().updateLastSyncTime(table_name, getUnixTimeSeconds());
    }
}

bool fim_recovery_check_if_full_sync_required(char* table_name, AgentSyncProtocolHandle* handle, uint32_t sync_response_timeout, long sync_max_eps){

    AgentSyncProtocolWrapper* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);

    minfo("Attempting to get checksum for %s table", table_name);
    std::string concatenated_checksums = DB::instance().getConcatenatedChecksums(table_name);
    //
    // Build checksum-of-checksums
    Utils::HashData hash(Utils::HashType::Sha1);
    std::string final_checksum;
    try
    {
        hash.update(concatenated_checksums.c_str(), concatenated_checksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        final_checksum = Utils::asciiToHex(hashResult);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error{"Error calculating hash: " + std::string(e.what())};
    }

    minfo("Success! Final file table checksum is: %s", final_checksum.c_str());

    bool needs_full_sync = wrapper->impl->requiresFullSync(
        table_name,
        final_checksum,
        std::chrono::seconds(sync_response_timeout),
        FIM_SYNC_RETRIES, 
        sync_max_eps
    );
    if (needs_full_sync) {
        minfo("Checksum mismatch detected for index %s, full sync required", table_name);
        return true;
    } else {
        minfo("Checksum valid for index %s, delta sync sufficient", table_name);
        return false;
    }

}

bool fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval){
    int64_t current_time = getUnixTimeSeconds();
    int64_t last_sync_time =  DB::instance().getLastSyncTime(table_name);
    int64_t new_sync_time = current_time - last_sync_time;
    return (new_sync_time >= integrity_interval) ;
}
