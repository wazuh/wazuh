#include <vector>
#include <string>
#include <hashHelper.h>

extern "C" {
    #include "debug_op.h" // Use the same C-style logging as the rest of FIM's code.
}

#include "recovery.h"
#include "agent_sync_protocol_c_wrapper.hpp"
#include "db.hpp"
#include "stringHelper.h"
#include "syscheck.h"
#include "timeHelper.h"

/**
 * @brief Calculate the checksum-of-checksums for a table
 * @param table_name The table to calculate checksum for
 * @return The SHA1 checksum-of-checksums as a hex string
 */

extern "C"
{
void fim_recovery_persist_table_and_resync(char* table_name, uint32_t sync_response_timeout, long sync_max_eps, AgentSyncProtocolHandle* handle, SynchronizeModuleCallback test_callback){
    std::vector<nlohmann::json> recoveryItems = DB::instance().getEveryElement(table_name);
    AgentSyncProtocolWrapper* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);

    for (const nlohmann::json& item : recoveryItems) {
        // Calculate SHA1 hash to get an id for persistDifferenceInMemory()
        std::string id = item["path"];
        try
        {
            Utils::HashData hash(Utils::HashType::Sha1);
            hash.update(id.c_str(), id.length());
            const std::vector<unsigned char> hashResult = hash.hash();
            id = Utils::asciiToHex(hashResult);
        }
        // LCOV_EXCL_START
        catch (const std::exception& e)
        {
            throw std::runtime_error{"Error calculating hash: " + std::string(e.what())};
        }
        // LCOV_EXCL_STOP
        wrapper->impl->persistDifferenceInMemory(
            id,
            Operation::CREATE,
            table_name,
            item.dump(),
            item["version"]
        );
    }
    minfo("Persisted %zu recovery items in memory", recoveryItems.size());
    minfo("Starting recovery synchronization...");

    // The test_callback parameter allows unit tests to inject custom synchronizeModule behavior.
    // This is necessary because AgentSyncProtocolWrapper's implementation cannot be easily mocked
    // without significant refactoring of the wrapper architecture.
    bool success;
    if (test_callback) {
        // Use test callback in tests
        success = test_callback();
    } else {
        // Use real implementation in production
        // LCOV_EXCL_START
        success = wrapper->impl->synchronizeModule(
            Mode::FULL,
            std::chrono::seconds(sync_response_timeout),
            FIM_SYNC_RETRIES,
            sync_max_eps
        );
        // LCOV_EXCL_STOP

    }

    if (success) {
        wrapper->impl->clearInMemoryData();
        minfo("Recovery completed successfully, in-memory data cleared");
    } else {
        minfo("Recovery synchronization failed, will retry later");
    }

    // Update the last sync time regardless of the synchronization result since we always want to wait for integrity_interval to try again.
    DB::instance().updateLastSyncTime(table_name, Utils::getSecondsFromEpoch());
}

// Excluding from coverage since this function is a simple wrapper around calculateTableChecksum and requiresFullSync
// LCOV_EXCL_START
bool fim_recovery_check_if_full_sync_required(char* table_name, uint32_t sync_response_timeout, long sync_max_eps, AgentSyncProtocolHandle* handle){
    minfo("Attempting to get checksum for %s table", table_name);
    std::string final_checksum = DB::instance().calculateTableChecksum(table_name);
    minfo("Success! Final file table checksum is: %s", final_checksum.c_str());

    bool needs_full_sync;
    AgentSyncProtocolWrapper* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
    needs_full_sync = wrapper->impl->requiresFullSync(
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
// LCOV_EXCL_STOP

bool fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval){
    int64_t current_time = Utils::getSecondsFromEpoch();
    int64_t last_sync_time = DB::instance().getLastSyncTime(table_name);
    int64_t new_sync_time = current_time - last_sync_time;
    return (new_sync_time >= integrity_interval);
}
}
