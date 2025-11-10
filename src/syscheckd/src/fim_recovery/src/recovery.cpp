#include <vector>
#include <string>
#include <hashHelper.h>

#include "recovery.h"
#include "agent_sync_protocol_c_wrapper.hpp"
#include "db.hpp"
#include "stringHelper.h"
#include "syscheck.h"
#include "../../config/syscheck-config.h"

// The time() macro from common.h (Included when running unit_tests) interferes with std::time calls in timeHelper.h
#ifdef time
#undef time
#endif
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

    // Make sure memory is clean before we start to persist
    wrapper->impl->clearInMemoryData();

    std::string id;
    std::string index;
    for (const nlohmann::json& item : recoveryItems) {
        // Calculate SHA1 hash to get an id for persistDifferenceInMemory()
#ifdef WIN32
#endif // WIN32
        if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
            id = item["path"];
            index = FIM_FILES_SYNC_INDEX;
        }
#ifdef WIN32
        else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
            // We use the value of 'architecture' in this way to use the same format for the hash as the one used by registry_key_transaction_callback from registry.c
            // This guarantees persisted entries share a consistent id format.
            int arch = (item["architecture"].get<std::string>() == "[x32]") ? ARCH_32BIT: ARCH_64BIT;
            id = std::to_string(arch) + ":" + item["path"].get<std::string>();
            index = FIM_REGISTRY_KEYS_SYNC_INDEX;
        }
        else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
            int arch = (item["architecture"].get<std::string>() == "[x32]") ? ARCH_32BIT: ARCH_64BIT;
            id = item["path"].get<std::string>() + ":" + std::to_string(arch) + ":" + item["value"].get<std::string>();
            index = FIM_REGISTRY_VALUES_SYNC_INDEX;
        }
#endif // WIN32
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
            index,
            item.dump(),
            item["version"]
        );
    }

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

    // Update the last sync time regardless of the synchronization result since we always want to wait for integrity_interval to try again.
    DB::instance().updateLastSyncTime(table_name, Utils::getSecondsFromEpoch());
}

// Excluding from coverage since this function is a simple wrapper around calculateTableChecksum and requiresFullSync
// LCOV_EXCL_START
bool fim_recovery_check_if_full_sync_required(char* table_name, uint32_t sync_response_timeout, long sync_max_eps, AgentSyncProtocolHandle* handle){
    std::string final_checksum = DB::instance().calculateTableChecksum(table_name);

    bool needs_full_sync;
    AgentSyncProtocolWrapper* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
    std::string index;
    if (strcmp(table_name, FIMDB_FILE_TABLE_NAME) == 0) {
        index = FIM_FILES_SYNC_INDEX;
    }
#ifdef WIN32
    else if (strcmp(table_name, FIMDB_REGISTRY_KEY_TABLENAME) == 0) {
        index = FIM_REGISTRY_KEYS_SYNC_INDEX;
    }
    else if (strcmp(table_name, FIMDB_REGISTRY_VALUE_TABLENAME) == 0) {
        index = FIM_REGISTRY_VALUES_SYNC_INDEX;
    }
#endif // WIN32
    needs_full_sync = wrapper->impl->requiresFullSync(
        index,
        final_checksum,
        std::chrono::seconds(sync_response_timeout),
        FIM_SYNC_RETRIES,
        sync_max_eps
    );

    return needs_full_sync;
}
// LCOV_EXCL_STOP

bool fim_recovery_integrity_interval_has_elapsed(char* table_name, int64_t integrity_interval){
    int64_t current_time = Utils::getSecondsFromEpoch();
    int64_t last_sync_time = DB::instance().getLastSyncTime(table_name);
    int64_t new_sync_time = current_time - last_sync_time;
    return (new_sync_time >= integrity_interval);
}
}
