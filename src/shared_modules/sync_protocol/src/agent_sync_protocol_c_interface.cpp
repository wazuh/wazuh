#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "agent_sync_protocol_c_wrapper.hpp"
#include "sync_socket_transport.hpp"
#include <cstring>
#include <memory>
#include <string>

// Excluding from coverage since these are simple wrappers for their C++ counterparts, which are already included in the coverage.
// LCOV_EXCL_START
extern "C" {

    void asp_set_session_max_bytes(uint64_t max_session_bytes)
    {
        AgentSyncProtocol::setSessionMaxBytes(static_cast<size_t>(max_session_bytes));
    }

    AgentSyncProtocolHandle* asp_create(const char* module, const char* db_path, asp_logger_t logger)
    {
        try
        {
            if (!module || !logger) return nullptr;

            LoggerFunc logger_wrapper =
                [logger](modules_log_level_t level, const std::string & msg)
            {
                logger(level, msg.c_str());
            };

            std::optional<std::string> dbPathOpt = db_path ? std::make_optional(std::string(db_path)) : std::nullopt;

            return reinterpret_cast<AgentSyncProtocolHandle*>(new AgentSyncProtocolWrapper(module, std::move(dbPathOpt), std::move(logger_wrapper)));
        }
        catch (const std::exception& ex)
        {
            return nullptr;
        }
        catch (...)
        {
            return nullptr;
        }
    }

    void asp_destroy(AgentSyncProtocolHandle* handle)
    {
        try
        {
            delete reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
        }
        catch (const std::exception& ex)
        {
            return;
        }
        catch (...)
        {
            return;
        }
    }

    void asp_persist_diff(AgentSyncProtocolHandle* handle,
                          const char* id,
                          Operation_t operation,
                          const char* index,
                          const char* data,
                          uint64_t version)
    {
        try
        {
            if (!handle || !id || !index || !data) return;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            wrapper->impl->persistDifference(id,
                                             static_cast<Operation>(operation),
                                             index, data, version);
        }
        catch (const std::exception& ex)
        {
            return;
        }
        catch (...)
        {
            return;
        }
    }

    SyncModuleResult_t asp_sync_module(AgentSyncProtocolHandle* handle,
                                       Mode_t mode)
    {
        try
        {
            if (!handle) return {false, {}, false, false, 0};

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);

            SyncModuleResult cppResult = wrapper->impl->synchronizeModule(static_cast<Mode>(mode));

            SyncModuleResult_t cResult;

            cResult.success = cppResult.success;

            strncpy(cResult.failure_reason, cppResult.failureReason.c_str(), SYNC_FAILURE_REASON_MAX_LEN - 1);

            cResult.failure_reason[SYNC_FAILURE_REASON_MAX_LEN - 1] = '\0';

            cResult.stopped = cppResult.stopped;

            cResult.manager_not_ready = cppResult.managerNotReady;

            cResult.consecutive_failures = cppResult.consecutiveFailures;

            cResult.awaiting_prerequisite = cppResult.awaitingPrerequisite;

            return cResult;
        }
        catch (const std::exception& ex)
        {
            return {false, {}, false, false, 0};
        }
        catch (...)
        {
            return {false, {}, false, false, 0};
        }
    }

    bool asp_requires_full_sync(AgentSyncProtocolHandle* handle,
                                const char* index,
                                const char* checksum)
    {
        try
        {
            if (!handle || !index || !checksum) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->requiresFullSync(index, checksum);
        }
        catch (const std::exception& ex)
        {
            return false;
        }
        catch (...)
        {
            return false;
        }
    }

    bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data, size_t length)
    {
        try
        {
            if (!handle || !data) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->parseResponseBuffer(data, length);
        }
        catch (const std::exception& ex)
        {
            return false;
        }
        catch (...)
        {
            return false;
        }
    }

    SyncModuleResult_t asp_sync_metadata_or_groups(AgentSyncProtocolHandle* handle,
                                                   Mode_t mode,
                                                   const char** indices,
                                                   size_t indices_count,
                                                   uint64_t global_version)
    {
        try
        {
            if (!handle || !indices || indices_count == 0) return {false, {}, false, false, 0};

            // Convert C array of strings to C++ vector
            std::vector<std::string> indices_vec;

            indices_vec.reserve(indices_count);

            for (size_t i = 0; i < indices_count; ++i)
            {
                if (indices[i])
                {
                    indices_vec.emplace_back(indices[i]);
                }
            }

            if (indices_vec.empty()) return {false, {}, false, false, 0};

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);

            SyncModuleResult cppResult = wrapper->impl->synchronizeMetadataOrGroups(static_cast<Mode>(mode),
                                                                                    indices_vec,
                                                                                    global_version);

            SyncModuleResult_t cResult;

            cResult.success = cppResult.success;

            strncpy(cResult.failure_reason, cppResult.failureReason.c_str(), SYNC_FAILURE_REASON_MAX_LEN - 1);

            cResult.failure_reason[SYNC_FAILURE_REASON_MAX_LEN - 1] = '\0';

            cResult.stopped = cppResult.stopped;

            cResult.manager_not_ready = cppResult.managerNotReady;

            cResult.consecutive_failures = cppResult.consecutiveFailures;

            cResult.awaiting_prerequisite = cppResult.awaitingPrerequisite;

            return cResult;
        }
        catch (const std::exception& ex)
        {
            return {false, {}, false, false, 0};
        }
        catch (...)
        {
            return {false, {}, false, false, 0};
        }
    }

    bool asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                               const char** indices,
                               size_t indices_count)
    {
        try
        {
            if (!handle || !indices || indices_count == 0) return false;

            // Convert C array of strings to C++ vector
            std::vector<std::string> indices_vec;
            indices_vec.reserve(indices_count);

            for (size_t i = 0; i < indices_count; ++i)
            {
                if (indices[i])
                {
                    indices_vec.emplace_back(indices[i]);
                }
            }

            if (indices_vec.empty()) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->notifyDataClean(indices_vec);
        }
        catch (const std::exception& ex)
        {
            return false;
        }
        catch (...)
        {
            return false;
        }
    }

    void asp_delete_database(AgentSyncProtocolHandle* handle)
    {
        try
        {
            if (!handle) return;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            wrapper->impl->deleteDatabase();
        }
        catch (const std::exception& ex)
        {
            return;
        }
        catch (...)
        {
            return;
        }
    }

    void asp_stop(AgentSyncProtocolHandle* handle)
    {
        try
        {
            if (!handle) return;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            wrapper->impl->stop();
        }
        catch (const std::exception& ex)
        {
            return;
        }
        catch (...)
        {
            return;
        }
    }

    void asp_reset(AgentSyncProtocolHandle* handle)
    {
        try
        {
            if (!handle) return;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            wrapper->impl->reset();
        }
        catch (const std::exception& ex)
        {
            return;
        }
        catch (...)
        {
            return;
        }
    }

    bool asp_should_stop(const AgentSyncProtocolHandle* handle)
    {
        try
        {
            if (!handle) return false;

            auto* wrapper = reinterpret_cast<const AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->shouldStop();
        }
        catch (const std::exception& ex)
        {
            return false;
        }
        catch (...)
        {
            return false;
        }
    }

    void asp_set_session_sender(asp_sync_session_sender_fn sender)
    {
        setInProcessSyncSessionSender(sender);
    }

} // extern "C"

// LCOV_EXCL_STOP
