#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "agent_sync_protocol_c_wrapper.hpp"
#include <memory>
#include <string>

// Excluding from coverage since these are simple wrappers for their C++ counterparts, which are already included in the coverage.
// LCOV_EXCL_START
extern "C" {

    AgentSyncProtocolHandle* asp_create(const char* module, const char* db_path, const MQ_Functions* mq_funcs, asp_logger_t logger, unsigned int syncEndDelay, unsigned int timeout, unsigned int retries,
                                        size_t maxEps)
    {
        try
        {
#if CLIENT

            if (!mq_funcs || !db_path || !module || !logger) return nullptr;

#else

            if (!db_path || !module || !logger) return nullptr;

#endif
            LoggerFunc logger_wrapper =
                [logger](modules_log_level_t level, const std::string & msg)
            {
                logger(level, msg.c_str());
            };

            return reinterpret_cast<AgentSyncProtocolHandle*>(new AgentSyncProtocolWrapper(module, db_path, *mq_funcs, logger_wrapper, std::chrono::seconds(syncEndDelay), std::chrono::seconds(timeout), retries,
                                                                                           maxEps));
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

    void asp_persist_diff_in_memory(AgentSyncProtocolHandle* handle,
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
            wrapper->impl->persistDifferenceInMemory(id,
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

    bool asp_sync_module(AgentSyncProtocolHandle* handle,
                         Mode_t mode)
    {
        try
        {
            if (!handle) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->synchronizeModule(static_cast<Mode>(mode));
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

    void asp_clear_in_memory_data(AgentSyncProtocolHandle* handle)
    {
        try
        {
            if (!handle) return;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            wrapper->impl->clearInMemoryData();
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

    bool asp_sync_metadata_or_groups(AgentSyncProtocolHandle* handle,
                                     Mode_t mode,
                                     const char** indices,
                                     size_t indices_count,
                                     uint64_t global_version)
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

            return wrapper->impl->synchronizeMetadataOrGroups(static_cast<Mode>(mode),
                                                              indices_vec,
                                                              global_version);
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

} // extern "C"

// LCOV_EXCL_STOP
