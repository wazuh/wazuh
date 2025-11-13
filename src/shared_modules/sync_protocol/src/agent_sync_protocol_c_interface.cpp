#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "persistent_queue.hpp"
#include <chrono>
#include <memory>
#include <string>

// LCOV_EXCL_START

/// @brief Wrapper struct that encapsulates the C++ AgentSyncProtocol implementation.
///
/// This wrapper is used to bridge the C interface and the internal C++ logic.
/// It holds a unique_ptr to the actual `AgentSyncProtocol` instance, and is
/// referenced via a C-compatible opaque pointer (`AgentSyncProtocolHandle*`).
struct AgentSyncProtocolWrapper
{
    /// @brief The actual C++ implementation instance.
    std::unique_ptr<AgentSyncProtocol> impl;

    /// @brief Constructs the wrapper and initializes the AgentSyncProtocol instance.
    ///
    /// @param module Name of the module associated with this instance.
    /// @param db_path Path to the SQLite database file for this protocol instance.
    /// @param logger Logger function
    /// @param mq_funcs Structure containing the MQ callback functions provided from C.
    AgentSyncProtocolWrapper(const std::string& module, const std::string& db_path, const MQ_Functions& mq_funcs, LoggerFunc logger)
        : impl(std::make_unique<AgentSyncProtocol>(module, db_path, mq_funcs, std::move(logger), nullptr)) {}
};

extern "C" {

    AgentSyncProtocolHandle* asp_create(const char* module, const char* db_path, const MQ_Functions* mq_funcs, asp_logger_t logger)
    {
        try
        {
            if (!mq_funcs || !db_path || !module || !logger) return nullptr;

            LoggerFunc logger_wrapper =
                [logger](modules_log_level_t level, const std::string & msg)
            {
                logger(level, msg.c_str());
            };

            return reinterpret_cast<AgentSyncProtocolHandle*>(new AgentSyncProtocolWrapper(module, db_path, *mq_funcs, logger_wrapper));
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
                         Mode_t mode,
                         unsigned int sync_timeout,
                         unsigned int retries,
                         size_t max_eps)
    {
        try
        {
            if (!handle) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->synchronizeModule(static_cast<Mode>(mode),
                                                    std::chrono::seconds(sync_timeout),
                                                    retries,
                                                    max_eps);
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
                                const char* checksum,
                                unsigned int sync_timeout,
                                unsigned int retries,
                                size_t max_eps)
    {
        try
        {
            if (!handle || !index || !checksum) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->requiresFullSync(index,
                                                   checksum,
                                                   std::chrono::seconds(sync_timeout),
                                                   retries,
                                                   max_eps);
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
                                     unsigned int sync_timeout,
                                     unsigned int retries,
                                     size_t max_eps,
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
                                                              std::chrono::seconds(sync_timeout),
                                                              retries,
                                                              max_eps,
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
                               size_t indices_count,
                               unsigned int sync_timeout,
                               unsigned int retries,
                               size_t max_eps)
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
            return wrapper->impl->notifyDataClean(indices_vec,
                                                  std::chrono::seconds(sync_timeout),
                                                  retries,
                                                  max_eps);
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
