#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "persistent_queue.hpp"
#include <chrono>
#include <memory>
#include <string>

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
                          const char* data)
    {
        try
        {
            if (!handle || !id || !index || !data) return;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            wrapper->impl->persistDifference(id,
                                             static_cast<Operation>(operation),
                                             index, data);
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

} // extern "C"
