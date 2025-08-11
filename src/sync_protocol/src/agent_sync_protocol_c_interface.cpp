#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol.hpp"
#include "persistent_queue.hpp"
#include "logging_helper.hpp"
#include <chrono>
#include <memory>
#include <string>

/// @brief Provides a shared persistent queue instance for all AgentSyncProtocol instances.
///
/// This function returns a singleton `std::shared_ptr` to a `PersistentQueue`, ensuring
/// that all AgentSyncProtocol objects created through the C interface share the same queue.
///
/// @return A shared pointer to the persistent queue instance.
std::shared_ptr<IPersistentQueue> sharedQueue()
{
    static std::shared_ptr<IPersistentQueue> queue = std::make_shared<PersistentQueue>();
    return queue;
}

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
    /// @param mq_funcs Structure containing the MQ callback functions provided from C.
    AgentSyncProtocolWrapper(const std::string& module, const MQ_Functions& mq_funcs)
        : impl(std::make_unique<AgentSyncProtocol>(module, mq_funcs, sharedQueue())) {}
};

extern "C" {

    AgentSyncProtocolHandle* asp_create(const char* module, const MQ_Functions* mq_funcs, asp_logger_t logger)
    {
        try
        {
            if (!mq_funcs) return nullptr;

            if (logger)
            {
                LoggingHelper::setLogCallback(
                    [logger](const modules_log_level_t level, const char* msg)
                {
                    logger(level, msg);
                }
                );
            }

            return reinterpret_cast<AgentSyncProtocolHandle*>(new AgentSyncProtocolWrapper(module, *mq_funcs));
        }
        catch (const std::exception& ex)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, std::string("asp_create exception: ") + ex.what());
            return nullptr;
        }
        catch (...)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, "asp_create unknown exception");
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
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, std::string("asp_destroy exception: ") + ex.what());
        }
        catch (...)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, "asp_destroy unknown exception");
        }
    }

    void asp_persist_diff(AgentSyncProtocolHandle* handle,
                          const char* id,
                          int operation,
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
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, std::string("asp_persist_diff exception: ") + ex.what());
        }
        catch (...)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, "asp_persist_diff unknown exception");
        }
    }

    bool asp_sync_module(AgentSyncProtocolHandle* handle,
                         int mode,
                         unsigned int sync_timeout,
                         unsigned int retries,
                         size_t max_eps)
    {
        try
        {
            if (!handle) return false;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->synchronizeModule(static_cast<Wazuh::SyncSchema::Mode>(mode),
                                                    std::chrono::seconds(sync_timeout),
                                                    retries,
                                                    max_eps);
        }
        catch (const std::exception& ex)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, std::string("asp_sync_module exception: ") + ex.what());
            return false;
        }
        catch (...)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, "asp_sync_module unknown exception");
            return false;
        }
    }

    int asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data)
    {
        try
        {
            if (!handle || !data) return -1;

            auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
            return wrapper->impl->parseResponseBuffer(data) ? 0 : -1;
        }
        catch (const std::exception& ex)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, std::string("asp_parse_response_buffer exception: ") + ex.what());
            return -1;
        }
        catch (...)
        {
            LoggingHelper::getInstance().log(modules_log_level_t::LOG_ERROR, "asp_parse_response_buffer unknown exception");
            return -1;
        }
    }

} // extern "C"
