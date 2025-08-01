#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol.hpp"
#include "persistent_queue.hpp"
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
    /// @param mq_funcs Structure containing the MQ callback functions provided from C.
    AgentSyncProtocolWrapper(const MQ_Functions& mq_funcs)
        : impl(std::make_unique<AgentSyncProtocol>(mq_funcs, sharedQueue())) {}
};

extern "C" {

    AgentSyncProtocolHandle* asp_create(const MQ_Functions* mq_funcs)
    {
        if (!mq_funcs) return nullptr;

        return reinterpret_cast<AgentSyncProtocolHandle*>(new AgentSyncProtocolWrapper(*mq_funcs));
    }

    void asp_destroy(AgentSyncProtocolHandle* handle)
    {
        delete reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
    }

    size_t asp_persist_diff(AgentSyncProtocolHandle* handle,
                            const char* id,
                            int operation,
                            const char* index,
                            const char* data)
    {
        if (!handle || !id || !index || !data) return 0;

        auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
        return wrapper->impl->persistDifference(id,
                                                static_cast<Operation>(operation),
                                                index, data);
    }

    bool asp_sync_module(AgentSyncProtocolHandle* handle,
                         const char* module,
                         int mode,
                         unsigned int sync_timeout,
                         unsigned int retries,
                         size_t max_amount)
    {
        if (!handle || !module) return false;

        auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
        return wrapper->impl->synchronizeModule(module,
                                                static_cast<Wazuh::SyncSchema::Mode>(mode),
                                                std::chrono::seconds(sync_timeout),
                                                retries,
                                                max_amount);
    }

    int asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data)
    {
        if (!handle || !data) return -1;

        auto* wrapper = reinterpret_cast<AgentSyncProtocolWrapper*>(handle);
        return wrapper->impl->parseResponseBuffer(data) ? 0 : -1;
    }

} // extern "C"
