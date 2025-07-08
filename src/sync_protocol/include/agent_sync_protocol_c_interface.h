#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Opaque handle to the AgentSyncProtocol C++ object.
///
/// Used to interact with the AgentSyncProtocol instance from C code.
typedef struct AgentSyncProtocol AgentSyncProtocolHandle;

/// @brief Function pointer type for starting a message queue.
///
/// @param key The identifier key for the message queue.
/// @param type The type of queue or message.
/// @param attempts The number of connection attempts.
/// @return Integer status code (0 on success, non-zero on failure).
typedef int (*mq_start_fn)(const char* key, short type, short attempts);

/// @brief Function pointer type for sending a message to the queue.
///
/// @param queue The queue identifier.
/// @param message The message payload to send.
/// @param locmsg Additional location/context message (optional).
/// @param loc A character representing the message location or type.
/// @return Integer status code (0 on success, non-zero on failure).
typedef int (*mq_send_fn)(int queue, const char* message, const char* locmsg, char loc);

/// @brief Struct containing function pointers for MQ operations.
///
/// This structure provides the implementation of MQ start and send operations.
typedef struct MQ_Functions
{
    /// Callback to start a message queue.
    mq_start_fn start;

    /// Callback to send a message.
    mq_send_fn send;
} MQ_Functions;

/// @brief Creates an instance of AgentSyncProtocol.
///
/// @param mq_funcs Pointer to a MQ_Functions struct containing the MQ callbacks.
/// @return A pointer to an opaque AgentSyncProtocol handle, or NULL on failure.
AgentSyncProtocolHandle* asp_create(const MQ_Functions* mq_funcs);

/// @brief Destroys an AgentSyncProtocol instance.
///
/// @param handle Pointer to the AgentSyncProtocol handle to destroy.
void asp_destroy(AgentSyncProtocolHandle* handle);

/// @brief Persists a difference (diff) for synchronization.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param module Module name associated with the diff.
/// @param id Unique identifier for the diff (usually a hash).
/// @param operation Type of operation (create, modify, delete).
/// @param index Target index or destination for the diff.
/// @param data JSON string representing the data to persist.
void asp_persist_diff(AgentSyncProtocolHandle* handle,
                      const char* module,
                      const char* id,
                      int operation,
                      const char* index,
                      const char* data);

// @brief Triggers synchronization of a module.
///
/// @param handle Pointer to the AgentSyncProtocol handle.
/// @param module The name of the module to synchronize.
/// @param mode Synchronization mode (e.g., full, delta).
/// @param realtime Boolean flag (non-zero = realtime mode, zero = batch mode).
void asp_sync_module(AgentSyncProtocolHandle* handle,
                     const char* module,
                     int mode,
                     int realtime);

/// @brief Parses a response buffer encoded in FlatBuffer format.
/// @param handle Protocol handle.
/// @param data Pointer to the FlatBuffer-encoded message.
/// @param size Size of the message in bytes.
/// @return 0 if parsed successfully, -1 on error.
int asp_parse_response_buffer(AgentSyncProtocolHandle* handle, const uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif
