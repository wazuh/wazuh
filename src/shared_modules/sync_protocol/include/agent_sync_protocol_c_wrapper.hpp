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
    /// @param syncEndDelay Delay for synchronization end message in seconds
    /// @param timeout Default timeout for synchronization operations.
    /// @param retries Default number of retries for synchronization operations.
    /// @param maxEps Default maximum events per second for synchronization operations.
    AgentSyncProtocolWrapper(const std::string& module, const std::string& db_path, const MQ_Functions& mq_funcs, LoggerFunc logger, std::chrono::seconds syncEndDelay, std::chrono::seconds timeout,
                             unsigned int retries, size_t maxEps)
        : impl(std::make_unique<AgentSyncProtocol>(module, db_path, mq_funcs, std::move(logger), syncEndDelay, timeout, retries, maxEps, nullptr)) {}
};

