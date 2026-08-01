#include <optional>
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
    /// @param db_path Optional path to the SQLite database file. If not provided, only in-memory synchronization is available.
    /// @param logger Logger function
    AgentSyncProtocolWrapper(const std::string& module, std::optional<std::string> db_path, LoggerFunc logger)
        : impl(std::make_unique<AgentSyncProtocol>(module, db_path, std::move(logger))) {}
};

