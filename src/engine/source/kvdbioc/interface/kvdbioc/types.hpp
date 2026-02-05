#ifndef _KVDBIOC_TYPES_HPP
#define _KVDBIOC_TYPES_HPP

#include <cstddef>
#include <string>
#include <vector>

namespace kvdbioc
{
/**
 * @brief DB State Machine (Simplified)
 *
 * State transitions:
 * - READY → DELETING → (destroyed)
 *
 * Note: SWAPPING state removed - structuralMutex already serializes operations
 */
enum class DbState
{
    READY,   ///< Ready for all operations (read/write/swap)
    DELETING ///< Being deleted (reject new operations, reads may continue)
};

/**
 * @brief Error codes for KVDB operations
 */
enum class ErrorCode
{
    OK,                ///< Success
    DB_NOT_FOUND,      ///< DB not registered
    NO_INSTANCE,       ///< DB exists but no instance published
    ALREADY_EXISTS,    ///< DB already exists (for add)
    BUILD_IN_PROGRESS, ///< Build already in progress
    NO_BUILD,          ///< No build in progress (for put/hotSwap)
    STATE_BUSY,        ///< DB in SWAPPING or DELETING state
    IN_USE,            ///< Cannot delete while in use
    ROCKSDB_ERROR,     ///< RocksDB operation failed
    JSON_PARSE_ERROR,  ///< JSON parsing failed
    FILESYSTEM_ERROR   ///< Filesystem operation failed
};

/**
 * @brief Convert error code to human-readable string
 */
inline const char* toString(ErrorCode code)
{
    switch (code)
    {
        case ErrorCode::OK: return "OK";
        case ErrorCode::DB_NOT_FOUND: return "DB_NOT_FOUND";
        case ErrorCode::NO_INSTANCE: return "NO_INSTANCE";
        case ErrorCode::ALREADY_EXISTS: return "ALREADY_EXISTS";
        case ErrorCode::BUILD_IN_PROGRESS: return "BUILD_IN_PROGRESS";
        case ErrorCode::NO_BUILD: return "NO_BUILD";
        case ErrorCode::STATE_BUSY: return "STATE_BUSY";
        case ErrorCode::IN_USE: return "IN_USE";
        case ErrorCode::ROCKSDB_ERROR: return "ROCKSDB_ERROR";
        case ErrorCode::JSON_PARSE_ERROR: return "JSON_PARSE_ERROR";
        case ErrorCode::FILESYSTEM_ERROR: return "FILESYSTEM_ERROR";
        default: return "UNKNOWN";
    }
}

} // namespace kvdbioc

#endif // _KVDBIOC_TYPES_HPP
