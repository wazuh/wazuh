#ifndef GEO_ERROR_CODES_HPP
#define GEO_ERROR_CODES_HPP

#include <base/error.hpp>
#include <string>
#include <string_view>
#include <variant>

namespace geo
{

/**
 * @brief Error codes for GeoIP operations
 *
 * These enum values represent common error conditions.
 */
enum class ErrorCode : uint8_t
{
    SUCCESS = 0,

    // Database-related errors
    DB_NOT_AVAILABLE,
    DB_HANDLE_EXPIRED,
    DB_TYPE_NOT_AVAILABLE,

    // IP/Network errors
    IP_TRANSLATION,
    IP_NOT_FOUND,

    // Data access errors
    DATA_TYPE_MISMATCH,
    DATA_TYPE_MISMATCH_SIMPLE,
    DATA_TYPE_MISMATCH_STRING,
    DATA_TYPE_MISMATCH_UINT32,
    DATA_TYPE_MISMATCH_DOUBLE,
    DATA_ENTRY_EMPTY,

    // MMDB library errors
    MMDB_VALUE_ERROR,
    MMDB_LIBMMDB_ERROR,
    MMDB_RETRIEVAL_ENTRY_LIST,
    MMDB_DUMP_ENTRY,

    // General errors
    UNKNOWN_ERROR
};

/**
 * @brief Get a human-readable description of an error code
 *
 * @param code The error code
 * @return constexpr std::string_view Static string description
 */
constexpr std::string_view getErrorDescription(ErrorCode code) noexcept
{
    switch (code)
    {
        case ErrorCode::SUCCESS: return "Success";

        // Database-related errors
        case ErrorCode::DB_NOT_AVAILABLE: return "Database is not available";
        case ErrorCode::DB_HANDLE_EXPIRED: return "Database handle expired";
        case ErrorCode::DB_TYPE_NOT_AVAILABLE: return "Type doesn't have a database available";

        // IP/Network errors
        case ErrorCode::IP_TRANSLATION: return "Error translating IP address";
        case ErrorCode::IP_NOT_FOUND: return "No data found for the IP address";

        // Data access errors
        case ErrorCode::DATA_TYPE_MISMATCH: return "Data type mismatch";
        case ErrorCode::DATA_TYPE_MISMATCH_SIMPLE: return "Data type is not a simple type";
        case ErrorCode::DATA_TYPE_MISMATCH_STRING: return "Data type is not a string";
        case ErrorCode::DATA_TYPE_MISMATCH_UINT32: return "Data type is not a uint32";
        case ErrorCode::DATA_TYPE_MISMATCH_DOUBLE: return "Data type is not a double";
        case ErrorCode::DATA_ENTRY_EMPTY: return "Entry data list is empty";

        // MMDB library errors
        case ErrorCode::MMDB_VALUE_ERROR: return "Error getting value from MMDB";
        case ErrorCode::MMDB_LIBMMDB_ERROR: return "Error from libmaxminddb";
        case ErrorCode::MMDB_RETRIEVAL_ENTRY_LIST: return "Error getting entry data list";
        case ErrorCode::MMDB_DUMP_ENTRY: return "Error dumping entry data";

        // General errors
        case ErrorCode::UNKNOWN_ERROR: return "Unknown error";
    }
    return "Unknown error code";
}

/**
 * @brief Stream operator for ErrorCode to make it work with assertions and logging
 */
inline std::ostream& operator<<(std::ostream& os, ErrorCode code)
{
    return os << getErrorDescription(code);
}

/**
 * @brief Result type for operations that can fail
 *
 * Similar to std::expected (C++23) but optimized for our use case.
 *
 * @tparam T The success value type
 */
template<typename T>
class Result
{
private:
    std::variant<T, ErrorCode> m_value;

public:
    // Default constructor - initializes with UNKNOWN_ERROR
    Result()
        : m_value(ErrorCode::UNKNOWN_ERROR)
    {
    }

    Result(const T& value)
        : m_value(value)
    {
    }
    Result(T&& value)
        : m_value(std::move(value))
    {
    }
    Result(ErrorCode error)
        : m_value(error)
    {
    }

    // Success/error checking
    bool isSuccess() const noexcept { return std::holds_alternative<T>(m_value); }
    bool isError() const noexcept { return std::holds_alternative<ErrorCode>(m_value); }

    // Value access (only call if isSuccess())
    const T& value() const& { return std::get<T>(m_value); }
    T& value() & { return std::get<T>(m_value); }
    T&& value() && { return std::get<T>(std::move(m_value)); }

    // Error access (only call if isError())
    ErrorCode error() const { return std::get<ErrorCode>(m_value); }

    // Convenience operators
    explicit operator bool() const noexcept { return isSuccess(); }
    const T& operator*() const& { return value(); }
    T& operator*() & { return value(); }
    T&& operator*() && { return std::move(value()); }

    const T* operator->() const { return &value(); }
    T* operator->() { return &value(); }

    friend std::ostream& operator<<(std::ostream& os, const Result<T>& res)
    {
        os << res.readableStr();
        return os;
    }
    /**
     * @brief Convert to human-readable error messages for legacy interfaces
     *
     * @return std::string Human-readable error message for legacy interfaces
     */
    std::string readableStr() const
    {
        if (isSuccess())
        {
            return "success";
        }
        else
        {
            return {std::string {getErrorDescription(error())}};
        }
    }
};

/**
 * @brief Specialization for void operations
 */
template<>
class Result<void>
{
private:
    ErrorCode m_error;

public:
    Result()
        : m_error(ErrorCode::SUCCESS)
    {
    }
    Result(ErrorCode error)
        : m_error(error)
    {
    }

    bool isSuccess() const noexcept { return m_error == ErrorCode::SUCCESS; }
    bool isError() const noexcept { return m_error != ErrorCode::SUCCESS; }

    ErrorCode error() const { return m_error; }

    explicit operator bool() const noexcept { return isSuccess(); }

    /**
     * @brief Convert to human-readable OptError string
     *
     * @return std::string Human-readable error message for legacy interfaces
     */
    std::string readableStr() const
    {
        if (isSuccess())
        {
            return "Success";
        }
        else
        {
            return {std::string {getErrorDescription(m_error)}};
        }
    }
};

using VoidResult = Result<void>;

} // namespace geo

#endif // GEO_ERROR_CODES_HPP