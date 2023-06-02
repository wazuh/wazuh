#ifndef _KVDB_EXCEPT_H
#define _KVDB_EXCEPT_H

#include <exception>
#include <string>

namespace kvdbManager
{

/**
 * @brief Exception thrown when critical KVDB Functions Fails
 */
class KVDBException : public std::exception
{

public:
    enum class Type
    {
        // 0 is reserved for success
        UNKNOWN_ERROR = 1,    ///< Unknown error (default)
        FILESYSTEM_ERROR,     ///< Filesystem related error
        DATABASE_IN_USE_ERROR ///< Database is in use
    };

    /**
     * @brief Construct a new KVDB Exception object
     *
     * @param msg Error message
     * @param errorType Error type
     */
    KVDBException(const std::string& msg, Type errorType = Type::UNKNOWN_ERROR)
        : m_errorMsg(msg)
        , m_errorType(errorType)
    {
    }

    /**
     * @brief Get the error message
     *
     * @return Error message
     */
    const char* what() const noexcept override { return m_errorMsg.c_str(); }

    /**
     * @brief Get the error type
     *
     * @return Type
     */
    Type getErrorType() const { return m_errorType; }

    /**
     * @brief Get the error type as int
     *
     * @return int Code Error type
     */
    int getErrorTypeAsInt() const { return static_cast<int>(m_errorType); }

    /**
     * @brief Get the description of the error type
     *
     * @return std::string Error type description
     */
    std::string getErrorTypeDescription() const
    {
        switch (m_errorType)
        {
            case Type::UNKNOWN_ERROR: return "Unknown error";
            case Type::FILESYSTEM_ERROR: return "Filesystem error";
            default: return "Invalid error type";
        }
    }

private:
    std::string m_errorMsg; ///< Error message
    Type m_errorType;       ///< Error type
};

} // namespace kvdbManager

#endif // _KVDB_EXCEPT_H
