#ifndef _CMDS_APIEXCEPT_HPP
#define _CMDS_APIEXCEPT_HPP

#include <exception>
#include <string>

namespace cmd {

/**
 * @brief Error type
 *
 * Error type for the API client, used in ClientException
 * The error type is used to identify the error type and always be greater than 0
 */

/**
 * @brief Exception thrown when the API client fails
 */
class ClientException : public std::exception {

public:
    enum class Type {
        // 0 is reserved for success
        UNKNOWN_ERROR = 1,            ///< Unknown error (default)
        SOCKET_COMMUNICATION_ERROR,   ///< Socket communication error
        INVALID_RESPONSE_FROM_SERVER, ///< Invalid response from server
        PROTOBUFF_SERIALIZE_ERROR,    ///< Protobuff serialize error
        PROTOBUFF_DESERIALIZE_ERROR,  ///< Protobuff deserialize error
        WRESPONSE_ERROR,              ///< Wazuh protocol response error
        EMESSAGE_ERROR,               ///< Engine requeset failed
        PATH_ERROR,                   ///< Path error (invalid path)
        INVALID_ARGUMENT,             ///< Invalid argument
    };

    /**
     * @brief Construct a new Api Client Exception object
     *
     * @param msg Error message
     * @param errorType Error type
     */
    ClientException(const std::string& msg, Type errorType = Type::UNKNOWN_ERROR)
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
        switch (m_errorType) {
        case Type::UNKNOWN_ERROR:
            return "Unknown error";
        case Type::SOCKET_COMMUNICATION_ERROR:
            return "Socket communication error";
        case Type::INVALID_RESPONSE_FROM_SERVER:
            return "Invalid response from server";
        case Type::PROTOBUFF_SERIALIZE_ERROR:
            return "Protobuff serialize error";
        case Type::PROTOBUFF_DESERIALIZE_ERROR:
            return "Protobuff deserialize error";
        case Type::WRESPONSE_ERROR:
            return "Wazuh protocol response error";
        case Type::EMESSAGE_ERROR:
            return "Engine requeset failed";
        default:
            return "Invalid error type";
        }
    }

private:
    std::string m_errorMsg; ///< Error message
    Type m_errorType;  ///< Error type
};

} // namespace cmd

#endif // _CMDS_APIEXCEPT_HPP
