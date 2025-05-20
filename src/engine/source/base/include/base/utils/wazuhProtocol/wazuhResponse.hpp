#ifndef _BASE_UTILS_WAZUH_RESPONSE_HPP
#define _BASE_UTILS_WAZUH_RESPONSE_HPP

#include <base/json.hpp>
#include <base/logging.hpp>

namespace base::utils::wazuhProtocol
{

enum class RESPONSE_ERROR_CODES
{
    OK = 0,
    UNKNOWN_ERROR,
    INVALID_JSON_REQUEST, // The request is not a valid json
    INVALID_MSG_SIZE,     // The size of the message is not valid
    INVALID_REQUEST,      // The request is not valid
    COMMAND_NOT_FOUND,    // The command is not found
    BUSY_SERVER,          // The server is busy
    INTERNAL_ERROR        // This never happens, its only for coverage, the code should never reach this point
};

/**
 * @brief A standard protocol for internal communication between Wazuh components
 *
 * https://github.com/wazuh/wazuh/issues/5934
 */
class WazuhResponse
{
private:
    // Mandatory fields for all responses
    int m_error;                          ///< Error code
    json::Json m_data;                    ///< Data
    std::optional<std::string> m_message; ///< Optional message

public:
    // TODO Delete explicit when json constructor does not throw exceptions
    /**
     * @brief  Construct a new Wazuh Response object
     *
     * @param data Data to be sent, it can be a json object or a string
     * @param error Error code (0 if no error)
     * @param message Optional message
     */
    explicit WazuhResponse(const json::Json& data, int error = 0, std::string_view message = "") noexcept
        : m_data(data)
        , m_error(error)
    {
        m_message = message.empty() ? std::nullopt : std::optional<std::string> {message};
    }

    /**
     * @brief  Construct a new Wazuh Response object
     *
     * @param data Data to be sent, it can be a json object or a array
     * @param error Error code (0 if no error).
     * @param message Optional message
     *
     * @warning This constructor is only for server API use, if you want to send a response
     * from a module use the other one with a error code of 0
     */
    explicit WazuhResponse(json::Json&& data, int error = 0, std::string_view message = "") noexcept
        : m_data(data)
        , m_error(error)
    {
        m_message = message.empty() ? std::nullopt : std::optional<std::string> {message};
    }

    /**
     * @brief Construct a new Wazuh Response object
     *
     * The error code will be set to 0 and the data will be an empty json object.
     * @param message Messsage to be sent as a response
     */
    explicit WazuhResponse(std::string_view message) noexcept
        : m_data(json::Json {R"({})"})
        , m_error(static_cast<int>(RESPONSE_ERROR_CODES::OK))
        , m_message(message) {};

    /**
     * @brief Construct a new Wazuh Response object
     *
     * The error code will be set to 0. By protocol the data needs to be a json object or a array
     * but is not checked.
     * @param data Data to be sent. It should be a json object or a array
     * @param message Messsage to be sent as a response
     */
    explicit WazuhResponse(json::Json& data, std::string_view message) noexcept
        : m_data(data)
        , m_error(static_cast<int>(RESPONSE_ERROR_CODES::OK))
        , m_message(message) {};

    /**
     * @brief Construct a new Wazuh Response object
     * Set the error code to 0 and the data to an empty json object
     */
    explicit WazuhResponse() noexcept
        : m_data(json::Json {R"({})"})
        , m_error(static_cast<int>(RESPONSE_ERROR_CODES::OK))
        , m_message() {};

    /**
     * @brief Return data object of the response
     *
     * @return data object
     */
    const json::Json& data() const { return m_data; }

    /**
     * @brief Return error code of the response
     *
     * @return error code
     */
    int error() const { return m_error; }

    /**
     * @brief Return message of the response if exists
     *
     * @return message of the response if exists
     */
    const std::optional<std::string>& message() const { return m_message; }

    /**
     * @brief Set data object of the response, overwriting the previous one
     *
     * @param data object
     */
    void data(const json::Json& data) { m_data = json::Json {data}; }

    /**
     * @brief Set error code of the response, overwriting the previous one
     *
     * @param error code
     */
    void error(int error) { m_error = error; }

    /**
     * @brief Set message of the response, overwriting the previous one if exists
     *
     * @param message of the response
     */
    void message(const std::string& message) { m_message = message; }

    /**
     * @brief Conver the response to a string according to the protocol
     *
     * @return response as a string
     */
    std::string toString() const
    {
        if (m_message.has_value())
        {
            json::Json jsonMesage;
            jsonMesage.setString(m_message.value(), "");
            return fmt::format("{{\"data\":{},\"error\":{},\"message\":{}}}", m_data.str(), m_error, jsonMesage.str());
        }
        return fmt::format("{{\"data\":{},\"error\":{}}}", m_data.str(), m_error);
    }

    /**
     * @brief Validate the response
     *
     * A response is valid if the data is a json object or a array
     * @return true
     * @return false
     */
    bool isValid() const { return !(!m_data.isObject() && !m_data.isArray()); }

    /**
     * @brief Create a WazuhResponse object from a string
     *
     * @param response Response as a string.
     * @return WazuhResponse object.
     * @throw std::runtime_error if the response is not valid response.
     * The protocol is:
     * {
     *  "data": <json object or array>,
     *  "error": <integer>,
     *  "message": <string> (optional)
     * }
     */
    static WazuhResponse fromStr(std::string_view response)
    {
        json::Json rawResponse;
        try
        {
            rawResponse = json::Json {response.data()};
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Invalid response: {}", e.what()));
        }
        const auto error = rawResponse.getInt("/error");
        if (!error)
        {
            throw std::runtime_error("Error field not found or is not an integer");
        }
        auto data = rawResponse.getJson("/data");
        if (!data)
        {
            throw std::runtime_error("Data field not found");
        }
        else if (!data->isObject() && !data->isArray())
        {
            throw std::runtime_error("Data field is not a json object or array");
        }
        if (rawResponse.exists("/message") && !rawResponse.isString("/message"))
        {
            throw std::runtime_error("Message field is not a string");
        }

        auto ret = WazuhResponse {std::move(data.value()), error.value()};
        if (rawResponse.exists("/message"))
        {
            ret.message(rawResponse.getString("/message").value());
        }
        return ret;
    }

    /************************************************************************
     *                     Predefined responses
     ***********************************************************************/

    /**
     * @brief Return a request with invalid JSON format message
     *
     */
    static WazuhResponse invalidJsonRequest()
    {
        return WazuhResponse(json::Json(R"({})"),
                             static_cast<int>(RESPONSE_ERROR_CODES::INVALID_JSON_REQUEST),
                             "Invalid request, malformed JSON");
    }

    /**
     * @brief Return a request with invalid Size message
     *
     */
    static WazuhResponse invalidSize()
    {
        return WazuhResponse(
            json::Json(R"({})"), static_cast<int>(RESPONSE_ERROR_CODES::INVALID_MSG_SIZE), "Invalid Size");
    }

    /**
     * @brief Return a request with unknown error message
     *
     */
    static WazuhResponse unknownError()
    {
        return WazuhResponse(
            json::Json(R"({})"), static_cast<int>(RESPONSE_ERROR_CODES::UNKNOWN_ERROR), "Unknown error");
    }

    /**
     * @brief Return a request with invalid JSON format message
     *
     */
    static WazuhResponse invalidRequest(const std::string& message)
    {
        return WazuhResponse(json::Json(R"({})"),
                             static_cast<int>(RESPONSE_ERROR_CODES::INVALID_REQUEST),
                             std::string {"Invalid request: "} + message);
    }

    /**
     * @brief Return a request with internal error message
     *
     * This error is used when the request is valid but the server cannot
     * process  the respons
     */
    static WazuhResponse internalError(const std::string& message)
    {
        return WazuhResponse(json::Json(R"({})"),
                             static_cast<int>(RESPONSE_ERROR_CODES::INTERNAL_ERROR),
                             std::string {"Internal error: "} + message);
    }

    /**
     * @brief Return a request with busy server message
     *
     */
    static WazuhResponse busyServer()
    {
        return WazuhResponse(
            json::Json(R"({})"), static_cast<int>(RESPONSE_ERROR_CODES::BUSY_SERVER), "Busy server, try again later");
    }
};

} // namespace base::utils::wazuhProtocol

#endif // _API_WAZUH_RESPONSE_HPP
