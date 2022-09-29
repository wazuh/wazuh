#ifndef _API_WAZUH_RESPONSE_HPP
#define _API_WAZUH_RESPONSE_HPP

#include <json/json.hpp>
#include <logging/logging.hpp>

namespace api
{

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
    explicit WazuhResponse(const json::Json& data,
                           int error,
                           std::string_view message = "") noexcept
        : m_data(data)
        , m_error(error)
    {
        m_message = message.empty() ? std::nullopt : std::make_optional(message);
    }

    // Rule of five
    WazuhResponse(const WazuhResponse& other)
        : m_data(other.m_data)
        , m_error(other.m_error)
        , m_message(other.m_message)
    {
    }
    WazuhResponse(WazuhResponse&& other)
        : m_data(std::move(other.m_data))
        , m_error(std::move(other.m_error))
        , m_message(std::move(other.m_message))
    {
    }
    WazuhResponse& operator=(const WazuhResponse& other)
    {
        m_data = other.m_data;
        m_error = other.m_error;
        m_message = other.m_message;
        return *this;
    }
    WazuhResponse& operator=(WazuhResponse&& other)
    {
        m_data = std::move(other.m_data);
        m_error = std::move(other.m_error);
        m_message = std::move(other.m_message);
        return *this;
    }
    ~WazuhResponse() = default;

    // Getters
    const json::Json& data() const { return m_data; }
    int error() const { return m_error; }
    const std::optional<std::string>& message() const { return m_message; }

    // Setters
    void data(const json::Json& data) { m_data = data; }
    void error(int error) { m_error = error; }
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
            return fmt::format("{{\"data\":{},\"error\":{},\"message\":\"{}\"}}",
                               m_data.str(),
                               m_error,
                               m_message.value());
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
};

} // namespace api

#endif // _API_WAZUH_RESPONSE_HPP
