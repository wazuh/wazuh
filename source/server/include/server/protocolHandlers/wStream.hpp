#ifndef _SERVER_PROTOCOLHANDLERS_WAZUHSTREAM_HPP
#define _SERVER_PROTOCOLHANDLERS_WAZUHSTREAM_HPP

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include <server/protocolHandler.hpp>

namespace engineserver::ph
{
/**
 * @brief Process the request received from the client
 *
 * Process the request received from the client, it is used to process the request received from the client and
 * generate the response to send to the client. The response is sent using the callback function.
 * @param req Request received from the client
 * @param callbackFn A callback function that will be invoked with the generated response.
 */
using ProcessRequestFn = std::function<void(const std::string& req, std::function<void(const std::string& res)>)>;

class WStream : public ProtocolHandler
{

private:
    /**
     * @brief Protocol stages
     */
    enum class Stage
    {
        HEADER, ///< HEADER stage
        PAYLOAD ///< PAYLOAD stage
    };

    std::string m_header;                            ///< Header buffer, stores the payload size
    std::string m_payload;                           ///< Payload buffer, stores the payload data
    Stage m_stage {Stage::HEADER};                   ///< Current stage
    int m_received {0};                              ///< Number of bytes received
    int m_pending {0};                               ///< Number of bytes pending to be received
    constexpr static int m_headerSize {sizeof(int)}; ///< Header size in bytes
    int maxPayloadSize;                              // 10 MB by default
    ProcessRequestFn m_onMessageCallback;            ///< Handler called when a message is received

    static const std::shared_ptr<std::string> m_busyResponse;  ///< Response when the server is busy
    static const std::shared_ptr<std::string> m_errorResponse; ///< Response when an unexpected error occurs

public:
    /**
     * @brief Construct a new WStream object
     *
     * @param onMessageCallback Callback to be called when a message is received
     * @param maxPayloadSize Maximum payload size in bytes (default 10 MB)
     */
    WStream(std::function<void(const std::string&, std::function<void(const std::string&)>)> onMessageCallback,
            int maxPayloadSize = 1024 * 1024 * 10)
        : m_header {}
        , m_payload {}
        , m_stage {Stage::HEADER}
        , m_received {0}
        , m_pending {0}
        , maxPayloadSize {maxPayloadSize}
        , m_onMessageCallback {onMessageCallback}

    {
        m_header.reserve(m_headerSize);
    }

    ~WStream() = default;

    /**
     * @brief Set the busy response
     *
     * @param response Response to be sent when the server is busy
     */
    static void setBusyResponse(const std::string& response) { *m_busyResponse = response; }

    /*
     * @brief Set the error response
     *
     * @param response Response to be sent when an unexpected error occurs
     */
    static void setErrorResponse(const std::string& response) { *m_errorResponse = response; }

    /**
     * @brief Reset the protocol handler to its initial state
     */
    void reset()
    {
        m_header.clear();
        m_payload.clear();
        m_stage = Stage::HEADER;
        m_received = 0;
        m_pending = 0;
    };

    /**
     * @copydoc ProtocolHandler::onData
     */
    std::optional<std::vector<std::string>> onData(std::string_view data) override;

    /**
     * @copydoc ProtocolHandler::onMessage
     */
    void onMessage(const std::string& message, std::function<void(const std::string&)> callbackFn) override
    {
        return m_onMessageCallback(message, callbackFn);
    }

    /**
     * @copydoc ProtocolHandler::streamToSend
     */
    std::tuple<std::unique_ptr<char[]>, std::size_t> streamToSend(std::shared_ptr<std::string> message) override;

    /**
     * @copydoc ProtocolHandler::streamToSend
     */
    std::tuple<std::unique_ptr<char[]>, std::size_t> streamToSend(const std::string& message) override;

    /**
     * @copydoc ProtocolHandler::getBusyResponse
     */
    std::tuple<std::unique_ptr<char[]>, std::size_t> getBusyResponse() override;

    /**
     * @copydoc ProtocolHandler::getErrorResponse
     */
    std::string getErrorResponse() override;
};

class WStreamFactory : public ProtocolHandlerFactory
{

private:
    ProcessRequestFn m_onMessageCallback; ///< Handler called when a message is received
    int maxPayloadSize;                   // 10 MB by default

public:
    /**
     * @brief Construct a new WStreamFactory object
     *
     * @param m_onMessageCallback Callback to be called when a message is received
     * @param maxPayloadSize Maximum payload size in bytes (default 10 MB)
     */
    WStreamFactory(std::function<void(const std::string&, std::function<void(const std::string&)>)> onMessageCallback,
                   int maxPayloadSize = 1024 * 1024 * 10)
        : m_onMessageCallback {onMessageCallback}
        , maxPayloadSize {maxPayloadSize}
    {
        if (maxPayloadSize <= 0)
        {
            throw std::invalid_argument("maxPayloadSize must be greater than 0");
        }
    }

    /**
     * @copydoc ProtocolHandlerFactory::create
     */
    std::shared_ptr<ProtocolHandler> create() override
    {
        return std::make_shared<WStream>(m_onMessageCallback, maxPayloadSize);
    }

    /**
     * @brief Set the busy response
     */
    void setBusyResponse(const std::string& response) { WStream::setBusyResponse(response); }

    /**
     * @brief Set the error response
     */
    void setErrorResponse(const std::string& response) { WStream::setErrorResponse(response); }
};

} // namespace engineserver::ph

#endif
