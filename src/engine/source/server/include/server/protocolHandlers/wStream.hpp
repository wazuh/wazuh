#ifndef _SERVER_PROTOCOLHANDLERS_WAZUHSTREAM_HPP
#define _SERVER_PROTOCOLHANDLERS_WAZUHSTREAM_HPP

#include <functional>
#include <string>

#include <server/protocolHandler.hpp>

namespace engineserver::ph
{
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
    std::function<std::string(const std::string&)>
        m_onMessageCallback; ///< Callback to be called when a message is received

    /**
     * @brief Response to be sent when the server is busy
     *
     */
    static const std::shared_ptr<std::string> m_busyResponse;
    static const std::shared_ptr<std::string> m_errorResponse;

public:
    /**
     * @brief Construct a new WStream object
     *
     * @param m_onMessageCallback Callback to be called when a message is received
     * @param maxPayloadSize Maximum payload size in bytes (default 10 MB)
     */
    WStream(std::function<std::string(const std::string&)> m_onMessageCallback,
            int maxPayloadSize = 1024 * 1024 * 10)
        : m_header {}
        , m_payload {}
        , m_stage {Stage::HEADER}
        , m_received {0}
        , m_pending {0}
        , maxPayloadSize {maxPayloadSize}
        , m_onMessageCallback {m_onMessageCallback}

    {
        m_header.reserve(m_headerSize);
    }

    ~WStream() = default;

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
    std::string onMessage(const std::string& message) override { return m_onMessageCallback(message); }

    /**
     * @copydoc ProtocolHandler::streamToSend
     */
    std::tuple<std::unique_ptr<char[]>, std::size_t> streamToSend(std::shared_ptr<std::string> message) override;

    /**
     * @copydoc ProtocolHandler::getBusyResponse
     */
    std::tuple<std::unique_ptr<char[]>, std::size_t> getBusyResponse() override;

    /**
     * @copydoc ProtocolHandler::getErrorResponse
     */
    std::string getErrorResponse() override;
};
} // namespace engineserver::ph

#endif
