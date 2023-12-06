#include <server/protocolHandlers/wStream.hpp>

#include <cstring>
#include <stdexcept>

#include <fmt/format.h>

namespace engineserver::ph
{

const std::shared_ptr<std::string> WStream::m_busyResponse = std::make_shared<std::string>("BUSY");
const std::shared_ptr<std::string> WStream::m_errorResponse = std::make_shared<std::string>("ERROR");

std::optional<std::vector<std::string>> WStream::onData(std::string_view data)
{
    std::vector<std::string> messages;

    for (auto c : data)
    {
        if (m_stage == Stage::HEADER)
        {
            m_header.push_back(c);
            if (m_header.size() == m_headerSize)
            {
                std::memcpy(&m_pending, m_header.data(), m_headerSize);
                if (m_pending > maxPayloadSize)
                {
                    auto msg = fmt::format(
                        "Payload size [{} bytes] exceeded the maximum allowed [{} bytes]", m_pending, maxPayloadSize);
                    reset();
                    throw std::runtime_error(msg);
                }
                m_stage = Stage::PAYLOAD;
            }
        }
        else
        {
            m_payload.push_back(c);
            if (m_payload.size() == m_pending)
            {
                messages.push_back(m_payload);
                m_payload.clear();
                m_header.clear();
                m_stage = Stage::HEADER;
            }
        }
    }
    return messages.empty() ? std::nullopt : std::optional<std::vector<std::string>>(std::move(messages));
}

std::tuple<std::unique_ptr<char[]>, std::size_t> WStream::streamToSend(std::shared_ptr<std::string> message)
{
    auto size = message->size();
    auto buffer = std::make_unique<char[]>(size + 4);
    std::memcpy(buffer.get(), &size, 4);
    std::memcpy(buffer.get() + 4, message->data(), size);
    return {std::move(buffer), size + 4};
}

std::tuple<std::unique_ptr<char[]>, std::size_t> WStream::streamToSend(const std::string& message)
{
    auto size = message.size();
    auto buffer = std::make_unique<char[]>(size + 4);
    std::memcpy(buffer.get(), &size, 4);
    std::memcpy(buffer.get() + 4, message.data(), size);
    return {std::move(buffer), size + 4};
}

std::tuple<std::unique_ptr<char[]>, std::size_t> WStream::getBusyResponse()
{
    return streamToSend(m_busyResponse);
}

std::string WStream::getErrorResponse()
{
    return *m_errorResponse;
}

} // namespace engineserver::ph
