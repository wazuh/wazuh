#pragma once

#include "../core/logger.hpp"
#include "i_http_transport.hpp"

namespace wazuh::container_instances
{

    /// Thin libcurl adapter — the single point where HTTP happens in this module.
    /// One easy handle per call (calls are infrequent); streams run on their own
    /// curl_multi so cancellation never couples to other transfers.
    class CurlHttpTransport final : public IHttpTransport
    {
    public:
        explicit CurlHttpTransport(Logger logger);

        [[nodiscard]] HttpResponse request(const HttpRequestSpec& spec) override;

        [[nodiscard]] StreamResult stream(const HttpRequestSpec& spec,
                                          const std::function<bool(std::string_view)>& onChunk,
                                          const StopController& stop) override;

    private:
        Logger m_logger;
    };

} // namespace wazuh::container_instances
