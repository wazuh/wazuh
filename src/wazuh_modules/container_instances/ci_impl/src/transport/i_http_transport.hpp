#pragma once

#include "../core/stop_controller.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_instances
{

    /// TLS material carried per request as in-memory blobs (kubeconfig *-data
    /// fields are never written to disk).
    struct TlsOptions
    {
        std::optional<std::string> caBlob;         ///< PEM CA bundle.
        std::optional<std::string> clientCertBlob; ///< PEM client certificate.
        std::optional<std::string> clientKeyBlob;  ///< PEM client private key.
        bool skipVerify {false};                   ///< Disables peer AND host verification. Dev-only.
    };

    struct HttpRequestSpec
    {
        std::string url;
        std::optional<std::string> unixSocket; ///< When set, connect over this Unix domain socket.
        std::vector<std::string> headers;      ///< Full header lines, e.g. "Authorization: Bearer x".
        TlsOptions tls;
        std::chrono::milliseconds connectTimeout {10000};
        std::chrono::milliseconds totalTimeout {30000}; ///< 0 = unlimited (streams).

        /// Streams only: invoked from the transfer loop roughly every poll
        /// interval, whether or not any data arrived. Empty = not wanted.
        ///
        /// An unterminated stream (totalTimeout 0) delivers no callback at all
        /// while the server is silent, so a consumer that must act on the
        /// PASSAGE OF TIME — rather than on data — has nowhere to do it. The
        /// transfer loop already wakes on a fixed interval to poll the stop
        /// token; this exposes that existing tick instead of each caller
        /// growing a thread and a mutex to recreate it.
        ///
        /// Called on the thread that invoked stream(), between chunks, so it
        /// shares the caller's single-threaded context and must not block for
        /// long: the transfer makes no progress while it runs.
        std::function<void()> onIdle;
    };

    struct HttpResponse
    {
        long status {0};
        std::string body;
    };

    /// Terminal state of a streaming request. Streams are intentionally
    /// unterminated, so "the server closed" is a distinct, often-expected outcome
    /// rather than a generic error.
    struct StreamResult
    {
        enum class Kind : std::uint8_t
        {
            cancelled,     ///< Stop token fired; the stream was aborted locally.
            serverClosed,  ///< Server ended the response (httpStatus carries the code).
            transportError ///< curl-level failure (curlCode carries the code).
        };

        Kind kind {Kind::transportError};
        long httpStatus {0};
        int curlCode {0};
        std::string message;
    };

    /// Thrown by unary request() on transport-level failure (connect, TLS, timeout).
    /// HTTP error statuses are NOT exceptions: they come back in HttpResponse.
    class HttpTransportError : public std::runtime_error
    {
    public:
        HttpTransportError(int curlCode, const std::string& message)
            : std::runtime_error(message)
            , m_curlCode(curlCode)
        {
        }

        [[nodiscard]] int curlCode() const noexcept
        {
            return m_curlCode;
        }

    private:
        int m_curlCode;
    };

    /// Module-local HTTP seam: one transport, one TLS path, for both unary calls
    /// and long-lived chunked streams (Kubernetes watch, Docker /events). The
    /// shared http-request client is deliberately not used here — it cannot
    /// deliver a body incrementally (see design doc §4).
    class IHttpTransport
    {
    public:
        virtual ~IHttpTransport() = default;

        [[nodiscard]] virtual HttpResponse request(const HttpRequestSpec& spec) = 0;

        /// Feeds each received chunk to onChunk as it arrives. Returning false from
        /// onChunk aborts the transfer (reported as transportError). The stop
        /// controller aborts it as cancelled, mid-chunk if necessary.
        [[nodiscard]] virtual StreamResult stream(const HttpRequestSpec& spec,
                                                  const std::function<bool(std::string_view)>& onChunk,
                                                  const StopController& stop) = 0;
    };

} // namespace wazuh::container_instances
