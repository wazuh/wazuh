#include "curl_http_transport.hpp"

#include <curl/curl.h>

#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        constexpr int STREAM_POLL_INTERVAL_MS = 500;

        void globalInitOnce()
        {
            static std::once_flag once;
            std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
        }

        struct EasyDeleter
        {
            void operator()(CURL* handle) const
            {
                curl_easy_cleanup(handle);
            }
        };

        struct MultiDeleter
        {
            void operator()(CURLM* handle) const
            {
                curl_multi_cleanup(handle);
            }
        };

        struct SlistDeleter
        {
            void operator()(curl_slist* list) const
            {
                curl_slist_free_all(list);
            }
        };

        using EasyHandle = std::unique_ptr<CURL, EasyDeleter>;
        using MultiHandle = std::unique_ptr<CURLM, MultiDeleter>;
        using HeaderList = std::unique_ptr<curl_slist, SlistDeleter>;

        /// State shared with the C write callback during one transfer.
        struct WriteContext
        {
            std::string buffer;                                             // Unary: accumulated body.
            const std::function<bool(std::string_view)>* onChunk {nullptr}; // Stream: per-chunk sink.
            const StopController* stop {nullptr};                           // Stream: mid-chunk abort.
            bool sinkRefused {false};
        };

        size_t writeCallback(char* data, size_t size, size_t nmemb, void* userData)
        {
            auto* context = static_cast<WriteContext*>(userData);
            const size_t total = size * nmemb;

            if (context->onChunk != nullptr)
            {
                if ((context->stop != nullptr && context->stop->isStopRequested()) ||
                    !(*context->onChunk)(std::string_view {data, total}))
                {
                    context->sinkRefused = context->stop == nullptr || !context->stop->isStopRequested();
                    return 0; // Short count aborts the transfer.
                }
                return total;
            }

            context->buffer.append(data, total);
            return total;
        }

        /// TLS blobs, socket, headers, timeouts: one configuration path for unary and
        /// streaming so list and watch can never diverge.
        HeaderList applySpec(CURL* handle, const HttpRequestSpec& spec, WriteContext& context)
        {
            curl_easy_setopt(handle, CURLOPT_URL, spec.url.c_str());
            curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeCallback);
            curl_easy_setopt(handle, CURLOPT_WRITEDATA, &context);
            curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(spec.connectTimeout.count()));
            curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, static_cast<long>(spec.totalTimeout.count()));

            if (spec.unixSocket)
            {
                curl_easy_setopt(handle, CURLOPT_UNIX_SOCKET_PATH, spec.unixSocket->c_str());
            }

            if (spec.tls.skipVerify)
            {
                curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
            }
            if (spec.tls.caBlob)
            {
                curl_blob blob {};
                blob.data = const_cast<char*>(spec.tls.caBlob->data());
                blob.len = spec.tls.caBlob->size();
                blob.flags = CURL_BLOB_COPY;
                curl_easy_setopt(handle, CURLOPT_CAINFO_BLOB, &blob);
            }
            if (spec.tls.clientCertBlob && spec.tls.clientKeyBlob)
            {
                curl_blob certBlob {};
                certBlob.data = const_cast<char*>(spec.tls.clientCertBlob->data());
                certBlob.len = spec.tls.clientCertBlob->size();
                certBlob.flags = CURL_BLOB_COPY;
                curl_easy_setopt(handle, CURLOPT_SSLCERT_BLOB, &certBlob);

                curl_blob keyBlob {};
                keyBlob.data = const_cast<char*>(spec.tls.clientKeyBlob->data());
                keyBlob.len = spec.tls.clientKeyBlob->size();
                keyBlob.flags = CURL_BLOB_COPY;
                curl_easy_setopt(handle, CURLOPT_SSLKEY_BLOB, &keyBlob);
            }

            HeaderList headers;
            for (const auto& header : spec.headers)
            {
                headers.reset(curl_slist_append(headers.release(), header.c_str()));
            }
            if (headers)
            {
                curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers.get());
            }

            return headers;
        }

        long responseStatus(CURL* handle)
        {
            long status = 0;
            curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
            return status;
        }

    } // namespace

    CurlHttpTransport::CurlHttpTransport(Logger logger)
        : m_logger(std::move(logger))
    {
        globalInitOnce();
    }

    HttpResponse CurlHttpTransport::request(const HttpRequestSpec& spec)
    {
        EasyHandle handle {curl_easy_init()};
        if (!handle)
        {
            throw HttpTransportError(CURLE_FAILED_INIT, "curl_easy_init failed");
        }

        WriteContext context;
        const auto headers = applySpec(handle.get(), spec, context);

        const auto code = curl_easy_perform(handle.get());
        if (code != CURLE_OK)
        {
            throw HttpTransportError(code, curl_easy_strerror(code));
        }

        HttpResponse response;
        response.status = responseStatus(handle.get());
        response.body = std::move(context.buffer);
        return response;
    }

    StreamResult CurlHttpTransport::stream(const HttpRequestSpec& spec,
                                           const std::function<bool(std::string_view)>& onChunk,
                                           const StopController& stop)
    {
        StreamResult result;

        EasyHandle easy {curl_easy_init()};
        MultiHandle multi {curl_multi_init()};
        if (!easy || !multi)
        {
            result.kind = StreamResult::Kind::transportError;
            result.curlCode = CURLE_FAILED_INIT;
            result.message = "curl init failed";
            return result;
        }

        WriteContext context;
        context.onChunk = &onChunk;
        context.stop = &stop;
        const auto headers = applySpec(easy.get(), spec, context);

        curl_multi_add_handle(multi.get(), easy.get());

        int running = 1;
        CURLcode transferCode = CURLE_OK;
        bool finished = false;

        while (running > 0 && !stop.isStopRequested())
        {
            curl_multi_perform(multi.get(), &running);
            if (running > 0)
            {
                curl_multi_poll(multi.get(), nullptr, 0, STREAM_POLL_INTERVAL_MS, nullptr);
            }
        }

        int messagesLeft = 0;
        while (CURLMsg* message = curl_multi_info_read(multi.get(), &messagesLeft))
        {
            if (message->msg == CURLMSG_DONE)
            {
                transferCode = message->data.result;
                finished = true;
            }
        }

        result.httpStatus = responseStatus(easy.get());
        curl_multi_remove_handle(multi.get(), easy.get());

        if (stop.isStopRequested() && !context.sinkRefused)
        {
            result.kind = StreamResult::Kind::cancelled;
            result.message = "stream cancelled by stop request";
        }
        else if (finished && transferCode == CURLE_OK)
        {
            result.kind = StreamResult::Kind::serverClosed;
            result.message = "server closed the stream";
        }
        else
        {
            result.kind = StreamResult::Kind::transportError;
            result.curlCode = transferCode;
            result.message = context.sinkRefused ? "chunk sink refused data" : curl_easy_strerror(transferCode);
        }

        return result;
    }

} // namespace wazuh::container_instances
