// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _HTTPSRV_TYPES_HPP
#define _HTTPSRV_TYPES_HPP

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

// <arpa/nameser_compat.h> (reached through <resolv.h>) defines `DELETE` as `ns_uop_delete`. Undefine it so
// Method::DELETE keeps its name whatever was included before this header.
#ifdef DELETE
#undef DELETE
#endif

namespace httpsrv
{

/**
 * @brief An enum class representing the HTTP methods supported by the server.
 *
 */
enum class Method
{
    GET,
    POST,
    PUT,
    DELETE,
    ERROR_METHOD
};

/**
 * @brief Service class of a route, by how the server may shed it under load.
 *
 * - Data: bulk payloads charged to the in-flight byte budget (event batches).
 * - Control: small management requests with their own session headroom.
 * - Liveness: probes that must answer even while Data is saturated.
 */
enum class RouteClass
{
    Data,
    Control,
    Liveness
};

/**
 * @brief Per-route options.
 */
/// RouteOptions::maxBodyBytes value that lifts the class cap: the route takes a body of any size.
constexpr std::size_t UNLIMITED_BODY {static_cast<std::size_t>(-1)};

struct RouteOptions
{
    RouteClass cls {RouteClass::Control};
    /// Declared-length cap answered with 413 before the body is read; 0 means the class default,
    /// UNLIMITED_BODY means none.
    std::size_t maxBodyBytes {0};
    /// Run the handler on the transport's I/O thread instead of the executor, so the route answers even when
    /// every worker is busy. Only for handlers that never block (they read state already in memory).
    bool runInline {false};
    /// Body of the 413 this route answers when maxBodyBytes (or the class cap) refuses the declared length;
    /// empty keeps the transport's JSON body.
    std::string payloadTooLargeBody {};
    /// Content-Type of payloadTooLargeBody; ignored while that body is empty.
    std::string payloadTooLargeContentType {"text/plain"};
};

/**
 * @brief Transport-neutral view of an HTTP request, as a handler sees it.
 *
 * The body is a view: the bytes belong to the transport's request, which `owner` keeps alive (and,
 * with it, the transport's byte reservation) for as long as the Request exists. Handlers run
 * synchronously inside the server's executor, so a Request never outlives its owner by accident;
 * a handler that needs the body afterwards copies it.
 */
struct Request
{
    Method method {Method::POST};
    std::string target;    ///< Raw target, query string included.
    std::string_view body; ///< Request body; valid while `owner` lives.
    /// Header names lower-cased; a repeated name keeps its last value.
    std::unordered_map<std::string, std::string> headers;
    /// Lower-cased names that appeared more than once.
    std::unordered_set<std::string> repeatedHeaders;
    /// Keeps the storage behind `body` alive.
    std::shared_ptr<const void> owner;

    /**
     * @brief The value of a header (name in any case), or nullopt when absent.
     */
    std::optional<std::string_view> header(std::string_view name) const
    {
        const auto it = headers.find(lowerCase(name));
        if (it == headers.end())
        {
            return std::nullopt;
        }
        return std::string_view {it->second};
    }

    /**
     * @brief How many times a header appeared: 0, 1, or 2 meaning "more than once".
     */
    std::size_t headerCount(std::string_view name) const
    {
        const auto key = lowerCase(name);
        if (headers.find(key) == headers.end())
        {
            return 0;
        }
        return repeatedHeaders.count(key) != 0 ? 2 : 1;
    }

    /**
     * @brief Builds a request that owns its body, for callers outside a transport (tests, tools).
     *
     * @param method HTTP method.
     * @param target Request target.
     * @param body Body, moved into the request's own storage.
     * @param headers Headers; names are lower-cased here.
     */
    static Request fromOwned(Method method,
                             std::string target,
                             std::string body,
                             const std::unordered_map<std::string, std::string>& headers = {})
    {
        Request request;
        request.method = method;
        request.target = std::move(target);
        auto storage = std::make_shared<const std::string>(std::move(body));
        request.body = *storage;
        request.owner = std::move(storage);
        for (const auto& [name, value] : headers)
        {
            request.headers.insert_or_assign(lowerCase(name), value);
        }
        return request;
    }

    /**
     * @brief ASCII lower-casing, the form header names are stored in.
     */
    static std::string lowerCase(std::string_view text)
    {
        std::string lowered {text};
        for (auto& c : lowered)
        {
            if (c >= 'A' && c <= 'Z')
            {
                c = static_cast<char>(c - 'A' + 'a');
            }
        }
        return lowered;
    }
};

/**
 * @brief Transport-neutral HTTP response a handler fills in.
 */
struct Response
{
    int status {200};
    std::string body;
    std::string contentType {"text/plain"};

    void setContent(std::string content, std::string type)
    {
        body = std::move(content);
        contentType = std::move(type);
    }
};

/**
 * @brief A route handler: fills the response for one request. Runs on the server's executor.
 */
using RouteHandler = std::function<void(const Request&, Response&)>;

} // namespace httpsrv

#endif // _HTTPSRV_TYPES_HPP
