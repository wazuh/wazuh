// SPDX-License-Identifier: AGPL-3.0-or-later
#include <httpsrv/server.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <limits>
#include <stdexcept>
#include <utility>

#include <base/logging.hpp>
#include <fastmetrics/registry.hpp>
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include <httpsrv/boundedExecutor.hpp>

namespace httpsrv
{
namespace uds = wazuh::uds_http;

namespace
{
constexpr auto SERVER_HEADER = "wazuh-manager-analysisd";
constexpr auto BUSY_BODY = R"({"error":"Server busy","code":503})";
constexpr auto SHUTTING_DOWN_BODY = R"({"error":"Server shutting down","code":503})";
constexpr auto INTERNAL_ERROR_BODY = "Internal server error";

/// One log line per window for a repeating condition; the line says how many occurrences it covers.
class Throttle
{
public:
    static constexpr int WINDOW_SECONDS {90};

    /// @return 0 when the caller must stay quiet, otherwise the occurrences this line stands for.
    std::uint64_t record()
    {
        m_pending.fetch_add(1, std::memory_order_relaxed);
        const auto now =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch())
                .count();
        auto last = m_lastEmit.load(std::memory_order_relaxed);
        if (now - last < WINDOW_SECONDS || !m_lastEmit.compare_exchange_strong(last, now))
        {
            return 0;
        }
        return m_pending.exchange(0, std::memory_order_relaxed);
    }

private:
    std::atomic<std::int64_t> m_lastEmit {std::numeric_limits<std::int32_t>::min()};
    std::atomic<std::uint64_t> m_pending {0};
};

uds::Method toTransport(Method method)
{
    switch (method)
    {
        case Method::GET: return uds::Method::Get;
        case Method::POST: return uds::Method::Post;
        case Method::PUT: return uds::Method::Put;
        case Method::DELETE: return uds::Method::Delete;
        default: throw std::invalid_argument {"Unsupported HTTP method for a route"};
    }
}

Method fromTransport(uds::Method method)
{
    switch (method)
    {
        case uds::Method::Get: return Method::GET;
        case uds::Method::Post: return Method::POST;
        case uds::Method::Put: return Method::PUT;
        case uds::Method::Delete: return Method::DELETE;
        default: return Method::ERROR_METHOD;
    }
}

uds::RouteClass toTransport(RouteClass cls)
{
    switch (cls)
    {
        case RouteClass::Data: return uds::RouteClass::Data;
        case RouteClass::Liveness: return uds::RouteClass::Liveness;
        case RouteClass::Control:
        default: return uds::RouteClass::Control;
    }
}

const char* methodName(Method method)
{
    switch (method)
    {
        case Method::GET: return "GET";
        case Method::POST: return "POST";
        case Method::PUT: return "PUT";
        case Method::DELETE: return "DELETE";
        default: return "?";
    }
}

/// The handler's view of a transport request. The body is not copied: `owner` keeps the
/// transport's request, and with it the bytes and their budget reservation, alive.
Request toRequest(const std::shared_ptr<const uds::HttpRequest>& in)
{
    Request out;
    out.method = fromTransport(in->method);
    out.target = in->target;
    out.body = std::string_view {in->body};
    out.headers = in->headers;
    out.repeatedHeaders = in->duplicateHeaders;
    out.owner = in;
    return out;
}

uds::HttpResponse toTransport(Response in)
{
    uds::HttpResponse out;
    out.status = in.status;
    out.body = std::move(in.body);
    if (!in.contentType.empty())
    {
        out.headers.emplace_back("Content-Type", std::move(in.contentType));
    }
    return out;
}
} // namespace

struct Server::Impl
{
    explicit Impl(ServerOptions opts)
        : options {std::move(opts)}
        , executor {std::make_unique<BoundedExecutor>(options.name, options.executorThreads, options.executorQueue)}
        , transport {uds::makeUdsHttpServer()}
    {
    }

    // Declaration order is destruction order reversed: the transport goes first (no new request
    // can reach the executor), then the executor (its destructor joins every worker), and the
    // counters the jobs touch outlive both.
    ServerOptions options;
    std::atomic<std::size_t> shedExecutorFull {0};
    std::atomic<std::size_t> shedShutdown {0};
    std::atomic<std::size_t> handlerErrors {0};
    Throttle busyThrottle;
    Throttle handlerErrorThrottle;
    std::atomic<bool> running {false};
    std::unique_ptr<BoundedExecutor> executor;
    std::unique_ptr<uds::IUdsHttpServer> transport;

    void answerShuttingDown(const std::shared_ptr<uds::IHttpResponder>& responder)
    {
        shedShutdown.fetch_add(1, std::memory_order_relaxed);
        responder->send(uds::HttpResponse::json(503, SHUTTING_DOWN_BODY));
    }

    void runHandler(const RouteHandler& handler,
                    const std::shared_ptr<const uds::HttpRequest>& transportRequest,
                    const std::shared_ptr<uds::IHttpResponder>& responder)
    {
        const auto request = toRequest(transportRequest);
        Response response;
        try
        {
            handler(request, response);
        }
        catch (const std::exception& e)
        {
            handlerErrors.fetch_add(1, std::memory_order_relaxed);
            if (const auto total = handlerErrorThrottle.record(); total != 0)
            {
                LOG_ERROR("[{}] {} request handler(s) failed in the last {} s (last: {} {}: {}).",
                          options.name,
                          total,
                          Throttle::WINDOW_SECONDS,
                          methodName(request.method),
                          request.target,
                          e.what());
            }
            response = Response {};
            response.status = 500;
            response.setContent(INTERNAL_ERROR_BODY, "text/plain");
        }
        catch (...)
        {
            handlerErrors.fetch_add(1, std::memory_order_relaxed);
            response = Response {};
            response.status = 500;
            response.setContent(INTERNAL_ERROR_BODY, "text/plain");
        }

        if (options.detailedLogging)
        {
            LOG_TRACE("[{}] {} {} -> {}", options.name, methodName(request.method), request.target, response.status);
        }
        responder->send(toTransport(std::move(response)));
    }

    uds::RouteHandler adapt(RouteHandler handler, bool runInline)
    {
        // Shared, not referenced: the transport (and this route lambda with it) is destroyed before
        // the executor joins its workers, so a job must own its handler.
        auto shared = std::make_shared<const RouteHandler>(std::move(handler));
        if (runInline)
        {
            return [this, shared](std::shared_ptr<const uds::HttpRequest> request,
                                  std::shared_ptr<uds::IHttpResponder> responder)
            {
                runHandler(*shared, request, responder);
            };
        }
        return [this, shared](std::shared_ptr<const uds::HttpRequest> request,
                              std::shared_ptr<uds::IHttpResponder> responder)
        {
            BoundedExecutor::Job job;
            job.run = [this, shared, request, responder]
            {
                runHandler(*shared, request, responder);
            };
            job.reject = [this, responder]
            {
                answerShuttingDown(responder);
            };

            switch (executor->trySubmit(std::move(job)))
            {
                case BoundedExecutor::Submit::Accepted: return;
                case BoundedExecutor::Submit::Closed: answerShuttingDown(responder); return;
                case BoundedExecutor::Submit::Full:
                    shedExecutorFull.fetch_add(1, std::memory_order_relaxed);
                    if (const auto total = busyThrottle.record(); total != 0)
                    {
                        LOG_WARNING("[{}] Rejected {} request(s) with 503 in the last {} s: every request worker is "
                                    "busy and the queue is full ({} queued).",
                                    options.name,
                                    total,
                                    Throttle::WINDOW_SECONDS,
                                    executor->depth());
                    }
                    responder->send(uds::HttpResponse::json(503, BUSY_BODY));
                    return;
            }
        };
    }
};

Server::Server(ServerOptions options)
    : m_impl {std::make_unique<Impl>(std::move(options))}
{
}

Server::~Server()
{
    if (m_impl->running.load())
    {
        stop();
    }
}

void Server::addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options)
{
    uds::RouteOptions routeOptions;
    routeOptions.cls = toTransport(options.cls);
    routeOptions.maxBodyBytes =
        options.maxBodyBytes == UNLIMITED_BODY ? uds::UdsHttpServerConfig::UNLIMITED_BODY_SIZE : options.maxBodyBytes;
    routeOptions.payloadTooLargeBody = std::move(options.payloadTooLargeBody);
    routeOptions.payloadTooLargeContentType = std::move(options.payloadTooLargeContentType);
    m_impl->transport->addRoute(
        toTransport(method), path, m_impl->adapt(std::move(handler), options.runInline), routeOptions);
}

void Server::start(const std::filesystem::path& socketPath)
{
    const auto& options = m_impl->options;
    uds::UdsHttpServerConfig config;
    config.socketPath = socketPath.string();
    config.maxConnections = options.maxConnections;
    config.ioThreads = options.ioThreads;
    if (!options.byteBudget)
    {
        config.maxInFlightBytes = 0;
    }
    else if (options.maxInFlightBytes != 0)
    {
        config.maxInFlightBytes = options.maxInFlightBytes;
    }
    if (options.maxBodySize != 0)
    {
        config.maxBodySize = options.maxBodySize;
    }
    config.expectContinue = options.expectContinue;
    config.logTag = options.logTag;
    config.serverName = options.name;
    config.serverHeader = SERVER_HEADER;
    config.budgetOptionHint = options.budgetOptionHint;
    config.connectionCapOptionHint = options.connectionCapOptionHint;

    m_impl->transport->start(config);
    m_impl->running.store(true);
}

bool Server::isRunning() const
{
    return m_impl->running.load();
}

void Server::stopAccepting()
{
    m_impl->transport->stopAccepting();
}

void Server::closeAdmission()
{
    m_impl->executor->closeAdmission();
}

ShutdownReport Server::drainUntil(std::chrono::steady_clock::time_point deadline)
{
    const auto drained = m_impl->executor->drainUntil(deadline);
    return ShutdownReport {drained.completed, drained.rejected, drained.abandoned};
}

void Server::waitForHandlers()
{
    m_impl->executor->join();
}

void Server::stop()
{
    m_impl->transport->stop();
    m_impl->running.store(false);
}

ShutdownReport Server::shutdown(std::chrono::milliseconds deadline)
{
    // The grace starts now: stopAccepting() can block while the transport answers what was not dispatched,
    // and the executor keeps working meanwhile.
    const auto until = std::chrono::steady_clock::now() + deadline;
    stopAccepting();
    closeAdmission();
    const auto report = drainUntil(until);
    stop();
    LOG_INFO("[{}] Stopped: {} request(s) finished during the drain, {} answered 503, {} still running at the "
             "deadline.",
             m_impl->options.name,
             report.completed,
             report.rejected,
             report.abandoned);
    waitForHandlers();
    return report;
}

ServerStats Server::stats() const
{
    const auto transport = m_impl->transport->diagnostics();
    ServerStats stats;
    stats.inFlightBytes = transport.budgetInFlightBytes;
    stats.inFlightRequests = transport.budgetInFlightCount;
    stats.sessions = transport.liveSessions;
    stats.shedBudget = transport.rejectedBudgetExhausted;
    stats.shedSessions = transport.rejectedSessionCap + transport.rejectedConnectionCap;
    stats.queueDepth = m_impl->executor->depth();
    stats.running = m_impl->executor->running();
    stats.shedExecutorFull = m_impl->shedExecutorFull.load(std::memory_order_relaxed);
    stats.shedShutdown = m_impl->shedShutdown.load(std::memory_order_relaxed) + transport.rejectedShutdown;
    stats.handlerErrors = m_impl->handlerErrors.load(std::memory_order_relaxed);
    stats.rejectedTooLarge = transport.rejectedTooLarge;
    return stats;
}

void registerMetrics(const std::weak_ptr<Server>& server, const std::string& instance)
{
    namespace names = fastmetrics::names;
    const auto publish = [&](const char* suffix, std::size_t ServerStats::* field)
    {
        fastmetrics::registerPullMetric(names::server_metric(instance, suffix),
                                        std::function<uint64_t()>(
                                            [server, field]() -> uint64_t
                                            {
                                                const auto alive = server.lock();
                                                return alive ? static_cast<uint64_t>(alive->stats().*field) : 0;
                                            }));
    };

    publish(names::SERVER_INFLIGHT_BYTES, &ServerStats::inFlightBytes);
    publish(names::SERVER_INFLIGHT_REQUESTS, &ServerStats::inFlightRequests);
    publish(names::SERVER_SESSIONS, &ServerStats::sessions);
    publish(names::SERVER_QUEUE_DEPTH, &ServerStats::queueDepth);
    publish(names::SERVER_RUNNING, &ServerStats::running);
    publish(names::SERVER_SHED_BUDGET, &ServerStats::shedBudget);
    publish(names::SERVER_SHED_CONNECTIONS, &ServerStats::shedSessions);
    publish(names::SERVER_SHED_EXECUTOR_FULL, &ServerStats::shedExecutorFull);
    publish(names::SERVER_SHED_SHUTDOWN, &ServerStats::shedShutdown);
    publish(names::SERVER_HANDLER_ERRORS, &ServerStats::handlerErrors);
    publish(names::SERVER_REJECTED_TOO_LARGE, &ServerStats::rejectedTooLarge);
}

void shutdownAll(const std::vector<Server*>& servers, std::chrono::milliseconds deadline)
{
    // One grace for every server, counted from here, as in Server::shutdown().
    const auto until = std::chrono::steady_clock::now() + deadline;

    // 1. No server lets a new request reach a handler; I/O stays up so replies still go out.
    for (auto* server : servers)
    {
        if (server != nullptr)
        {
            server->stopAccepting();
        }
    }
    // 2. No executor admits new work; what is queued keeps running.
    for (auto* server : servers)
    {
        if (server != nullptr)
        {
            server->closeAdmission();
        }
    }
    // 3. Drain every executor in parallel up to one deadline.
    std::vector<std::future<ShutdownReport>> drains;
    for (auto* server : servers)
    {
        if (server != nullptr)
        {
            drains.push_back(std::async(std::launch::async, [server, until] { return server->drainUntil(until); }));
        }
    }
    ShutdownReport total;
    for (auto& drain : drains)
    {
        const auto report = drain.get();
        total.completed += report.completed;
        total.rejected += report.rejected;
        total.abandoned += report.abandoned;
    }
    // 4. Only now close the transports, before the caller destroys what the handlers use.
    for (auto* server : servers)
    {
        if (server != nullptr)
        {
            server->stop();
        }
    }
    LOG_INFO("HTTP servers stopped: {} request(s) finished during the drain, {} answered 503, {} still running at "
             "the deadline.",
             total.completed,
             total.rejected,
             total.abandoned);
    // 5. A handler that outlived the deadline is waited for: returning while one runs would let the caller tear down
    //    what it uses.
    for (auto* server : servers)
    {
        if (server != nullptr)
        {
            server->waitForHandlers();
        }
    }
}

} // namespace httpsrv
