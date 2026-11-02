// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _HTTPSRV_UDS_SERVER_HPP
#define _HTTPSRV_UDS_SERVER_HPP

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <httpsrv/irouteregistrar.hpp>
#include <httpsrv/types.hpp>

namespace httpsrv
{

/// Time an engine server gives admitted requests to finish once the daemon is stopping.
constexpr std::chrono::seconds DEFAULT_SHUTDOWN_DEADLINE {10};

/**
 * @brief Settings of one UdsServer.
 *
 * I/O threads, timeouts and the socket mode (0660) are the transport's defaults on purpose; only
 * what an engine server needs to size is exposed.
 */
struct UdsServerOptions
{
    std::string name;   ///< Shown in log lines ("<name> server ...").
    std::string logTag; ///< Tag of the transport's own log lines.
    std::size_t maxConnections {1024};
    std::size_t maxInFlightBytes {0}; ///< 0 keeps the transport's default byte budget.
    /// false: no in-flight byte budget at all, and so no parser limit derived from it; bodies are then
    /// bounded only by the route caps (and maxBodySize). For servers whose routes never charge the budget.
    bool byteBudget {true};
    std::size_t maxBodySize {0}; ///< Server-wide declared-length cap; 0 = none of its own.
    std::size_t executorThreads {2};
    std::size_t executorQueue {64};
    bool expectContinue {false};  ///< Answer "Expect: 100-continue" once a request is admitted.
    bool detailedLogging {false}; ///< One TRACE line per request (method, target, status).
    /// Setting that raises the in-flight byte budget, named in the transport's budget-exhausted log line;
    /// empty omits the advice.
    std::string budgetOptionHint;
    /// Setting that raises the connection limit, named in the transport's connection-limit log line; empty
    /// omits the advice.
    std::string connectionCapOptionHint;
};

/**
 * @brief Counters and gauges of one UdsServer, for metrics.
 */
struct UdsServerStats
{
    std::size_t inFlightBytes {0};    ///< Bytes reserved by admitted requests.
    std::size_t inFlightRequests {0}; ///< Requests holding a reservation.
    std::size_t sessions {0};         ///< Open connections.
    std::size_t queueDepth {0};       ///< Requests admitted but not started.
    std::size_t running {0};          ///< Requests being handled.
    std::size_t shedBudget {0};       ///< 503: byte budget exhausted.
    std::size_t shedSessions {0};     ///< 503: connection or session cap reached.
    std::size_t shedExecutorFull {0}; ///< 503: the executor queue was full.
    std::size_t shedShutdown {0};     ///< 503: the server was stopping.
    std::size_t handlerErrors {0};    ///< 500: a handler threw.
    std::size_t rejectedTooLarge {0}; ///< 413: the body exceeded the route or server cap.
};

/**
 * @brief What a shutdown did with the requests still in the server.
 */
struct ShutdownReport
{
    std::size_t completed {0}; ///< Finished during the drain.
    std::size_t rejected {0};  ///< Not started at the deadline; answered 503.
    std::size_t abandoned {0}; ///< Still running at the deadline; their connection is closed.
};

/**
 * @brief An HTTP-over-Unix-socket server for the engine, on the manager's shared transport.
 *
 * The transport's I/O threads only parse, route and admit; every admitted request becomes a job of
 * this server's bounded executor, where the synchronous RouteHandler runs, and the reply goes back
 * through the transport. A full executor answers 503 {"error":"Server busy","code":503}; a handler
 * that throws answers 500 "Internal server error".
 *
 * Routes are registered before start(). The object is one-shot: start() once, stop once.
 */
class UdsServer : public IRouteRegistrar
{
public:
    explicit UdsServer(UdsServerOptions options);
    ~UdsServer() override;

    UdsServer(const UdsServer&) = delete;
    UdsServer& operator=(const UdsServer&) = delete;

    /**
     * @brief Registers a route. Must be called before start().
     */
    void addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options = {}) override;

    /**
     * @brief Binds the socket (mode 0660) and starts serving. Throws on failure.
     */
    void start(const std::filesystem::path& socketPath);

    bool isRunning() const;

    /// @name Shutdown steps (shutdown() and shutdownAll() run them in order)
    /// @{
    void stopAccepting();  ///< No new request reaches a handler; replies still go out.
    void closeAdmission(); ///< The executor takes nothing new; queued requests keep running.
    ShutdownReport drainUntil(std::chrono::steady_clock::time_point deadline);
    void stop(); ///< Drains the replies and closes the transport.
    /// Waits until no handler runs: one that outlived the deadline is waited for, never left running.
    void waitForHandlers();
    /// @}

    /**
     * @brief All the shutdown steps for this server alone. Returns only once no handler runs, so the caller can
     * destroy what the handlers use.
     */
    ShutdownReport shutdown(std::chrono::milliseconds deadline = DEFAULT_SHUTDOWN_DEADLINE);

    UdsServerStats stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * @brief Shuts several servers down together: every server stops accepting first, then every
 * executor closes admission, all drain in parallel up to one deadline, and only then is each
 * transport stopped. Null entries are skipped.
 */
void shutdownAll(const std::vector<UdsServer*>& servers,
                 std::chrono::milliseconds deadline = DEFAULT_SHUTDOWN_DEADLINE);

/**
 * @brief Publishes a server's stats() as fastmetrics pull metrics named server.<instance>.<suffix>
 * (in-flight bytes and requests, sessions, queue depth, running handlers, 503s by cause, handler
 * errors, 413s).
 *
 * The metrics hold only a weak reference: once the server is destroyed they read 0. The fastmetrics
 * manager must already be registered, and it keeps the first registration of a name: call this once
 * per instance name and process.
 *
 * @param server Server to observe.
 * @param instance Middle segment of every name ("ingest", "api").
 */
void registerMetrics(const std::weak_ptr<UdsServer>& server, const std::string& instance);

} // namespace httpsrv

#endif // _HTTPSRV_UDS_SERVER_HPP
