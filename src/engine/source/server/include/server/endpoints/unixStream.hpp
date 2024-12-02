#ifndef _SERVER_ENDPOINT_UNIX_STREAM_HPP
#define _SERVER_ENDPOINT_UNIX_STREAM_HPP

#include <atomic>
#include <functional>

#include <server/endpoint.hpp>
#include <server/protocolHandler.hpp>

namespace engineserver::endpoint
{
/**
 * @brief Unix Stream class to handle unix stream sockets.
 *
 * @details This class is used to handle unix stream sockets. It is used to communicate with the engine.
 * It is a child of the Endpoint class.
 *
 * If the taskQueueSize is set to 0, the callback function will be called in the same thread as the one that received
 * the message. If the taskQueueSize is set to a value greater than 0, the callback function will be enqueued and
 * called in a thread from a thread pool when a slot is available
 * If the queue is full, drop the message and respond with an error from the protocol handler,
 * "resource temporarily unavailable"
 *
 * @note The thread pool is shared between all the endpoints.
 * @note Currently responses are not implemented, so the callback function must not return a string.
 */
class UnixStream : public Endpoint
{
private:
    std::shared_ptr<uvw::PipeHandle> m_handle;         ///< Handle to the socket
    std::size_t m_timeout;                             ///< Timeout for the connection in milliseconds
    std::shared_ptr<ProtocolHandlerFactory> m_factory; ///< Factory to create protocol handlers for each client

    // struct Metric
    // {
    //     std::shared_ptr<metricsManager::IMetricsScope> m_metricsScope;         ///< Metrics scope for the endpoint
    //     std::shared_ptr<metricsManager::iCounter<uint64_t>> m_totalRequest;    ///< Counter for the total requests
    //     std::shared_ptr<metricsManager::iHistogram<uint64_t>> m_responseTime;  ///< Histogram for the response time
    //     std::shared_ptr<metricsManager::iHistogram<uint64_t>> m_queueSize;     ///< Histogram for the queue size
    //     std::shared_ptr<metricsManager::iCounter<int64_t>> m_connectedClients; ///< Counter for the current clients
    //     std::shared_ptr<metricsManager::iCounter<uint64_t>> m_serverBusy;      ///< Counter for the server busy

    //     std::shared_ptr<metricsManager::IMetricsScope> m_metricsScopeDelta;     ///< Metrics scope for the endpoint
    //     rate std::shared_ptr<metricsManager::iCounter<uint64_t>> m_requestPerSecond; ///< Counter for the requests
    //     per second
    // };
    // Metric m_metric; ///< Metrics for the endpoint
    /**
     * @brief Create a client
     *
     * This function is used to create a client to establish a connection with the engine,
     * it is called when a new connection is received.
     *
     * @return std::shared_ptr<uvw::PipeHandle> Handle to the client
     */
    std::shared_ptr<uvw::PipeHandle> createClient();

    /**
     * @brief Process messages
     *
     * This function is used to process the messages received from the client, it is called when a stream is parsed.
     * @param client Handle to the client that sent the message
     * @param asyncs Array of AsyncHandler instance that will be used to send the event using send()
     * @param protocolHandler Protocol handler to process the message
     * @param requests Messages to be processed
     * @param response Shared memory where the callback executed by the AsyncHandle will write the response
     */
    void processMessages(std::weak_ptr<uvw::PipeHandle> clientRef,
                         std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs,
                         std::shared_ptr<ProtocolHandler> protocolHandler,
                         std::vector<std::string>&& requests);

    /**
     * @brief Create a Task from a message received from the client and enqueue it
     *
     * This function is used to create a task work from a message received from the client, it is called when a message
     * is received and enqueued for processing by the thread pool.
     * @param client Handle to the client that sent the message
     * @param asyncs Array of AsyncHandler instance that will be used to send the event using send()
     * @param protocolHandler Protocol handler to process the message
     * @param request Message to be processed
     */
    void createAndEnqueueTask(std::weak_ptr<uvw::PipeHandle> wClient,
                              std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs,
                              std::shared_ptr<ProtocolHandler> protocolHandler,
                              std::string&& request);

    /**
     * @brief Configure the client to close the connection gracefully
     *
     * @param client Client to close
     * @param async Array of AsyncHandler instance that will be used to send the event using send()
     * @param timer Timer to close if the client closes the connection
     */
    void configureCloseClient(std::shared_ptr<uvw::PipeHandle> client,
                              std::shared_ptr<uvw::TimerHandle> timer,
                              std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> async);

    /**
     * @brief Create a Timer resource, this timer will be used to close the client connection if it doesn't send any
     * data
     *
     * @param loop Loop to create the timer
     * @param wClient Client to close if the timer expires
     * @param asyncs Array of AsyncHandler instance that will be used to send the event using send()
     * @return Timer resource
     */
    std::shared_ptr<uvw::TimerHandle> createTimer(std::weak_ptr<uvw::PipeHandle> wClient,
                                                  std::shared_ptr<std::vector<std::weak_ptr<uvw::AsyncHandle>>> asyncs);

public:
    /**
     * @brief Construct a new Unix Stream object
     *
     * @param address Path to the socket
     * @param factory Factory to create protocol handlers for each client
     * @param taskQueueSize Size of the queue of tasks to be processed by the thread pool
     * @param timeout Timeout for the connection in milliseconds
     */
    UnixStream(const std::string& address,
               std::shared_ptr<ProtocolHandlerFactory> factory,
               const std::size_t taskQueueSize = 0,
               std::size_t timeout = 5000);
    ~UnixStream();

    /**
     * @copydoc link-object::Endpoint::bind
     */
    void bind(std::shared_ptr<uvw::Loop> loop) override;

    /**
     * @copydoc link-object::Endpoint::close
     */
    void close(void) override;

    /**
     * @copydoc link-object::Endpoint::pause
     */
    bool pause(void) override;

    /**
     * @copydoc link-object::Endpoint::resume
     */
    bool resume(void) override;
};
} // namespace engineserver::endpoint
#endif // _SERVER_ENDPOINT_UNIX_STREAM_HPP
