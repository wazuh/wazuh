#ifndef _SERVER_ENDPOINT_UNIX_DATAGRAM_HPP
#define _SERVER_ENDPOINT_UNIX_DATAGRAM_HPP

#include <functional>
#include <memory>

#include <metrics/iMetricsManager.hpp>

#include <server/endpoint.hpp>

namespace engineserver::endpoint
{
/**
 * @brief Unix Datagram class to handle unix datagram sockets
 *
 * @details This class is used to handle unix datagram sockets. It is used to communicate with the engine.
 * It is a child of the Endpoint class.
 *
 * If the taskQueueSize is set to 0, the callback function will be called in the same thread as the one that received
 * the message. If the taskQueueSize is set to a value greater than 0, the callback function will be called in a
 * thread from a thread pool. If the queue is full, the handle will be paused and the message will enqueue until a slot
 * is available. If the client is configured as blocking, the client will be blocked until a slot in the queue is
 * available. If the client is configured as non-blocking, the client will receive a "Resource temporarily unavailable"
 * error. The size of the thread pool is defined by the taskQueueSize parameter.
 *
 * @note The thread pool is shared between all the endpoints.
 * @note Currently responses are not implemented, so the callback function must not return a string.
 */
class UnixDatagram : public Endpoint
{
private:
    std::function<void(std::string&)> m_callback; ///< Callback function to be called when a message is received
    std::shared_ptr<uvw::UDPHandle> m_handle;     ///< Handle to the socket
    int m_bufferSize;                             ///< Size of the receive buffer

    struct Metric
    {
        std::shared_ptr<metricsManager::IMetricsScope> m_metricsScope;     ///< Metrics scope for the endpoint
        std::shared_ptr<metricsManager::iCounter<uint64_t>> m_byteRecv;    ///< Counter for the total requests
        std::shared_ptr<metricsManager::iHistogram<uint64_t>> m_eventSize; ///< Histogram for the event size
        std::shared_ptr<metricsManager::iHistogram<uint64_t>> m_queueSize; ///< Histogram for the use queue size
        std::shared_ptr<metricsManager::iCounter<uint64_t>> m_busyQueue;   ///< Counter for the busy queue

        std::shared_ptr<metricsManager::IMetricsScope> m_metricsScopeDelta; ///< Metrics scope for the endpoint rate
        std::shared_ptr<metricsManager::iCounter<uint64_t>> m_byteRecvPerSecond; ///< Byte received per second
        std::shared_ptr<metricsManager::iCounter<uint64_t>> m_eventPerSecond;    ///< Event received per second
    };
    Metric m_metric;

    /**
     * @brief This function opens, binds and configures a Unix datagram socket.
     *
     * @return Returns either the file descriptor value
     * @throw std::runtime_error if the path is too long or the socket cannot be created or bound.
     */
    int bindUnixDatagramSocket(int& bufferSize);

public:
    /**
     * @brief Create a Unix Datagram object
     *
     * @param address Path to the socket
     * @param callback Callback function to be called when a message is received
     * @param metricsScope Metrics scope for the endpoint
     * @param metricsScopeDelta Metrics scope for the endpoint rate
     * @param taskQueueSize Size of the queue of tasks to be processed by the thread pool
     */
    UnixDatagram(const std::string& address,
                 const std::function<void(const std::string&)>& callback,
                 std::shared_ptr<metricsManager::IMetricsScope> metricsScope,
                 std::shared_ptr<metricsManager::IMetricsScope> metricsScopeDelta,
                 const std::size_t taskQueueSize = 0);

    /**
     * @brief Construct a new Unix Datagram object
     *
     * @param address Path to the socket
     * @param callback Callback function to be called when a message is received, it must return a string to be sent
     * back to the client
     * @param taskQueueSize Size of queue worker thread pool
     * #TODO: Not implemented yet
     */
    UnixDatagram(const std::string& address,
                 std::function<std::string(const std::string&)> callback,
                 const std::size_t taskQueueSize = 0);
    ~UnixDatagram();

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

    /**
     * @brief Get the size of the receive buffer
     * @return int Size of the receive buffer
     */
    int getReciveBufferSize(void) { return m_bufferSize; };
};
} // namespace engineserver::endpoint
#endif // _SERVER_ENDPOINT_UNIX_DATAGRAM_HPP
