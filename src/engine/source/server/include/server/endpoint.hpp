#ifndef _SERVER_ENDPOINT_HPP
#define _SERVER_ENDPOINT_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include <uvw.hpp>

namespace engineserver
{

/**
 * @brief Endpoint base interfaz that exposes functionality required by EngineServer.
 */
class Endpoint
{

protected:
    std::string m_address;             ///< Endpoint address.
    std::shared_ptr<uvw::Loop> m_loop; ///< Loop to bind endpoint.
    bool m_running;                    ///< If endpoint is running.
    const std::size_t m_taskQueueSize; ///< Size of of the queue of tasks to be processed by the thread pool. If 0, the
                                       ///< callback is called synchronously.
    /** @brief Current size of the queue of tasks to be processed by the thread pool */
    std::atomic<std::size_t> m_currentTaskQueueSize;

    /**
     * @brief Construct a new Endpoint object.
     *
     * @param address Endpoint address.
     * @param taskQueueSize Size of the queue worker. If 0, the callback is called synchronously.
     */
    Endpoint(const std::string& address, const std::size_t taskQueueSize)
        : m_address(address)
        , m_loop(nullptr)
        , m_running(false)
        , m_currentTaskQueueSize(0)
        , m_taskQueueSize(taskQueueSize)
    {
    }

    /**
     * @brief Unlink unix socket if exists and is a socket.
     *
     * Do nothing if socket does not exist.
     * @throw std::runtime_error If unlink fails.
     */
    void unlinkUnixSocket();

public:
    /**
     * @brief Destroy the  Endpoint object, made virtual to destroy children classes.
     *
     */
    virtual ~Endpoint() {};

    /**
     * @brief Bind endpoint to loop.
     *
     * Bind endpoint to loop. Endpoint must be closed before binding.
     * @param loop Loop to bind endpoint.
     * @throw std::runtime_error If endpoint is already bound.
     */
    virtual void bind(std::shared_ptr<uvw::Loop> loop) = 0;

    /**
     * @brief Close and liberate all resources used by endpoint.
     *
     */
    virtual void close(void) = 0;

    /**
     * @brief Get the Address
     *
     * @return Endpoint address.
     */
    std::string getAddress() const { return m_address; }

    /**
     * @brief Get the Task Queue Size
     *
     * @return Size of the queue worker. If 0, the callback is called synchronously.
     */
    std::size_t gettaskQueueSize() const { return m_taskQueueSize; }

    /**
     * @brief Get the Current Task Queue Size
     *
     * @return Current size of the queue of tasks to be processed by the thread pool.
     */
    const std::size_t getCurrenttaskQueueSize() const { return m_currentTaskQueueSize; }

    /**
     * @brief if endpoint is bound.
     *
     * @return (bool) True if endpoint is bound.
     */
    bool isBound() const { return m_loop != nullptr; }

    /**
     * @brief Pause receiving data. Endpoint must be bound.
     *
     * @return (bool) True if endpoint was paused.
     * This Method is not thread safe and must be called from the same thread that loop is running.
     */
    virtual bool pause() = 0;

    /**
     * @brief Resume receiving data. Endpoint must be bound.
     *
     * @return (bool) True if endpoint was resumed.
     * This Method is not thread safe and must be called from the same thread that loop is running.
     */
    virtual bool resume() = 0;
};

} // namespace engineserver

#endif // _SERVER_ENDPOINT_HPP
