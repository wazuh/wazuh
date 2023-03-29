#ifndef _SERVER_ENDPOINT_HPP
#define _SERVER_ENDPOINT_HPP

#include <atomic>
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
    std::string m_address;
    std::shared_ptr<uvw::Loop> m_loop;
    bool m_running;
    std::atomic<std::size_t> m_currentQWSize;      ///< Current size of the queue worker

    Endpoint(const std::string& address)
        : m_address(address)
        , m_loop(nullptr)
        , m_running(false)
        , m_currentQWSize(0)
    {
    }

public:
    /**
     * @brief Destroy the  Endpoint object, made virtual to destroy children classes.
     *
     */
    virtual ~Endpoint() {};

    /**
     * @brief Configure and bind endpoint.
     *
     * @param loop (std::shared_ptr<uvw::Loop>) Loop to bind endpoint.
     * @param queueWorkerSize (std::size_t) Size of the queue worker. If 0, the callback is called synchronously.
     * @throw (std::runtime_error) If endpoint is already bound or endpoint can't be bound.
     */
    virtual void bind(std::shared_ptr<uvw::Loop> loop, const  std::size_t queueWorkerSize = 0) = 0;

    /**
     * @brief Close and liberate all resources used by endpoint.
     *
     */
    virtual void close(void) = 0;

    /**
     * @brief Get the Address object.
     *
     * @return (std::string) Endpoint address.
     */
    std::string getAddress() const { return m_address; }

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
