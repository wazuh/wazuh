#include <uvw.hpp>
#ifndef _SERVER_ENDPOINT_HPP
#define _SERVER_ENDPOINT_HPP

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

    Endpoint(const std::string& address)
        : m_address(address)
        , m_loop(nullptr)
        , m_running(false)
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
     */
    virtual void bind(std::shared_ptr<uvw::Loop> loop) = 0;

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
     */
    virtual bool pause() = 0;

    /**
     * @brief Resume receiving data. Endpoint must be bound.
     *
     * @return (bool) True if endpoint was resumed.
     */
    virtual bool resume() = 0;
};

} // namespace engineserver

#endif // _SERVER_ENDPOINT_HPP
