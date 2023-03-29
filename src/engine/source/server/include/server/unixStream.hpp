#ifndef _SERVER_UNIX_STREAM_HPP
#define _SERVER_UNIX_STREAM_HPP

#include <atomic>
#include <functional>

#include <server/endpoint.hpp>
#include <server/protocolHandler.hpp>


namespace engineserver::endpoint
{
class UnixStream : public Endpoint
{
private:
    std::shared_ptr<uvw::PipeHandle> m_handle;
    std::size_t m_timeout;
    std::function<std::shared_ptr<std::string>(const std::shared_ptr<std::string>)> m_callback;
    std::shared_ptr<std::string> createWork(std::shared_ptr<uvw::PipeHandle> client,
                                                    std::shared_ptr<ProtocolHandler> protocolHandler,
                                                    std::string&& data);
    std::shared_ptr<ProtocolHandlerFactory> m_factory;

public:
    UnixStream(const std::string& address, std::shared_ptr<ProtocolHandlerFactory> factory, std::size_t timeout = 5000);
    ~UnixStream();

    /**
     * @copydoc link-object::Endpoint::bind
     */
    void bind(std::shared_ptr<uvw::Loop> loop, const std::size_t queueWorkerSize = 0) override;

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
#endif // _SERVER_UNIX_STREAM_HPP
