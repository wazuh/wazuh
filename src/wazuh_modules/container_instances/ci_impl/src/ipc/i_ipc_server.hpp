#pragma once

namespace wazuh::container_instances
{

    class IIpcServer
    {
    public:
        virtual ~IIpcServer() = default;

        /// @throws std::runtime_error on socket/bind/listen failure.
        virtual void start() = 0;

        /// Idempotent; unblocks the accept loop and joins all threads.
        virtual void stop() = 0;
    };

} // namespace wazuh::container_instances
