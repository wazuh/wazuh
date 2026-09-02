#pragma once

#include "../core/logger.hpp"
#include "i_ipc_server.hpp"
#include "i_query_handler.hpp"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wazuh::container_instances
{

    /// Unix-domain-socket query server: line-delimited JSON, one request/response
    /// per connection. An eventfd unblocks the accept loop on stop; a small worker
    /// pool keeps a slow cold-path resolution from head-of-line-blocking hot
    /// lookups.
    class IpcServer final : public IIpcServer
    {
    public:
        IpcServer(IQueryHandler& handler, std::string socketPath, Logger logger, std::size_t workerCount = 2);
        ~IpcServer() override;

        IpcServer(const IpcServer&) = delete;
        IpcServer& operator=(const IpcServer&) = delete;
        IpcServer(IpcServer&&) = delete;
        IpcServer& operator=(IpcServer&&) = delete;

        void start() override;
        void stop() override;

    private:
        void acceptLoop();
        void workerLoop();
        void handleClient(int clientFd);

        IQueryHandler& m_handler;
        std::string m_socketPath;
        Logger m_logger;
        std::size_t m_workerCount;

        int m_listenFd {-1};
        int m_wakeupFd {-1};
        std::atomic<bool> m_stopping {false};
        std::thread m_acceptThread;
        std::vector<std::thread> m_workers;

        std::mutex m_queueMutex;
        std::condition_variable m_queueCv;
        std::deque<int> m_pendingClients;
    };

} // namespace wazuh::container_instances
