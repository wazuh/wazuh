#pragma once

#include "../cache/lifecycle_journal.hpp"
#include "../core/logger.hpp"

#include <string>
#include <vector>

namespace wazuh::container_instances
{

    /// Tells consumers that the container list moved, so they can read the
    /// journal now instead of at their next scheduled poll.
    ///
    /// Fire-and-forget datagrams to sockets the CONSUMERS bind, which is the
    /// shape agentd already uses to reach execd. Three properties follow from
    /// that choice and are the reason it was taken over a subscription:
    ///
    ///   - No connection, so nothing occupies the query server's small worker
    ///     pool, which exists to answer the eBPF enrichment hot path.
    ///   - No registry, so the module keeps no per-consumer state and a consumer
    ///     that dies needs no cleanup.
    ///   - No delivery guarantee, which is affordable only because the datagram
    ///     carries no authority: it says "something changed", never what. A loss
    ///     costs latency until the consumer's own periodic read, and nothing
    ///     else.
    ///
    /// Sending never blocks and never fails loudly. A consumer that has not
    /// bound its socket is the normal case — the feature is off, or that daemon
    /// is not running — so a failed send is logged once per socket per change of
    /// state rather than on every reconcile.
    class LifecycleNotifier
    {
        public:
            /// @param socketPaths absolute paths of the consumer-bound sockets.
            LifecycleNotifier(std::vector<std::string> socketPaths, Logger logger);
            ~LifecycleNotifier();

            LifecycleNotifier(const LifecycleNotifier&) = delete;
            LifecycleNotifier& operator=(const LifecycleNotifier&) = delete;
            LifecycleNotifier(LifecycleNotifier&&) = delete;
            LifecycleNotifier& operator=(LifecycleNotifier&&) = delete;

            /// Sends one datagram per configured socket. Safe to call from the
            /// store's notify hook; does no allocation beyond the payload and
            /// never waits on a reader.
            void notify(const LifecycleCursor& cursor);

        private:
            struct Target
            {
                std::string path;
                /// Whether the last send succeeded, so the log reports
                /// transitions rather than repeating every few hundred
                /// milliseconds on a host where the consumer is simply absent.
                bool lastSendOk {true};
            };

            int m_fd {-1};
            std::vector<Target> m_targets;
            Logger m_logger;
    };

} // namespace wazuh::container_instances
