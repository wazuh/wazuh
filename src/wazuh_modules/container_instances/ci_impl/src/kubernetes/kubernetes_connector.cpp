#include "kubernetes_connector.hpp"

#include "k8s_object_parser.hpp"

#include <algorithm>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        constexpr auto RECONCILE_DEBOUNCE = std::chrono::milliseconds {500};
        constexpr auto BACKOFF_BASE = std::chrono::seconds {5};
        constexpr auto BACKOFF_CAP = std::chrono::seconds {60};
        constexpr auto WATCH_RETRY_DELAY = std::chrono::seconds {2};
        constexpr auto DEGRADED_COOLDOWN = std::chrono::seconds {60};
        constexpr int WATCH_MAX_RETRIES = 3;

        bool isKataPod(const PodSnapshot& pod)
        {
            return pod.runtimeClassName.find("kata") != std::string::npos;
        }

        ContainerRecord makeRecord(const PodSnapshot& pod,
                                   const PodContainer& container,
                                   const std::vector<OwnerRef>& ownerChain,
                                   const std::string& nodeName)
        {
            ContainerRecord record;
            record.runtime = ContainerRuntime::kubernetes;
            record.containerId = container.containerId;
            record.containerName = container.name;
            record.image = container.image;
            record.imageDigest = container.imageDigest;
            record.restartCount = container.restartCount;
            record.podUid = pod.uid;
            record.podName = pod.name;
            record.podNamespace = pod.podNamespace;
            record.nodeName = pod.nodeName.empty() ? nodeName : pod.nodeName;
            record.labels = pod.labels;
            record.annotations = pod.annotations;
            record.ownerRefs = ownerChain;
            record.network = pod.podIPs;
            record.ociMounts = container.mounts;
            return record;
        }

    } // namespace

    KubernetesConnector::KubernetesConnector(IKubernetesApiClient& client,
                                             const ICgroupResolver& resolver,
                                             IMetadataStore& store,
                                             const IWorkloadIndexSource& workloadIndex,
                                             std::string nodeName,
                                             Logger logger)
        : m_client(client)
        , m_resolver(resolver)
        , m_store(store)
        , m_workloadIndex(workloadIndex)
        , m_nodeName(std::move(nodeName))
        , m_logger(std::move(logger))
    {
    }

    void KubernetesConnector::reconcile()
    {
        const auto scan = m_resolver.scan();
        std::unordered_map<std::string, std::uint64_t> inodeByContainerId;
        for (const auto& entry : scan.containers)
        {
            inodeByContainerId.emplace(entry.containerId, entry.inode);
        }
        const auto inodeFor = [&inodeByContainerId](const std::string& containerId)
        {
            const auto it = inodeByContainerId.find(containerId);
            return (it != inodeByContainerId.end()) ? it->second : 0;
        };

        m_ownersGeneration = m_workloadIndex.generation();
        const auto workloads = m_workloadIndex.latest();

        std::vector<ContainerRecord> records;
        std::vector<std::pair<std::uint64_t, VerdictReason>> verdicts;

        for (const auto& [uid, pod] : m_podsByUid)
        {
            // Host-namespace and Kata pods never enter the retry/cold-cache loop:
            // their containers become permanent verdicts keyed by cgroup inode.
            if (pod.hostNetwork || pod.hostPID || isKataPod(pod))
            {
                const auto reason = isKataPod(pod) ? VerdictReason::kata : VerdictReason::hostNamespace;
                for (const auto& container : pod.containers)
                {
                    if (const auto inode = inodeFor(container.containerId); inode != 0)
                    {
                        verdicts.emplace_back(inode, reason);
                    }
                }
                continue;
            }

            const auto ownerChain = workloads ? k8s::resolveOwnerChain(pod, *workloads) : pod.ownerRefs;
            for (const auto& container : pod.containers)
            {
                auto record = makeRecord(pod, container, ownerChain, m_nodeName);
                record.cgroupId = inodeFor(container.containerId);
                records.push_back(std::move(record));
            }
        }

        m_store.applySnapshot(KUBERNETES_SOURCE, std::move(records), scan.allInodes, std::chrono::steady_clock::now());
        for (const auto& [inode, reason] : verdicts)
        {
            m_store.upsertVerdict(inode, reason);
        }

        m_lastReconcile = std::chrono::steady_clock::now();
        m_reconcilePending = false;
    }

    void KubernetesConnector::handleWatchEvent(const PodWatchEvent& event)
    {
        if (!event.resourceVersion.empty())
        {
            m_resourceVersion = event.resourceVersion;
        }

        if (m_workloadIndex.generation() != m_ownersGeneration)
        {
            m_reconcilePending = true;
        }

        switch (event.type)
        {
            case PodEventType::added:
            case PodEventType::modified: m_podsByUid[event.pod.uid] = event.pod; break;
            case PodEventType::deleted: m_podsByUid.erase(event.pod.uid); break;
            case PodEventType::bookmark:
            case PodEventType::error:
                if (m_reconcilePending && std::chrono::steady_clock::now() - m_lastReconcile >= RECONCILE_DEBOUNCE)
                {
                    reconcile();
                }
                return;
        }

        // Coalesce: at most one full reconcile per debounce window; the pending
        // flag makes the next event pick up anything skipped.
        m_reconcilePending = true;
        if (std::chrono::steady_clock::now() - m_lastReconcile >= RECONCILE_DEBOUNCE)
        {
            reconcile();
        }
    }

    void KubernetesConnector::run(const StopController& stop)
    {
        auto backoff = BACKOFF_BASE;

        while (!stop.isStopRequested())
        {
            try
            {
                const auto list = m_client.listPods();
                m_podsByUid.clear();
                for (const auto& pod : list.pods)
                {
                    m_podsByUid.emplace(pod.uid, pod);
                }
                m_resourceVersion = list.resourceVersion;
                reconcile();
                backoff = BACKOFF_BASE;

                for (int i = 0; i < 50 && m_workloadIndex.generation() == 0 && !stop.isStopRequested(); ++i)
                {
                    static_cast<void>(stop.waitFor(std::chrono::milliseconds {100}));
                }
                if (m_workloadIndex.generation() != m_ownersGeneration)
                {
                    reconcile();
                }

                int attempts = 0;
                while (!stop.isStopRequested())
                {
                    const auto outcome = m_client.watchPods(
                        m_resourceVersion, [this](const PodWatchEvent& event) { handleWatchEvent(event); }, stop);

                    if (outcome.kind == WatchOutcome::Kind::cancelled)
                    {
                        return;
                    }
                    if (m_reconcilePending)
                    {
                        reconcile(); // Flush anything the debounce deferred.
                    }
                    if (outcome.kind == WatchOutcome::Kind::gone)
                    {
                        m_logger(LogLevel::debug, "Watch resourceVersion expired; re-listing");
                        break;
                    }

                    ++attempts;
                    m_logger(LogLevel::warn,
                             "Pod watch disconnected (attempt " + std::to_string(attempts) + "/" +
                                 std::to_string(WATCH_MAX_RETRIES) + "): " + outcome.message);
                    if (attempts >= WATCH_MAX_RETRIES)
                    {
                        m_logger(LogLevel::warn,
                                 "Pod watch failed " + std::to_string(WATCH_MAX_RETRIES) +
                                     " times; falling back to periodic re-list until the watch recovers");
                        if (!stop.waitFor(DEGRADED_COOLDOWN))
                        {
                            return;
                        }
                        break; // Outer loop re-lists and tries a fresh watch.
                    }
                    if (!stop.waitFor(WATCH_RETRY_DELAY))
                    {
                        return;
                    }
                }
            }
            catch (const KubernetesApiError& error)
            {
                if (error.httpStatus() == 403)
                {
                    m_logger(LogLevel::error,
                             std::string {"Access denied by the apiserver (check the wazuh-container-instances "
                                          "ClusterRole/ClusterRoleBinding): "} +
                                 error.what());
                }
                else
                {
                    m_logger(LogLevel::warn, std::string {"Kubernetes connector error: "} + error.what());
                }
                if (!stop.waitFor(backoff))
                {
                    return;
                }
                backoff = std::min(backoff * 2, std::chrono::seconds {BACKOFF_CAP});
            }
            catch (const std::exception& error)
            {
                m_logger(LogLevel::warn, std::string {"Kubernetes connector error: "} + error.what());
                if (!stop.waitFor(backoff))
                {
                    return;
                }
                backoff = std::min(backoff * 2, std::chrono::seconds {BACKOFF_CAP});
            }
        }
    }

    RefreshOutcome KubernetesConnector::refreshOne(const std::string& containerId, std::uint64_t cgroupInode)
    {
        try
        {
            // One list; the watch cache normally already holds the pod, this is
            // the cold-path fallback only.
            const auto list = m_client.listPods();
            m_ownersGeneration = m_workloadIndex.generation();
            const auto workloads = m_workloadIndex.latest();

            for (const auto& pod : list.pods)
            {
                for (const auto& container : pod.containers)
                {
                    if (container.containerId != containerId)
                    {
                        continue;
                    }
                    if (pod.hostNetwork || pod.hostPID || isKataPod(pod))
                    {
                        m_store.upsertVerdict(cgroupInode,
                                              isKataPod(pod) ? VerdictReason::kata : VerdictReason::hostNamespace);
                        return RefreshOutcome::resolved;
                    }
                    auto record = makeRecord(pod,
                                             container,
                                             workloads ? k8s::resolveOwnerChain(pod, *workloads) : pod.ownerRefs,
                                             m_nodeName);
                    record.cgroupId = cgroupInode;
                    m_store.upsertResolved(KUBERNETES_SOURCE, std::move(record));
                    return RefreshOutcome::resolved;
                }
            }
            return RefreshOutcome::notFound;
        }
        catch (const std::exception& error)
        {
            m_logger(LogLevel::debug, std::string {"On-demand pod lookup failed: "} + error.what());
            return RefreshOutcome::error;
        }
    }

} // namespace wazuh::container_instances
