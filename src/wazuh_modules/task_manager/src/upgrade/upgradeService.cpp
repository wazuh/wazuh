/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "upgradeService.hpp"

#include "taskManagerLog.hpp"

#include <utility>

namespace task_manager::upgrade
{
    UpgradeService::UpgradeService(UpgradeOrchestrator& orchestrator,
                                   std::function<RemotedSettings()> remotedProvider,
                                   Options options)
        : m_orchestrator {orchestrator}
        , m_remotedProvider {std::move(remotedProvider)}
        , m_options {std::move(options)}
    {
        if (m_options.workers < 1)
        {
            m_options.workers = 1;
        }

        if (m_options.queueDepth < 1)
        {
            m_options.queueDepth = 1;
        }
    }

    UpgradeService::~UpgradeService()
    {
        stop();
    }

    void UpgradeService::start()
    {
        std::lock_guard lock {m_mutex};
        if (!m_workers.empty())
        {
            return;
        }

        m_workers.reserve(static_cast<std::size_t>(m_options.workers));
        for (int index = 0; index < m_options.workers; ++index)
        {
            m_workers.emplace_back([this] { workerLoop(); });
        }
    }

    std::vector<int> UpgradeService::agentsOf(const ParsedRequest& request)
    {
        return std::visit([](const auto& typed) { return typed.agentIds; }, request);
    }

    void UpgradeService::answer(const std::shared_ptr<wazuh::uds_http::IHttpResponder>& responder,
                                const std::string& body)
    {
        if (responder)
        {
            // Always 200. The per-agent verdicts live in the envelope, and the Server API reads
            // them; a non-2xx would be raised before it ever looked.
            responder->send(wazuh::uds_http::HttpResponse::json(200, body));
        }
    }

    bool UpgradeService::submit(ParsedRequest request, std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
    {
        std::lock_guard lock {m_mutex};

        if (m_stopping || m_jobs.size() >= m_options.queueDepth)
        {
            ++m_shed;
            // The responder is NOT taken: returning false leaves it with the caller, which answers.
            // Taking it and then failing to send would make the transport answer 503 on our behalf,
            // and the Server API handles that far worse than an explicit refusal.
            return false;
        }

        m_jobs.push_back(Job {std::move(request), std::move(responder)});
        m_queued.notify_one();
        return true;
    }

    void UpgradeService::workerLoop()
    {
        for (;;)
        {
            Job job;

            {
                std::unique_lock lock {m_mutex};
                m_queued.wait(lock, [this] { return m_stopping || !m_jobs.empty(); });

                if (m_jobs.empty())
                {
                    // Only reachable when stopping: stop() drains the queue itself so that the
                    // draining and the answering happen in one place.
                    return;
                }

                job = std::move(m_jobs.front());
                m_jobs.pop_front();
            }

            run(job);
        }
    }

    void UpgradeService::run(Job& job)
    {
        try
        {
            const auto remoted {m_remotedProvider ? m_remotedProvider() : RemotedSettings {}};

            const auto outcomes {std::visit(
                [&](const auto& typed) { return m_orchestrator.process(typed, remoted, m_stopToken); }, job.request)};

            answer(job.responder, buildResponse(UpgradeError::Success, outcomes));
        }
        catch (const std::exception& exception)
        {
            LOGFN_ERROR(upgradeLogFn(), "Unhandled error running an upgrade batch: %s", exception.what());
            // Still an answer, and still per agent: an unhandled fault here is indistinguishable
            // from the task manager being unreachable, which is what error 4 means -- and which the
            // Server API retries with a smaller chunk.
            answer(job.responder, buildUniformResponse(UpgradeError::TaskManagerCommunication, agentsOf(job.request)));
        }
        catch (...)
        {
            LOGFN_ERROR(upgradeLogFn(), "Unhandled non-standard error running an upgrade batch");
            answer(job.responder, buildUniformResponse(UpgradeError::TaskManagerCommunication, agentsOf(job.request)));
        }
    }

    void UpgradeService::stop()
    {
        std::deque<Job> pending;
        std::vector<std::thread> workers;

        {
            std::lock_guard lock {m_mutex};
            if (m_stopping && m_workers.empty())
            {
                return;
            }

            m_stopping = true;
            // Taken under the lock and answered outside it: sending a response can block on the
            // socket, and holding the queue mutex across that would stall every worker trying to
            // pick up its next job.
            pending.swap(m_jobs);
            workers.swap(m_workers);
        }

        m_stopToken.requestStop();
        m_queued.notify_all();

        // Answer what never started. These agents were accepted and must not be left to the
        // transport's 503 -- see the header.
        for (auto& job : pending)
        {
            answer(job.responder, buildUniformResponse(UpgradeError::TaskManagerCommunication, agentsOf(job.request)));
        }

        for (auto& worker : workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
    }

    std::size_t UpgradeService::queueDepth() const
    {
        std::lock_guard lock {m_mutex};
        return m_jobs.size();
    }

    std::size_t UpgradeService::shedCount() const
    {
        std::lock_guard lock {m_mutex};
        return m_shed;
    }
} // namespace task_manager::upgrade
