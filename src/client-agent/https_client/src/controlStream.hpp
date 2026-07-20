/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CONTROL_STREAM_HPP
#define _HC_CONTROL_STREAM_HPP

#include "callbackSink.hpp"
#include "controlStateMachine.hpp"
#include "moduleConfig.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"
#include "taskDeduper.hpp"

#include <mutex>
#include <string>
#include <vector>

/**
 * @brief The /control client: Startup, Notify and Response, speaking the
 *        message formats of #37733 Appendix C.
 *
 * Drives the pure ControlStateMachine: nextAction() decides the request,
 * step() performs it and feeds the result back as an event. Startup applies
 * the handshake JSON and releases the producer gate; Notify reports the
 * config hash and dispatches the deduped tasks[] (at-least-once) through the
 * sink; Response posts queued task results.
 */
class ControlStream final
{
    public:
        ControlStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                      IClock& clock, IRandom& random, ICallbackSink& sink);

        /// One control iteration. Returns whether Startup has been accepted (the
        /// producer gate is open) so the facade can gate the data streams.
        bool step(Waiter& waiter);

        /// Queue a task result for the next Response.
        void queueTaskResponse(const std::string& taskId, const std::string& resultJson);

        hc_conn_state_t connState() const;
        bool isRegistered() const;

        /// True while retrying Startup (Rejected/AuthError): use the slow cadence.
        bool useSlowCadence() const
        {
            return m_machine.useSlowCadence();
        }

    private:
        OutcomeClass sendStartup(Waiter& waiter);
        OutcomeClass sendNotify(Waiter& waiter);
        void sendPendingResponses(Waiter& waiter);
        void applyEffects(const ControlStateMachine::Effects& effects, const std::string& handshake);
        void handleNotifyBody(const std::string& body);
        void dispatchTasks(const std::string& body);
        ControlStateMachine::Event eventFor(OutcomeClass outcome) const;

        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        ICallbackSink& m_sink;
        ControlStateMachine m_machine;
        TaskDeduper m_deduper;

        std::mutex m_responseMutex;
        std::vector<std::pair<std::string, std::string>> m_pendingResponses;
};

#endif // _HC_CONTROL_STREAM_HPP
