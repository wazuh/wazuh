/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentModuleFacade.hpp"
#include "components/indexerConnectorQueryPort.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <stdexcept>
#include <utility>

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

void ContentModuleFacade::start(
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
{
    Log::assignLogFunction(logFunction);
    Log::setModuleLogFn(LogFn {WM_CONTENTUPDATER});
}

void ContentModuleFacade::stop()
{
    // Same discipline as removeProvider, for all of them at once: unregister under the lock, then
    // stop and drain outside it. Destroying a provider while holding the registry lock would run a
    // sink's teardown under it, and a host whose teardown calls back in here would deadlock.
    std::unordered_map<std::string, std::unique_ptr<ContentProvider>> providers;
    {
        std::lock_guard<std::shared_mutex> lock {m_mutex};
        providers.swap(m_providers);
        m_sessions.clear();
    }

    // Every stop first, then every drain: one pass would let a topic run to completion while the
    // ones after it had not even been asked to wind down yet.
    for (auto& [_, provider] : providers)
    {
        if (provider)
        {
            provider->requestStop();
        }
    }
    for (auto& [_, provider] : providers)
    {
        if (provider)
        {
            provider->waitForIdle();
        }
    }
}

void ContentModuleFacade::removeProvider(const std::string& name)
{
    // Moved out under the lock and destroyed outside it: ~ContentProvider drains an in-flight cycle,
    // and that cycle's sink may reach back into the host, which may in turn call in here.
    std::unique_ptr<ContentProvider> provider;
    {
        std::lock_guard<std::shared_mutex> lock {m_mutex};
        if (const auto it = m_providers.find(name); it != m_providers.end())
        {
            provider = std::move(it->second);
            m_providers.erase(it);
        }
    }

    if (provider)
    {
        // The topic is unreachable from here on, so no new cycle can start; what remains is to wait
        // for one that had already claimed the slot. runOnce() claims it while still holding the
        // registry lock this function just took exclusively, which is what makes "erase, then
        // drain" airtight rather than racy: a cycle either claimed the slot before the erase — and
        // is waited for here — or never found the topic at all.
        provider->requestStop();
        provider->waitForIdle();
    }
}

void ContentModuleFacade::addProvider(const std::string& name,
                                      const nlohmann::json& parameters,
                                      std::shared_ptr<content_manager::IContentSink> sink,
                                      std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                                      std::shared_ptr<IIndexerQueryPort> port)
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};

    if (m_providers.find(name) != m_providers.end())
    {
        throw std::runtime_error("Provider already exist");
    }

    if (!port)
    {
        const auto& indexerConfig = parameters.at("configData").at("indexer");
        port = std::make_shared<IndexerConnectorQueryPort>(indexerConfig, sessionFor(indexerConfig));
    }

    m_providers.emplace(
        name,
        std::make_unique<ContentProvider>(name, parameters, std::move(sink), std::move(tokenStore), std::move(port)));
}

void ContentModuleFacade::startScheduling(const std::string& name, size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        if (const auto providerIt {m_providers.find(name)}; providerIt != m_providers.end())
        {
            providerIt->second->startActionScheduler(interval);
            return;
        }
        logDebug1(WM_CONTENTUPDATER, "Couldn't start scheduled action: Provider '%s' not found.", name.c_str());
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Couldn't start scheduled action: %s.", e.what());
    }
}

void ContentModuleFacade::startOndemand(const std::string& name)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        if (const auto providerIt {m_providers.find(name)}; providerIt != m_providers.end())
        {
            providerIt->second->startOnDemandAction();
            return;
        }
        logDebug1(WM_CONTENTUPDATER, "Couldn't start on-demand action: Provider '%s' not found.", name.c_str());
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Couldn't start on-demand action: %s.", e.what());
    }
}

void ContentModuleFacade::changeSchedulerInterval(const std::string& name, const size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        if (const auto providerIt {m_providers.find(name)}; providerIt != m_providers.end())
        {
            providerIt->second->changeSchedulerInterval(interval);
            return;
        }
        logDebug1(WM_CONTENTUPDATER, "Couldn't change scheduled interval: Provider '%s' not found.", name.c_str());
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Couldn't change scheduled interval: %s.", e.what());
    }
}

content_manager::CycleOutcome ContentModuleFacade::runOnce(const std::string& name,
                                                           content_manager::RunRequest request) noexcept
{
    // The registry lock is held only long enough to find the topic and claim its run slot, NOT for
    // the cycle itself. Holding it across a download would make registering or removing any *other*
    // topic wait for it — minutes, for a full feed load — and a reader-preferring shared_mutex can
    // starve that writer indefinitely under a steady stream of cycles.
    //
    // Claiming the slot under the lock is what keeps the short hold safe: removeProvider() erases
    // under the exclusive lock and only then drains, so a claim is either visible to that drain or
    // could not have happened.
    ContentProvider* provider = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock {m_mutex};

        const auto providerIt = m_providers.find(name);
        if (providerIt == m_providers.end())
        {
            content_manager::CycleOutcome outcome;
            outcome.status = content_manager::CycleStatus::FailedConfig;
            outcome.detail = "unknown topic '" + name + "'";
            return outcome;
        }

        provider = providerIt->second.get();
        if (!provider->tryBeginRun())
        {
            content_manager::CycleOutcome outcome;
            outcome.status = content_manager::CycleStatus::SkippedAlreadyRunning;
            outcome.detail = "an update for this topic is already in progress";
            return outcome;
        }
    }

    return provider->runClaimed(request);
}

std::string ContentModuleFacade::currentToken(const std::string& name) const noexcept
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    if (const auto providerIt = m_providers.find(name); providerIt != m_providers.end())
    {
        return providerIt->second->currentToken();
    }
    return {};
}

void ContentModuleFacade::requestStop(const std::string& name) noexcept
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    if (const auto providerIt = m_providers.find(name); providerIt != m_providers.end())
    {
        providerIt->second->requestStop();
    }
}

std::shared_ptr<IndexerSession> ContentModuleFacade::sessionFor(const nlohmann::json& indexerConfig)
{
    const auto key = fingerprint(indexerConfig);

    if (const auto it = m_sessions.find(key); it != m_sessions.end())
    {
        if (auto session = it->second.lock())
        {
            return session;
        }
    }

    auto session = std::make_shared<IndexerSession>(indexerConfig, LoggingContext {WM_CONTENTUPDATER, {}});
    m_sessions[key] = session;
    return session;
}

std::string ContentModuleFacade::fingerprint(const nlohmann::json& indexerConfig)
{
    // An ordered_json keeps the rendering stable regardless of how the host assembled the object,
    // so two equivalent configurations cannot end up with two sessions.
    nlohmann::ordered_json identity;
    for (const auto* key : {"hosts",
                            "ssl",
                            "username",
                            "password",
                            "service_account_token",
                            "monitoring_interval_seconds"})
    {
        if (indexerConfig.contains(key))
        {
            identity[key] = indexerConfig.at(key);
        }
    }
    return identity.dump();
}
