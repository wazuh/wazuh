/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILD_FIM_ELEMENT_HPP
#define _BUILD_FIM_ELEMENT_HPP

#include "chainOfResponsability.hpp"
#include "elements/fileElement.hpp"
#include "elements/registryKeyElement.hpp"
#include "elements/registryValueElement.hpp"
#include "loggerHelper.h"
#include <stdexcept>

template<typename TContext>
class UpsertFimElement final : public AbstractHandler<std::shared_ptr<TContext>>
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~UpsertFimElement() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Context.
     * @return std::shared_ptr<Context> Abstract handler.
     */
    std::shared_ptr<TContext> handleRequest(std::shared_ptr<TContext> data) override
    {
        if (data->originTable() == TContext::OriginTable::File)
        {
            data->m_serializedElement = serializeToJSON(FileElement<TContext>::build(data.get()));
        }
        else if (data->originTable() == TContext::OriginTable::RegistryKey)
        {
            data->m_serializedElement = serializeToJSON(RegistryKeyElement<TContext>::build(data.get()));
        }
        else if (data->originTable() == TContext::OriginTable::RegistryValue)
        {
            data->m_serializedElement = serializeToJSON(RegistryValueElement<TContext>::build(data.get()));
        }
        else
        {
            logDebug2(LOGGER_DEFAULT_TAG, "UpsertFimElement::build: not implemented");
            return nullptr;
        }
        logDebug2(LOGGER_DEFAULT_TAG, "UpsertFimElement::build: %s", data->m_serializedElement.c_str());
        return AbstractHandler<std::shared_ptr<TContext>>::handleRequest(std::move(data));
    }
};

#endif // _BUILD_FIM_ELEMENT_HPP
