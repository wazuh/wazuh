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

#ifndef _DELETE_FIM_ELEMENT_HPP
#define _DELETE_FIM_ELEMENT_HPP

#include "chainOfResponsability.hpp"
#include "elements/fileElement.hpp"
#include "elements/registryKeyElement.hpp"
#include "elements/registryValueElement.hpp"
#include "loggerHelper.h"

template<typename TContext>
class DeleteFimElement final : public AbstractHandler<std::shared_ptr<TContext>>
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~DeleteFimElement() = default;
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
            data->m_serializedElement = serializeToJSON(FileElement<TContext>::deleteElement(data.get()));
        }
        else if (data->originTable() == TContext::OriginTable::RegistryKey)
        {
            data->m_serializedElement = serializeToJSON(RegistryKeyElement<TContext>::deleteElement(data.get()));
        }
        else if (data->originTable() == TContext::OriginTable::RegistryValue)
        {
            data->m_serializedElement = serializeToJSON(RegistryValueElement<TContext>::deleteElement(data.get()));
        }
        else
        {
            logDebug2(LOGGER_DEFAULT_TAG, "DeleteFimElement::build: not implemented");
            return nullptr;
        }
        logDebug2(LOGGER_DEFAULT_TAG, "DeleteFimElement::build: %s", data->m_serializedElement.c_str());
        return AbstractHandler<std::shared_ptr<TContext>>::handleRequest(std::move(data));
    }
};

#endif // _DELETE_FIM_ELEMENT_HPP
