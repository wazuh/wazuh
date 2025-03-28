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

#ifndef _DELETE_SYSTEM_ELEMENT_HPP
#define _DELETE_SYSTEM_ELEMENT_HPP

#include "chainOfResponsability.hpp"
#include "elements/osElement.hpp"
#include "elements/packageElement.hpp"
#include "elements/portElement.hpp"
#include "elements/processElement.hpp"
#include "loggerHelper.h"

template<typename TContext>
class DeleteSystemElement final : public AbstractHandler<std::shared_ptr<TContext>>
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~DeleteSystemElement() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Context.
     * @return std::shared_ptr<Context> Abstract handler.
     */
    std::shared_ptr<TContext> handleRequest(std::shared_ptr<TContext> data) override
    {
        if (const auto originTable = data->originTable(); originTable == TContext::OriginTable::Os)
        {
            data->m_serializedElement = serializeToJSON(OsElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::Packages)
        {
            data->m_serializedElement = serializeToJSON(PackageElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::Processes)
        {
            data->m_serializedElement = serializeToJSON(ProcessElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::Ports)
        {
            data->m_serializedElement = serializeToJSON(PortElement<TContext>::deleteElement(data.get()));
        }
        else
        {
            logDebug2(LOGGER_DEFAULT_TAG, "DeleteSystemElement::build: not implemented");
            return nullptr;
        }
        logDebug2(LOGGER_DEFAULT_TAG, "DeleteSystemElement::build: %s", data->m_serializedElement.c_str());
        return AbstractHandler<std::shared_ptr<TContext>>::handleRequest(std::move(data));
    }
};

#endif // _DELETE_SYSTEM_ELEMENT_HPP
