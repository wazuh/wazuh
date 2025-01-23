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

#ifndef _BUILD_SYSTEM_ELEMENT_HPP
#define _BUILD_SYSTEM_ELEMENT_HPP

#include "chainOfResponsability.hpp"
#include "elements/hwElement.hpp"
#include "elements/osElement.hpp"
#include "elements/packageElement.hpp"
#include "elements/processElement.hpp"
#include <stdexcept>

template<typename TContext>
class UpsertSystemElement final : public AbstractHandler<std::shared_ptr<TContext>>
{
    void build(TContext* data)
    {
        if (data->originTable() == TContext::OriginTable::Hw)
        {
            data->m_serializedElement = serializeToJSON(HwElement<TContext>::build(data));
        }
        else if (data->originTable() == TContext::OriginTable::Os)
        {
            data->m_serializedElement = serializeToJSON(OsElement<TContext>::build(data));
        }
        else if (data->originTable() == TContext::OriginTable::Packages)
        {
            data->m_serializedElement = serializeToJSON(PackageElement<TContext>::build(data));
        }
        else if (data->originTable() == TContext::OriginTable::Processes)
        {
            data->m_serializedElement = serializeToJSON(ProcessElement<TContext>::build(data));
        }
        else
        {
            throw std::runtime_error("Unable to build scan context. Unknown type");
        }
    }

public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~UpsertSystemElement() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Context.
     * @return std::shared_ptr<Context> Abstract handler.
     */
    std::shared_ptr<TContext> handleRequest(std::shared_ptr<TContext> data) override
    {
        build(data.get());
        return AbstractHandler<std::shared_ptr<TContext>>::handleRequest(std::move(data));
    }
};

#endif // _BUILD_SYSTEM_ELEMENT_HPP
