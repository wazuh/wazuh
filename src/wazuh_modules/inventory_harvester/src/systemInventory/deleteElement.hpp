/*
 * Wazuh Inventory Harvester - Delete element
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
#include "elements/browserExtensionElement.hpp"
#include "elements/groupElement.hpp"
#include "elements/hotfixElement.hpp"
#include "elements/hwElement.hpp"
#include "elements/netElement.hpp"
#include "elements/netIfaceElement.hpp"
#include "elements/networkProtocolElement.hpp"
#include "elements/osElement.hpp"
#include "elements/packageElement.hpp"
#include "elements/portElement.hpp"
#include "elements/processElement.hpp"
#include "elements/userElement.hpp"
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
        else if (originTable == TContext::OriginTable::Hw)
        {
            data->m_serializedElement = serializeToJSON(HwElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::Hotfixes)
        {
            data->m_serializedElement = serializeToJSON(HotfixElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::NetworkProtocol)
        {
            data->m_serializedElement = serializeToJSON(NetworkProtocolElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::NetIfaces)
        {
            data->m_serializedElement = serializeToJSON(NetIfaceElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::NetAddress)
        {
            data->m_serializedElement = serializeToJSON(NetElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::Users)
        {
            data->m_serializedElement = serializeToJSON(UserElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::Groups)
        {
            data->m_serializedElement = serializeToJSON(GroupElement<TContext>::deleteElement(data.get()));
        }
        else if (originTable == TContext::OriginTable::BrowserExtensions)
        {
            data->m_serializedElement = serializeToJSON(BrowserExtensionElement<TContext>::deleteElement(data.get()));
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
