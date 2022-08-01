/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderHelperNetInfoAddress.hpp"

#include <optional>
#include <string>
#include <variant>

#include "syntax.hpp"

#include <baseHelper.hpp>
#include "protocolHandler.hpp"
#include <wdb/wdb.hpp>
#include <kvdb/kvdbManager.hpp>

namespace builder::internals::builders
{

// TODO: remove when undoing set for testing
constexpr std::string_view STREAM_SOCK_PATH = "/tmp/testStream.socket";

using builder::internals::syntax::REFERENCE_ANCHOR;

// when isIPv6 == true the third field will be set to 0
// agent <ID> netaddr save <ID>|<name>|isIPv6=false|add[i]|netm[i]|broad[i]
// agent 0001 netaddr save ID|name|0|add0|netm0|broad0
static bool sysNetAddresTableFill(base::Event event, bool isIPv6)
{
    auto agent_id {event->getString(engineserver::EVENT_AGENT_ID)};
    auto scan_id {event->getString(std::string(engineserver::EVENT_LOG) + "/ID")};
    auto name {event->getString(std::string(engineserver::EVENT_LOG) + "/iface/name")};

    std::vector<std::string> addresValues {};
    std::vector<std::string> netmaskValues {};
    std::vector<std::string> broadcastValues {};

    std::string middleFieldName = isIPv6 ? "IPv6" : "IPv4";
    std::string msg {"agent " + agent_id.value() + " netaddr save"};

    const auto& address_ar = event->getArray(std::string(engineserver::EVENT_LOG)
                                             + "/iface/" + middleFieldName + "/address");
    for (auto const& address : address_ar.value())
    {
        if (address.isString())
        {
            addresValues.emplace_back(address.getString().value());
        }
        else
        {
            return false;
        }
    }

    const auto& netmasks_ar = event->getArray(std::string(engineserver::EVENT_LOG)
                                              + "/iface/" + middleFieldName + "/netmask");
    for (auto const& netmask : netmasks_ar.value())
    {
        if (!netmask.isString())
        {
            netmaskValues.emplace_back("NULL");
        }
        netmaskValues.emplace_back(netmask.getString().value());
    }

    const auto& broadcast_ar =
        event->getArray(std::string(engineserver::EVENT_LOG) + "/iface/" + middleFieldName
                        + "/broadcast");
    for (auto const& broadcast : broadcast_ar.value())
    {
        if (!broadcast.isString())
        {
            broadcastValues.emplace_back("NULL");
        }
        broadcastValues.emplace_back(broadcast.getString().value());
    }

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);

    if (!scan_id.has_value())
    {
        msg += " NULL";
    }
    msg += " " + scan_id.value();

    if (!name.has_value())
    {
        msg += "|NULL";
    }
    msg += " " + name.value();

    // Information about an IPv4 address
    msg += "|" + std::string(isIPv6 ? "1" : "0");

    for (size_t i = 0; i < addresValues.size(); i++)
    {
        msg += "|" + addresValues.at(i);
        msg += "|" + netmaskValues.at(i);
        msg += "|" + broadcastValues.at(i);

        auto findEventResponse = wdb.tryQueryAndParseResult(msg);
        if (std::get<0>(findEventResponse) != wazuhdb::QueryResultCodes::OK)
        {
            return false;
        }
    }
    return true;
}

// field: +netInfoAddress/<1_if_IPv6>|<ref_if_IPv6>
base::Expression opBuilderHelperNetInfoAddres(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(rawParameters);
    if (parameters.empty())
    {
        throw std::runtime_error(
            fmt::format("[netInfoAddress] parameter can not be empty"));
    }

    if (parameters.size() != 1)
    {
        throw std::runtime_error(
            fmt::format("[netInfoAddress] should have a single parameter"));
    }
    auto IPversion = parameters.at(0);

    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace =
        fmt::format("[{}] -> Failure, wrong type of parameter reference", name);
    const auto failureTrace1 =
        fmt::format("[{}] -> Failure: [{}] sysNetAddressTableFill throw exception",
                    name,
                    targetField);
    const auto failureTrace2 = fmt::format(
        "[{}] -> Failure: [{}] sysNetAddressTableFill didn't finished succesfully ",
        name,
        targetField);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event> {
            // Getting separator field name
            std::optional<std::string> resolvedIPversion;
            switch (IPversion.m_type)
            {
                case helper::base::Parameter::Type::REFERENCE:
                {
                    resolvedIPversion = event->getString(IPversion.m_value);
                    if (!resolvedIPversion.has_value())
                    {
                        return base::result::makeFailure(event, failureTrace);
                    }
                    break;
                }
                case helper::base::Parameter::Type::VALUE:
                {
                    resolvedIPversion = IPversion.m_value;
                    break;
                }
                default:
                    throw std::runtime_error(
                        fmt::format("[netInfoAddress] invalid separator type"));
            }

            bool resultCode = false;
            try
            {
                // IPv6 if resolvedIPversion equeal 1 , IPv4 otherwise
                //TODO: just limit to those 2 values
                resultCode =
                    sysNetAddresTableFill(event, (std::stoi(resolvedIPversion.value()) == 1));
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            event->setBool(resultCode, targetField);
            if (!resultCode)
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            return base::result::makeSuccess(event, successTrace);
        });
}

} // namespace builder::internals::builders
