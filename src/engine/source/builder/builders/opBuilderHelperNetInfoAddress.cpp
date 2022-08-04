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

#include "protocolHandler.hpp"
#include <baseHelper.hpp>
#include <kvdb/kvdbManager.hpp>
#include <wdb/wdb.hpp>

namespace
{

// TODO: remove pre release or leave it just for testing
constexpr std::string_view STREAM_SOCK_PATH = "/tmp/testStream.socket";

enum class Name
{
    ID,
    IFACE,
    IFACE_NAME,
    ADDRESS,
    NETMASK,
    BROADCAST
};

constexpr std::string_view getPath(Name field)
{
    switch (field)
    {
        case Name::ID: return "/ID";
        case Name::IFACE: return "/iface";
        case Name::IFACE_NAME: return "/iface/name";
        case Name::ADDRESS: return "/address";
        case Name::NETMASK: return "/netmask";
        case Name::BROADCAST: return "/broadcast";
        default: return "";
    }
}

// when isIPv6 == true the third field will be set to 0, otherwise 1 for IPv4
// agent <agent_id> netaddr save <scan_ID>|<name>|isIPv6=false|add[i]|netm[i]|broad[i]
// agent 0001 netaddr save 1234|name|0|add0|netm0|broad0
std::optional<bool> sysNetAddresTableFill(base::Event event, bool isIPv6)
{
    // this fields presence is checked before in the yml
    const auto& agent_id = event->getString(engineserver::EVENT_AGENT_ID);
    const auto& scan_id =
        event->getString(std::string(engineserver::EVENT_LOG) + getPath(Name::ID).data());
    const auto& name = event->getString(std::string(engineserver::EVENT_LOG)
                                        + getPath(Name::IFACE_NAME).data());

    std::string middleFieldName = isIPv6 ? "IPv6" : "IPv4";
    std::string msg {"agent " + agent_id.value() + " netaddr save"};

    // Cheking if AddresArray exists
    std::optional<std::vector<json::Json>> address_ar;
    try
    {
        address_ar = event->getArray(std::string(engineserver::EVENT_LOG)
                                     + getPath(Name::IFACE).data() + "/" + middleFieldName
                                     + getPath(Name::ADDRESS).data());
    }
    catch (const std::exception& e)
    {
        return false;
    }

    if(!address_ar.has_value())
    {
        return false;
    }

    auto wdb = wazuhdb::WazuhDB(STREAM_SOCK_PATH);

    if (!scan_id.has_value())
    {
        msg += " NULL";
    }
    else
    {
        msg += " " + scan_id.value();
    }
    if (!name.has_value())
    {
        msg += "|NULL";
    }
    else
    {
        msg += "|" + name.value();
    }

    // Information about an IPv4(0) or IPv6(1) address
    msg += "|" + std::string(isIPv6 ? "1" : "0");

    // TODO: can we avoid using rapidjson directly here?
    rapidjson::SizeType i = 0;
    for (auto const& address : address_ar.value())
    {
        std::string addresesMessage {};
        if (address.isString())
        {
            addresesMessage = msg + "|" + address.getString().value();
        }
        else
        {
            return false;
        }

        //TODO: is there a fastest way of checking each json array items?
        // if netmask items dosen't exists or has a wrong type then append NULL
        if (!event->exists(std::string(engineserver::EVENT_LOG)
                           + getPath(Name::IFACE).data() + "/" + middleFieldName
                           + getPath(Name::NETMASK).data() + "/" + std::to_string(i)))
        {
            addresesMessage += "|NULL";
        }
        else
        {
            try
            {
                const auto& netmasks_ar = event->getArray(
                    std::string(engineserver::EVENT_LOG) + getPath(Name::IFACE).data()
                    + "/" + middleFieldName + getPath(Name::NETMASK).data());
                if (!netmasks_ar.value()[i].isString())
                {
                    addresesMessage += "|NULL";
                }
                else
                {
                    addresesMessage += "|" + netmasks_ar.value()[i].getString().value();
                }
            }
            catch (const std::exception& e)
            {
                addresesMessage += "|NULL";
            }
        }

        // if netmask items dosen't exists or has a wrong type then append NULL
        if (!event->exists(std::string(engineserver::EVENT_LOG)
                           + +getPath(Name::IFACE).data() + "/" + middleFieldName
                           + getPath(Name::BROADCAST).data() + "/" + std::to_string(i)))
        {
            addresesMessage += "|NULL";
        }
        else
        {
            try
            {
                const auto& broadcast_ar = event->getArray(
                    std::string(engineserver::EVENT_LOG) + getPath(Name::IFACE).data()
                    + "/" + middleFieldName + getPath(Name::BROADCAST).data());
                if (!broadcast_ar.value()[i].isString())
                {
                    addresesMessage += "|NULL";
                }
                else
                {
                    addresesMessage += "|" + broadcast_ar.value()[i].getString().value();
                }
            }
            catch (const std::exception& e)
            {
                addresesMessage += "|NULL";
            }
        }

        auto findEventResponse = wdb.tryQueryAndParseResult(addresesMessage);
        if (std::get<0>(findEventResponse) != wazuhdb::QueryResultCodes::OK)
        {
            return false;
        }

        i++;
    }

    return true;
}

base::Expression opBuilderHelperNetInfoAddress(const std::any& definition, bool isIPv6)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(rawParameters);
    if (!parameters.empty())
    {
        throw std::runtime_error(fmt::format("[{}] parameter should be empty", name));
    }

    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Tracing
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace =
        fmt::format("[{}] -> Failure, wrong type of parameter reference", name);
    const auto failureTrace1 = fmt::format(
        "[{}] -> Failure: [{}] sysNetAddressTableFill error", name, targetField);
    const auto failureTrace2 = fmt::format(
        "[{}] -> Failure: [{}] couldn't assign result value", name, targetField);

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](
            base::Event event) -> base::result::Result<base::Event> {
            auto resultExecution = sysNetAddresTableFill(event, isIPv6);

            if (!resultExecution.has_value() || !resultExecution.value())
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            try
            {
                event->setBool(resultExecution.value(), targetField);
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(event, failureTrace2);
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

} // namespace

namespace builder::internals::builders
{

base::Expression opBuilderHelperSaveNetInfoIPv4(const std::any& definition)
{
    return opBuilderHelperNetInfoAddress(definition, false);
}

base::Expression opBuilderHelperSaveNetInfoIPv6(const std::any& definition)
{
    return opBuilderHelperNetInfoAddress(definition, true);
}

} // namespace builder::internals::builders
