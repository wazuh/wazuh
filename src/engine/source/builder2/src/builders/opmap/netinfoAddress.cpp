#include "builders/optransform/netinfoAddress.hpp"

#include <optional>
#include <string>
#include <variant>

namespace
{
using namespace builder::builders;

enum class Name
{
    ADDRESS,
    NETMASK,
    BROADCAST
};

constexpr std::string_view getPath(Name field)
{
    switch (field)
    {
        case Name::ADDRESS: return "/address";
        case Name::NETMASK: return "/netmask";
        case Name::BROADCAST: return "/broadcast";
        default: return "";
    }
}

// when isIPv6 == true the third field will be set to 0, otherwise 1 for IPv4
// agent <agent_id> netaddr save <scan_ID>|<name>|isIPv6=false|add[i]|netm[i]|broad[i]
// agent 0001 netaddr save 1234|name|0|add0|netm0|broad0
bool sysNetAddresTableFill(base::Event event,
                           const std::string& agentId,
                           const std::string& scan_id,
                           const std::string& name,
                           const std::string& ipObjectPath,
                           const std::shared_ptr<wazuhdb::IWDBHandler>& wdb,
                           const bool isIPv6)
{
    // Cheking if AddresArray exists
    const auto address_ar = event->getArray(ipObjectPath + getPath(Name::ADDRESS).data());

    if (!address_ar.has_value())
    {
        return false;
    }

    const auto netmaskI =
        event->getArray(ipObjectPath + getPath(Name::NETMASK).data()).value_or(std::vector<json::Json>());

    const auto broadcastI =
        event->getArray(ipObjectPath + getPath(Name::BROADCAST).data()).value_or(std::vector<json::Json>());

    for (size_t i = 0; i != address_ar.value().size(); ++i)
    {
        std::optional<std::string> addressIValue {};
        std::optional<std::string> netmaskIValue {"NULL"};
        std::optional<std::string> broadcastIValue {"NULL"};

        try
        {
            addressIValue = address_ar.value().at(i).getString();
        }
        catch (const std::out_of_range& e)
        {
            return false;
        }

        try
        {
            netmaskIValue = netmaskI.at(i).getString();
        }
        catch (const std::out_of_range& e)
        {
            netmaskIValue = "NULL";
        }

        try
        {
            broadcastIValue = broadcastI.at(i).getString().value_or("NULL");
        }
        catch (const std::out_of_range& e)
        {
            broadcastIValue = "NULL";
        }

        // We should still check if it's empty because value_or only checks nullopt
        const std::string msg = fmt::format("agent {} netaddr save {}|{}|{}|{}|{}|{}",
                                            agentId,
                                            scan_id,
                                            name,
                                            isIPv6 ? "1" : "0",
                                            addressIValue.value(),
                                            netmaskIValue.value(),
                                            broadcastIValue.value());

        const auto findEventResponse = wdb->tryQueryAndParseResult(msg);
        if (std::get<0>(findEventResponse) != wazuhdb::QueryResultCodes::OK)
        {
            return false;
        }
    }

    return true;
}

TransformBuilder netInfoAddressBuilder(const Reference& targetField,
                                       const std::vector<OpArgs>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx,
                                       const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager,
                                       bool isIPv6)
{
    utils::assertSize(opArgs, 4);
    utils::assertRef(opArgs);

    // Get params
    const auto& agentId = *std::static_pointer_cast<Reference>(opArgs[0]);
    const auto& scan_id = *std::static_pointer_cast<Reference>(opArgs[1]);
    const auto& name = *std::static_pointer_cast<Reference>(opArgs[2]);
    const auto& ipObject = *std::static_pointer_cast<Reference>(opArgs[3]);

    const auto traceName = buildCtx->context().opName;

    // Tracing
    const auto successTrace = fmt::format("{} -> Success", traceName);
    const auto failureTrace =
        fmt::format("{} -> Failure: Parameter doesn't exist or it has the wrong type: ", traceName);
    const auto failureTrace1 =
        fmt::format("{} -> Failure: {} sysNetAddressTableFill error", traceName, targetField.dotPath());
    const auto failureTrace2 =
        fmt::format("{} -> Failure: {} couldn't assign result value", traceName, targetField.dotPath());

    // EventPaths and mappedPaths can be set in buildtime
    auto wdb = wdbManager->connection();

    // Return Op
    return [=,
            targetField = targetField.jsonPath(),
            agent_id_path = agentId.jsonPath(),
            scan_id_path = scan_id.jsonPath(),
            name_path = name.jsonPath(),
            ipObject_path = ipObject.jsonPath(),
            runState = buildCtx->runState(),
            wdb = std::move(wdb)](base::Event event) -> TransformResult
    {
        // Checking values and saving them
        if (!event->exists(agent_id_path) || !event->isString(agent_id_path))
        {
            RETURN_FAILURE(runState, event, failureTrace + agent_id_path);
        }
        const auto agent_id {event->getString(agent_id_path).value_or("NULL")};

        if (!event->exists(scan_id_path) || !event->isInt(scan_id_path))
        {
            RETURN_FAILURE(runState, event, failureTrace + scan_id_path);
        }
        const auto resultValue {event->getInt(scan_id_path)};
        const auto scan_id {resultValue.has_value() ? std::to_string(resultValue.value()) : "NULL"};

        if (!event->exists(name_path) || !event->isString(name_path))
        {
            RETURN_FAILURE(runState, event, failureTrace + name_path);
        }
        const auto name = event->getString(name_path).value_or("NULL");

        // Cheking base object existence
        if (!event->exists(ipObject_path))
        {
            RETURN_FAILURE(runState, event, failureTrace + ipObject_path);
        }

        const auto resultExecution = sysNetAddresTableFill(event, agent_id, scan_id, name, ipObject_path, wdb, isIPv6);

        if (!resultExecution)
        {
            RETURN_FAILURE(runState, event, failureTrace1);
        }

        try
        {
            event->setBool(resultExecution, targetField);
        }
        catch (const std::exception& e)
        {
            RETURN_FAILURE(runState, event, failureTrace2);
        }

        RETURN_SUCCESS(runState, event, successTrace);
    };
}

} // namespace

namespace builder::builders::optransform
{

TransformBuilder getSaveNetInfoIPv4Builder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager)
{
    return [wdbManager](const Reference& targetField,
                        const std::vector<OpArgs>& opArgs,
                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return netInfoAddressBuilder(targetField, opArgs, buildCtx, wdbManager, false);
    };
}

TransformBuilder getSaveNetInfoIPv6Builder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager)
{
    return [wdbManager](const Reference& targetField,
                        const std::vector<OpArgs>& opArgs,
                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return netInfoAddressBuilder(targetField, opArgs, buildCtx, wdbManager, true);
    };
}

} // namespace builder::builders::optransform
