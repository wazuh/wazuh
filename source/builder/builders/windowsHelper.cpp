#include "windowsHelper.hpp"

#include <baseHelper.hpp>

using namespace helper::base;

namespace
{
const std::string ACC_SID_DESC_KEY = "accountSIDDescription";
const std::string DOM_SPC_SID_KEY = "DomainSpecificSID";
} // namespace

namespace builder::internals::builders
{
HelperBuilder getWindowsSidListDescHelperBuilder(std::shared_ptr<kvdbManager::IKVDBManager> kvdb,
                                                 const std::string& kvdbScopeName,
                                                 std::shared_ptr<schemf::ISchema> schema)
{
    // TODO: add shared_ptr validation when tests are updated

    return [=](const std::string& targetField,
               const std::string& rawName,
               const std::vector<std::string>& rawParameters,
               std::shared_ptr<defs::IDefinitions> definitions) -> base::Expression
    {
        // Process parameters
        auto parameters = processParameters(rawName, rawParameters, definitions);

        // Format name
        const auto name = formatHelperName(targetField, rawName, parameters);

        // Check parameters
        checkParametersSize(rawName, parameters, 2);
        checkParameterType(rawName, parameters[0], Parameter::Type::VALUE);
        checkParameterType(rawName, parameters[1], Parameter::Type::REFERENCE);

        auto kvdbName = parameters[0].m_value;
        auto sidListRef = parameters[1].m_value;

        // TODO: change to string and do the transformation to a list
        if (schema->hasField(sidListRef) && schema->getType(sidListRef) != json::Json::Type::Array)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an array.", sidListRef));
        }
        if (schema->hasField(targetField) && schema->getType(targetField) != json::Json::Type::Array)
        {
            throw std::runtime_error(fmt::format("The target field '{}' is not an array.", targetField));
        }

        // Get the kvdb handler
        auto kbdbRes = kvdb->getKVDBHandler(kvdbName, kvdbScopeName);
        if (base::isError(kbdbRes))
        {
            throw std::runtime_error(
                fmt::format("Error getting the kvdb handler: {}", base::getError(kbdbRes).message));
        }

        auto kvdbHandler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(kbdbRes);

        // Get the lists
        // Account SID Description
        auto asd = kvdbHandler->get(ACC_SID_DESC_KEY);
        if (base::isError(asd))
        {
            throw std::runtime_error(
                fmt::format("Error getting the accountSIDDescription from DB: {}", base::getError(asd).message));
        }
        auto jAsd = json::Json(base::getResponse<std::string>(asd).c_str());
        auto jObjAsd = jAsd.getObject();
        if (!jObjAsd)
        {
            throw std::runtime_error("Error parsing the accountSIDDescription from DB: Expected object");
        }
        std::map<std::string, std::string> asdMap;
        for (auto it = jObjAsd.value().begin(); it != jObjAsd.value().end(); ++it)
        {
            auto key = std::get<0>(*it);
            auto jValue = std::get<1>(*it).getString();
            if (!jValue)
            {
                throw std::runtime_error(
                    fmt::format("Error parsing the accountSIDDescription from DB: Expected string for key '{}'", key));
            }

            asdMap.emplace(key, jValue.value());
        }

        // Domain Specific SID
        auto dss = kvdbHandler->get(DOM_SPC_SID_KEY);
        if (base::isError(dss))
        {
            throw std::runtime_error(
                fmt::format("Error getting the DomainSpecificSID from DB: {}", base::getError(dss).message));
        }
        auto jDss = json::Json(base::getResponse<std::string>(dss).c_str());
        auto jObjDss = jDss.getObject();
        if (!jObjDss)
        {
            throw std::runtime_error("Error parsing the DomainSpecificSID from DB: Expected object");
        }
        std::map<std::string, std::string> dssMap;
        for (auto it = jObjDss.value().begin(); it != jObjDss.value().end(); ++it)
        {
            auto key = std::get<0>(*it);
            auto jValue = std::get<1>(*it).getString();
            if (!jValue)
            {
                throw std::runtime_error(
                    fmt::format("Error parsing the DomainSpecificSID from DB: Expected string for key '{}'", key));
            }

            dssMap.emplace(key, jValue.value());
        }

        // Trace messages
        const std::string successTrace {fmt::format("[{}] -> Success", name)};
        const std::string referenceNotFoundTrace {
            fmt::format("[{}] -> Failure: Reference to array {} not found", name, sidListRef)};
        const std::string failureEmptyRef {fmt::format("[{}] -> Failure: Empty reference {}", name, sidListRef)};
        const std::string failureItemNotString {
            fmt::format("[{}] -> Failure: Item in array {} is not a string", name, sidListRef)};

        // Return Term
        return base::Term<base::EngineOp>::create(
            name,
            [=](base::Event event) -> base::result::Result<base::Event>
            {
                // Get reference
                auto sidList = event->getArray(sidListRef);
                if (!sidList)
                {
                    return base::result::makeFailure<base::Event>(event, referenceNotFoundTrace);
                }
                if (sidList.value().empty())
                {
                    return base::result::makeFailure<base::Event>(event, failureEmptyRef);
                }

                // Iterate over the sids and get the mappings
                for (const auto& sid : sidList.value())
                {
                    auto sidStr = sid.getString();
                    if (!sidStr)
                    {
                        return base::result::makeFailure<base::Event>(event, failureItemNotString);
                    }

                    auto asdIt = asdMap.find(sidStr.value());
                    if (asdIt == asdMap.end())
                    {
                        if (base::utils::string::startsWith(sidStr.value(), "S-1-5-21"))
                        {
                            // TODO: implement regex for [0-9]{1,5}$

                            if (true) // If the regex matches
                            {
                                // TODO map the dssMap value
                            }
                            else
                            {
                                event->appendString(targetField, sidStr.value());
                            }
                        }
                        else
                        {
                            event->appendString(targetField, sidStr.value());
                        }
                    }
                    else
                    {
                        event->appendString(targetField, asdIt->second);
                    }
                }

                return base::result::makeSuccess(event, successTrace);
            });
    };
}
} // namespace builder::internals::builders
