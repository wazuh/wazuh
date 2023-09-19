#include "windowsHelper.hpp"

#include <regex>

#include <baseHelper.hpp>

using namespace helper::base;

namespace
{
const std::string ACC_SID_DESC_KEY = "accountSIDDescription";
const std::string DOM_SPC_SID_KEY = "domainSpecificSID";

/**
 * @brief Parse the list of SID, the list must be in the format:
 *
 * '%{sid1} %{sid2} %{sid3} ... ' // TODO: Check the format
 *
 * Ths function will return a vector with the sids in the same order as the input
 * or return an empty vector if the input is not valid
 * @param listSrt String with the list of sids
 * @return std::vector<std::string>
 */
std::vector<std::string> parserListSID(const std::string& listSrt)
{

    std::vector<std::string> result = base::utils::string::split(listSrt, ' '); // TODO Check format

    for (auto& sid : result)
    {
        if (sid.size() > 3)
        {
            // Remove header '%{' and tail '}'
            sid = sid.substr(2, sid.size() - 3);
        }
    }

    return result;
}

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

        if (schema->hasField(sidListRef) && schema->getType(sidListRef) != json::Json::Type::String)
        {
            throw std::runtime_error(fmt::format("The reference '{}' is not an string.", sidListRef));
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
        std::map<std::string, std::string> asdMap;
        {
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

            for (auto it = jObjAsd.value().begin(); it != jObjAsd.value().end(); ++it)
            {
                auto key = std::get<0>(*it);
                auto jValue = std::get<1>(*it).getString();
                if (!jValue)
                {
                    throw std::runtime_error(fmt::format(
                        "Error parsing the accountSIDDescription from DB: Expected string for key '{}'", key));
                }

                asdMap.emplace(key, jValue.value());
            }
            if (asdMap.empty())
            {
                throw std::runtime_error("Error parsing the accountSIDDescription from DB: Empty object");
            }
        }

        // Domain Specific SID
        std::map<std::string, std::string> dssMap;
        {
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
            if (dssMap.empty())
            {
                throw std::runtime_error("Error parsing the DomainSpecificSID from DB: Empty object");
            }
        }
        // Trace messages
        const std::string successTrace {fmt::format("[{}] -> Success", name)};
        const std::string referenceNotFoundTrace {
            fmt::format("[{}] -> Failure: Reference to array {} not found", name, sidListRef)};
        const std::string failureRefErrorParsing {
            fmt::format("[{}] -> Failure: Error parsing reference '{}' as sidList", name, sidListRef)};
        // const std::string failureItemNotString {
        //     fmt::format("[{}] -> Failure: Item in array {} is not a string", name, sidListRef)};
        std::regex endRegex("\\d{1,5}$");
        // Return Term
        return base::Term<base::EngineOp>::create(
            name,
            [=](const base::Event& event) -> base::result::Result<base::Event>
            {
                // Get reference
                auto optSidList = event->getString(sidListRef);
                if (!optSidList)
                {
                    return base::result::makeFailure<base::Event>(event, referenceNotFoundTrace);
                }
                auto sidList = parserListSID(optSidList.value());
                if (sidList.empty())
                {
                    return base::result::makeFailure<base::Event>(event, failureRefErrorParsing);
                }

                // Iterate over the sids and get the mappings
                // Parse de sid list
                for (const auto& sid : sidList)
                {

                    auto asdIt = asdMap.find(sid);
                    bool hasDesc = false;
                    // Check if is a account sid
                    if (asdIt != asdMap.end())
                    {
                        event->appendString(asdIt->second, targetField);
                        hasDesc = true;
                    }
                    else if (base::utils::string::startsWith(sid, "S-1-5-21")) // If not found and check if is a domain
                    {
                        // Che if sid end with a number between 1 and 5 digits
                        std::smatch matches;

                        if (std::regex_search(sid, matches, endRegex)) // If the regex matches
                        {
                            // Extraxt string from the regex match
                            auto match = matches[0].str();
                            auto dssIt = dssMap.find(match);
                            if (dssIt != dssMap.end())
                            {
                                event->appendString(dssIt->second, targetField);
                                hasDesc = true;
                            }
                        }
                    }

                    if (!hasDesc)
                    {
                        event->appendString(sid, targetField);
                    }
                }

                return base::result::makeSuccess(event, successTrace);
            });
    };
}
} // namespace builder::internals::builders
