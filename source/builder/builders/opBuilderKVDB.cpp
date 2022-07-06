#include "opBuilderKVDB.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>

#include "baseTypes.hpp"
#include "baseHelper.hpp"
#include "syntax.hpp"
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
using namespace helper::base;

// <field>: +kvdb_extract/<DB>/<ref_key>
base::Expression opBuilderKVDBExtract(const std::any& definition)
{
    std::string target;
    std::vector<std::string> parametersArr;

    try
    {
        auto tuple =
            std::any_cast<std::tuple<std::string, std::vector<std::string>>>(definition);
        target = json::Json::formatJsonPath(std::get<0>(tuple));
        parametersArr = std::get<1>(tuple);
    }
    catch (std::exception& e)
    {
        std::throw_with_nested(std::runtime_error(
            fmt::format("[builder::opBuilderKVDBExtract(<field, parameters>)] Received "
                        "unexpected argument type")));
    }
    if (parametersArr.size() != 3) // TODO: We are using default column only now
    {
        throw std::runtime_error(
            fmt::format("[builder::opBuilderKVDBExtract(<field, parameters>)] "
                        "Expected 3 arguments, but got [{}]",
                        parametersArr.size()));
    }

    // Get DB
    auto kvdb = KVDBManager::get().getDB(parametersArr[1]);
    if (!kvdb)
    {
        const auto msg {
            fmt::format("[{}] DB isn't available for usage", parametersArr[1])};
        throw std::runtime_error(std::move(msg));
    }

    // Get reference key
    std::string& key = parametersArr[2];
    bool isReference = false;
    if (REFERENCE_ANCHOR == key[0])
    {
        key = json::Json::formatJsonPath(key.substr(1));
        isReference = true;
    }

    // Trace messages
    auto name = fmt::format("{}: kvdb", target);
    std::string successTrace = fmt::format("[{}] -> Success", name);
    std::string failureTrace = fmt::format("[{}] -> Failure", name);

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::move(kvdb)](base::Event event)
        {
            // Get DB key
            std::string dbKey;
            if (isReference)
            {
                try
                {
                    auto value = event->getString(key);
                    dbKey = value.value();
                }
                catch (std::exception& ex)
                {
                    return base::result::makeFailure(std::move(event), failureTrace);
                }
            }
            else
            {
                dbKey = key;
            }

            // Get value from the DB
            std::string dbValue = kvdb->read(dbKey);
            if (dbValue.empty())
            {
                return base::result::makeFailure(std::move(event), failureTrace);
            }

            // Create and add string to event
            try
            {
                json::Json val;
                val.setString(dbValue.c_str());
                // TODO: add proper set once json supports
                event->set(target, val);
            }
            catch (std::exception& ex)
            {
                return base::result::makeFailure(event, failureTrace);
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

base::Expression opBuilderKVDBExistanceCheck(const std::any& definition, bool checkExist)
{

    auto [targetField, name, arguments] = extractDefinition(definition);
    auto parameters = processParameters(arguments);
    checkParametersSize(parameters, 1);
    checkParameterType(parameters[0], Parameter::Type::VALUE);
    name = formatHelperFilterName(targetField, name, parameters);

    auto kvdb = KVDBManager::get().getDB(parameters[0].m_value);
    if (!kvdb)
    {
        auto msg = fmt::format("[{}] DB isn't available for usage", parameters[0].m_value);
        throw std::runtime_error(std::move(msg));
    }

    std::string successTrace = fmt::format("[{}] -> Success", name);
    std::string failureTrace = fmt::format("[{}] -> Failure", name);

    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::move(kvdb), targetField = std::move(targetField)](base::Event event)
        {
            bool found = false;
            try // TODO We are only using try for JSON::get. Is correct to
                // wrap everything?
            {
                auto value = event->getString(targetField);
                if (value.has_value())
                {
                    if (kvdb->hasKey(value.value()))
                    {
                        found = true;
                    }
                }
            }
            catch (std::exception& ex)
            {
                return base::result::makeFailure(event, failureTrace);
            }

            bool truth = checkExist ? found : !found;
            if (truth)
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace);
            }
        });
}

// <field>: +kvdb_match/<DB>
base::Expression opBuilderKVDBMatch(const std::any& definition)
{
    return opBuilderKVDBExistanceCheck(definition, true);
}

// <field>: +kvdb_not_match/<DB>
base::Expression opBuilderKVDBNotMatch(const std::any& definition)
{
    return opBuilderKVDBExistanceCheck(definition, false);
}
} // namespace builder::internals::builders
