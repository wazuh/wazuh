#include "opBuilderKVDB.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>

#include "baseHelper.hpp"
#include "baseTypes.hpp"
#include "syntax.hpp"
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
using namespace helper::base;

// <field>: +kvdb_extract/<DB>/<ref_key>
base::Expression opBuilderKVDBExtract(const std::any& definition)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    helper::base::checkParameterType(parameters[0], Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Extract parameters
    const auto dbName = parameters[0].m_value;
    const auto key = parameters[1];

    // Get DB
    KVDBManager::get().addDb(dbName, false);
    auto kvdb = KVDBManager::get().getDB(dbName);
    if (!kvdb)
    {
        const auto msg {fmt::format("[{}] DB isn't available for usage", dbName)};
        throw std::runtime_error(std::move(msg));
    }

    // Trace messages
    std::string successTrace = fmt::format("[{}] -> Success", name);
    std::string failureTrace1 =
        fmt::format("[{}] -> Failure: field [{}] not found", name, key.m_value);
    std::string failureTrace2 = fmt::format("[{}] -> Failure", name);
    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::move(kvdb), targetField = std::move(targetField)](
            base::Event event)
        {
            // Get DB key
            std::string resolvedKey;
            if (Parameter::Type::REFERENCE == key.m_type)
            {
                auto value = event->getString(key.m_value);
                if (value)
                {
                    resolvedKey = value.value();
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
            }
            else
            {
                resolvedKey = key.m_value;
            }

            // Get value from the DB
            std::string dbValue = kvdb->read(resolvedKey);
            if (dbValue.empty())
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            // Create and add string to event
            else
            {
                event->setString(dbValue, targetField);
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
        auto msg =
            fmt::format("[{}] DB isn't available for usage", parameters[0].m_value);
        throw std::runtime_error(std::move(msg));
    }

    std::string successTrace = fmt::format("[{}] -> Success", name);
    std::string failureTrace = fmt::format("[{}] -> Failure", name);

    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::move(kvdb), targetField = std::move(targetField)](
            base::Event event)
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
