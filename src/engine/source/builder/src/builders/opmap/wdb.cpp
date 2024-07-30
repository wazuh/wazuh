#include "builders/opmap/wdb.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <variant>

#include <base/utils/stringUtils.hpp>

namespace builder::builders::opmap
{

static inline MapOp opBuilderWdbGenericQuery(const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx> buildCtx,
                                             bool doReturnPayload,
                                             const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager)
{
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
        {
            throw std::runtime_error(fmt::format("Expected 'string' parameter with query but got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().str()));
        }

        if (std::static_pointer_cast<Value>(opArgs[0])->value().getString().value().empty())
        {
            throw std::runtime_error("Empty value parameter query");
        }
    }
    else
    {
        const auto& ref = *std::static_pointer_cast<Reference>(opArgs[0]);

        if (buildCtx->validator().hasField(ref.dotPath()))
        {
            auto jType = buildCtx->validator().getJsonType(ref.dotPath());
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(fmt::format(
                    "Expected reference to 'string' parameter with query but got reference '{}' of type '{}'",
                    ref.dotPath(),
                    json::Json::typeToStr(jType)));
            }
        }
    }

    // instantiate WDB
    auto wdb = wdbManager->connection();

    // Tracing
    const auto name = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", name);

    const auto failureTrace = fmt::format("{} -> Failed to perform query: ", name);
    const auto failureTrace1 = [&]()
    {
        if (opArgs[0]->isReference())
        {
            return fmt::format("{} -> Field reference '{}' not found",
                               name,
                               std::static_pointer_cast<Reference>(opArgs[0])->dotPath());
        }
        return std::string {};
    }();
    const auto failureTrace2 = [&]()
    {
        if (opArgs[0]->isReference())
        {
            return fmt::format("{} -> Field reference '{}' is not a string",
                               name,
                               std::static_pointer_cast<Reference>(opArgs[0])->dotPath());
        }
        return std::string {};
    }();
    const auto failureTrace3 = fmt::format("{} -> Empty query", name);

    // Return Op
    return [=, wdb = std::move(wdb), param = opArgs[0], runState = buildCtx->runState()](
               base::ConstEvent event) -> MapResult
    {
        std::string completeQuery {};

        // Check if the value comes from a reference
        if (param->isReference())
        {
            auto refPath = std::static_pointer_cast<Reference>(param)->jsonPath();
            if (!event->exists(refPath))
            {
                RETURN_FAILURE(runState, json::Json {}, failureTrace1);
            }

            auto resolvedRValue = event->getString(refPath);
            if (!resolvedRValue.has_value())
            {
                RETURN_FAILURE(runState, json::Json {}, failureTrace2);
            }

            completeQuery = resolvedRValue.value();
            if (completeQuery.empty())
            {
                RETURN_FAILURE(runState, json::Json {}, failureTrace3);
            }
        }
        else // Direct value
        {
            completeQuery = std::static_pointer_cast<Value>(param)->value().getString().value();
        }

        // Execute complete query in DB
        auto returnTuple = wdb->tryQueryAndParseResult(completeQuery);

        // Handle response
        auto resultCode = std::get<0>(returnTuple);

        // Store value on json
        if (doReturnPayload)
        {
            if (wazuhdb::QueryResultCodes::OK == resultCode)
            {
                json::Json result;
                const auto& queryResponse = std::get<1>(returnTuple);
                if (queryResponse.has_value() && !queryResponse.value().empty())
                {
                    result.setString(queryResponse.value());
                }
                else
                {
                    result.setString("");
                }
                RETURN_SUCCESS(runState, result, successTrace);
            }
            else
            {
                auto retCode = wazuhdb::qrcToStr(resultCode);

                RETURN_FAILURE(runState, json::Json {}, failureTrace + fmt::format("Result code is '{}'", retCode));
            }
        }
        else
        {
            json::Json result;
            auto ok = wazuhdb::QueryResultCodes::OK == resultCode;
            result.setBool(ok);
            if (!ok)
            {
                RETURN_FAILURE(
                    runState, result, failureTrace + fmt::format("Result code is '{}'", wazuhdb::qrcToStr(resultCode)));
            }
            RETURN_SUCCESS(runState, result, successTrace);
        }
    };
}

// <wdb_result>: +wdb_update/<quey>|$<quey>
MapBuilder getWdbUpdateBuilder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager)
{
    return [wdbManager](const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx> buildCtx) -> MapOp
    {
        return opBuilderWdbGenericQuery(opArgs, buildCtx, false, wdbManager);
    };
}

// <wdb_result>: +wdb_query/<quey>|$<quey>
MapBuilder getWdbQueryBuilder(const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager)
{
    return [wdbManager](const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx> buildCtx) -> MapOp
    {
        return opBuilderWdbGenericQuery(opArgs, buildCtx, true, wdbManager);
    };
}

} // namespace builder::builders::opmap
