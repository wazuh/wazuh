#include "builders/opmap/wdb.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <variant>

#include <utils/stringUtils.hpp>

namespace builder::builders::opmap
{

static inline MapOp opBuilderWdbGenericQuery(const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx> buildCtx,
                                             bool doReturnPayload,
                                             const std::shared_ptr<wazuhdb::IWDBManager>& wdbManager)
{
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error("WDB query must be a string or a reference");
    }

    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string successTrace {fmt::format("{} -> Success", name)};

    const std::string failureTrace {fmt::format("{} -> Failure: ", name)};
    const std::string failureTrace1 {fmt::format("{} -> Failure: parameter reference not found", name)};
    const std::string failureTrace2 {fmt::format("{} -> Failure: parameter reference contains empty query", name)};

    // instantiate WDB
    auto wdb = wdbManager->connection();

    // Return Op
    return [=, wdb = std::move(wdb), param = opArgs[0], runState = buildCtx->runState()](
               base::ConstEvent event) -> MapResult
    {
        std::string completeQuery {};

        // Check if the value comes from a reference
        if (param->isReference())
        {
            const auto& path = std::static_pointer_cast<Reference>(param)->jsonPath();
            auto resolvedRValue = event->getString(path);

            if (resolvedRValue.has_value())
            {
                completeQuery = resolvedRValue.value();
                if (completeQuery.empty())
                {
                    RETURN_FAILURE(runState, json::Json {}, failureTrace2);
                }
            }
            else
            {
                RETURN_FAILURE(runState, json::Json {}, failureTrace1);
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
            result.setBool(wazuhdb::QueryResultCodes::OK == resultCode);
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
