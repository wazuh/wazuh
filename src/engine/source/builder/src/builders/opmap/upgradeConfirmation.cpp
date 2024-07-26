#include "builders/opmap/upgradeConfirmation.hpp"

#include <optional>
#include <string>

namespace builder::builders::opmap
{

// field: +send_upgrade_confirmation/ar_message
MapBuilder getUpgradeConfirmationBUilder(const std::shared_ptr<sockiface::ISockFactory>& sockFactory)
{
    return [sockFactory](const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        utils::assertSize(opArgs, 1);
        utils::assertRef(opArgs);

        const auto name = buildCtx->context().opName;

        const auto& refParam = *std::static_pointer_cast<const Reference>(opArgs[0]);

        // Socket instance
        auto socketUC = sockFactory->getHandler(sockiface::ISockHandler::Protocol::STREAM, WM_UPGRADE_SOCK);

        // Tracing
        const auto successTrace = fmt::format("{} -> Success", name);

        const auto failureTrace1 = fmt::format("{} -> Message reference '{}' not found", name, refParam.dotPath());
        const auto failureTrace2 = fmt::format("{} -> The message is empty", name);
        const auto failureTrace3 = fmt::format("{} -> Upgrade confirmation message could not be sent", name);
        const auto failureTrace4 = fmt::format("{} -> Error trying to send upgrade confirmation message: ", name);
        const auto failureTrace5 = fmt::format("{} -> Message should be a JSON object: ", name);

        // Return Op
        return [=, ref = refParam.jsonPath(), runState = buildCtx->runState()](base::ConstEvent event) -> MapResult
        {
            std::string query {};
            bool messageSent {false};
            json::Json result;
            result.setBool(false);

            std::string resolvedRValue;

            if (!event->isObject(ref))
            {
                RETURN_FAILURE(runState, result, failureTrace5);
            }
            query = event->str(ref).value();

            // Verify that its a non-empty object
            if (query.empty() || "{}" == query)
            {
                RETURN_FAILURE(runState, result, failureTrace2);
            }
            else
            {
                try
                {
                    if (sockiface::ISockHandler::SendRetval::SUCCESS == socketUC->sendMsg(query))
                    {
                        result.setBool(true);
                        RETURN_SUCCESS(runState, result, successTrace);
                    }
                    else
                    {
                        RETURN_FAILURE(runState, result, failureTrace3);
                    }
                }
                catch (const std::exception& e)
                {
                    RETURN_FAILURE(runState, result, failureTrace4 + e.what());
                }
            }
        };
    };
}

} // namespace builder::builders::opmap
