#include "builders/opmap/activeResponse.hpp"

// TODO: move the wazuhRequest to a common path such as "utils"
#include <base/utils/wazuhProtocol/wazuhRequest.hpp>

namespace builder::builders
{
using SendRetval = sockiface::ISockHandler::SendRetval;
using Protocol = sockiface::ISockHandler::Protocol;

namespace ar
{
// TODO: move all the sockets to a shared utils directory
// TODO: when the api is merged these values can be obtained from "base".
constexpr const char* AR_QUEUE_PATH {"/var/ossec/queue/alerts/ar"};

// TODO: unify these parameters with the api ones
constexpr const char* AGENT_ID_PATH {"/agent/id"};
constexpr const char* MODULE_NAME {"wazuh-engine"};
constexpr const char* ORIGIN_NAME {"node01"};
constexpr const char* SUPPORTED_VERSION {"1"};

constexpr const char* AR_JSON_PARAMS {R"({"extra_args":[], "alert": {} })"};

constexpr auto TRACE_SUCCESS = "[{}] -> Success";

constexpr auto TRACE_REFERENCE_STR_NOT_FOUND = "[{}] -> Failure: field '{}' reference not found or is not a string";
constexpr auto TRACE_REFERENCE_INT_NOT_FOUND = "[{}] -> Failure: field '{}' reference not found or is not an integer";
constexpr auto TRACE_REFERENCE_ARR_NOT_FOUND = "[{}] -> Failure: Parameter '{}' reference not found or is not an array";
constexpr auto TRACE_REFERENCE_TYPE_IS_NOT_STR = "[{}] -> Failure: Reference '{}' type is not string";

} // namespace ar

// ar_message: +active_response_create/<command-name>/<location>/<timeout>/<extra-args>
MapOp CreateARBuilder(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{

    const auto& name = buildCtx->context().opName;

    // Validate parameters
    utils::assertSize(opArgs, 2, 4);

    // command-name (only string values are allowed)
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }
    const auto commandName = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();

    // location
    if (opArgs[1]->isValue() && !std::static_pointer_cast<Value>(opArgs[1])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().typeName()));
    }
    auto getLocationFn = [locationSrc = opArgs[1], name](base::ConstEvent event) -> std::string
    {
        if (locationSrc->isReference())
        {
            auto location = event->getString(std::static_pointer_cast<Reference>(locationSrc)->jsonPath());
            if (!location)
            {
                throw std::runtime_error(fmt::format(ar::TRACE_REFERENCE_STR_NOT_FOUND,
                                                     name,
                                                     std::static_pointer_cast<Reference>(locationSrc)->jsonPath()));
            }
            return std::move(location.value());
        }
        return std::static_pointer_cast<Value>(locationSrc)->value().getString().value();
    };

    // timeout
    std::function<std::int64_t(base::ConstEvent)> getTimeoutFn = [](base::ConstEvent) -> std::int64_t
    {
        return 0;
    };
    if (opArgs.size() > 2)
    {
        if (opArgs[2]->isValue() && !std::static_pointer_cast<Value>(opArgs[2])->value().isInt()
            && !std::static_pointer_cast<Value>(opArgs[2])->value().isInt64())
        {
            throw std::runtime_error(fmt::format("Expected 'int' parameter but got type '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[2])->value().typeName()));
        }

        getTimeoutFn = [timeoutSrc = opArgs[2], name](base::ConstEvent event) -> std::int64_t
        {
            if (timeoutSrc->isReference())
            {
                auto timeout = event->getIntAsInt64(std::static_pointer_cast<Reference>(timeoutSrc)->jsonPath());
                if (!timeout)
                {
                    throw std::runtime_error(fmt::format(ar::TRACE_REFERENCE_INT_NOT_FOUND,
                                                         name,
                                                         std::static_pointer_cast<Reference>(timeoutSrc)->jsonPath()));
                }
                return timeout.value();
            }
            return std::static_pointer_cast<Value>(timeoutSrc)->value().getIntAsInt64().value();
        };
    }

    // extra-args (If exist should be an array of strings)
    std::function<std::vector<std::string>(base::ConstEvent)> getExtraArgsFn =
        [](base::ConstEvent) -> std::vector<std::string>
    {
        return {};
    };
    if (opArgs.size() > 3)
    {
        if (opArgs[3]->isValue() && !std::static_pointer_cast<Value>(opArgs[3])->value().isArray())
        {
            throw std::runtime_error(fmt::format("Expected 'array' parameter but got type '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[3])->value().typeName()));
        }
        getExtraArgsFn = [extraSrc = opArgs[3], name](base::ConstEvent event) -> std::vector<std::string>
        {
            std::optional<std::vector<json::Json>> extraArgs = std::nullopt;
            std::vector<std::string> result {};

            if (extraSrc->isReference())
            {
                extraArgs = event->getArray(std::static_pointer_cast<Reference>(extraSrc)->jsonPath());
                if (!extraArgs)
                {
                    throw std::runtime_error(fmt::format(ar::TRACE_REFERENCE_ARR_NOT_FOUND,
                                                         name,
                                                         std::static_pointer_cast<Reference>(extraSrc)->jsonPath()));
                }
            }
            else
            {
                extraArgs = std::static_pointer_cast<Value>(extraSrc)->value().getArray();
            }

            for (const auto& arg : extraArgs.value())
            {
                if (!arg.isString())
                {
                    throw std::runtime_error(fmt::format(ar::TRACE_REFERENCE_TYPE_IS_NOT_STR,
                                                         name,
                                                         std::static_pointer_cast<Reference>(extraSrc)->jsonPath()));
                }
                result.emplace_back(arg.getString().value());
            }

            return result;
        };
    }

    auto getAgentID = [name](base::ConstEvent event) -> std::string
    {
        auto agentID = event->getString(ar::AGENT_ID_PATH);
        if (!agentID)
        {
            throw std::runtime_error(fmt::format(ar::TRACE_REFERENCE_STR_NOT_FOUND, name, ar::AGENT_ID_PATH));
        }
        return std::move(agentID.value());
    };

    // TODO This should be rewritten, do a better way to handle the different cases (LOCAL, ALL, ID) and use the api
    return [commandName, getLocationFn, getTimeoutFn, getExtraArgsFn, getAgentID, name](
               base::ConstEvent event) -> MapResult
    {
        std::string location {};
        std::int64_t timeout {};
        std::vector<std::string> extraArgs {};

        try
        {
            location = getLocationFn(event);
            timeout = getTimeoutFn(event);
            extraArgs = getExtraArgsFn(event);
        }
        catch (const std::exception& e)
        {
            return base::result::makeFailure(json::Json {}, e.what());
        }

        auto cmd = commandName + std::to_string(timeout);

        std::string agentID {};
        bool isLocal {false};
        bool isAll {false};
        bool isID {false};

        if (!location.compare("LOCAL"))
        {
            try
            {
                agentID = getAgentID(event);
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(json::Json {}, e.what());
            }
            isLocal = true;
        }
        else if (!location.compare("ALL"))
        {
            // TODO: This case generated one message per active agent in analysisd,
            // currently only the "all" text will be sent, which is not supported at
            // the moment by execd.
            isAll = true;
            agentID = "ALL";
        }
        else
        {
            // Check if it is a number (specific agent id)
            try
            {
                std::stoi(location);
                agentID = location;
                isID = true;
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(json::Json {}, e.what());
            }
        }

        json::Json jsonParams(ar::AR_JSON_PARAMS); // TODO: Make a static fn and not parse the json every time
        try
        {
            json::Json jsonEvent {event->str().c_str()};
            jsonParams.merge(json::NOT_RECURSIVE, jsonEvent, std::string_view {"/alert"});
        }
        catch (const std::exception& e)
        {
            // Should never happen
            return base::result::makeFailure(
                json::Json {}, fmt::format("[{}] -> Failure: Error trying to merge json: ", name) + e.what());
        }

        auto payload = base::utils::wazuhProtocol::WazuhRequest::create(cmd, ar::ORIGIN_NAME, jsonParams);

        // Append header message
        const std::string completeMesage = fmt::format("(local_source) [] N{}{} {} {}",
                                                       isLocal ? 'R' : 'N',
                                                       (isAll || isID) ? 'S' : 'N',
                                                       agentID,
                                                       payload.toStr());

        json::Json result {};
        result.setString(completeMesage);

        return base::result::makeSuccess(std::move(result), fmt::format(ar::TRACE_SUCCESS, name));
    };
}

// result: active_response_send('query'|$query)
MapOp SendAR(std::shared_ptr<sockiface::ISockFactory> sockFactory,
             const std::vector<OpArg>& opArgs,
             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Validate parameters
    if (!sockFactory)
    {
        throw std::runtime_error("sockFactory is nullptr");
    }

    utils::assertSize(opArgs, 1);
    if (opArgs[0]->isValue() && !std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' parameter but got type '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().typeName()));
    }
    const auto& rightParameter = opArgs[0];

    auto socketAR = sockFactory->getHandler(Protocol::DATAGRAM, ar::AR_QUEUE_PATH);

    const auto& name = buildCtx->context().opName;

    const auto success = fmt::format(ar::TRACE_SUCCESS, name);
    const std::string failureTrace1 =
        rightParameter->isReference() ? fmt::format(
            ar::TRACE_REFERENCE_STR_NOT_FOUND, name, std::static_pointer_cast<Reference>(rightParameter)->dotPath())
                                      : std::string();
    const auto failureTrace2 = fmt::format("[{}] -> Failure: The query is empty", name);
    const auto failureTrace3 = fmt::format("[{}] -> Failure: AR message could not be send", name);
    const auto failureTrace4 = fmt::format("[{}] -> Failure: Error trying to send AR message: ", name);

    return [socketAR, rightParameter, success, failureTrace1, failureTrace2, failureTrace3, failureTrace4](
               base::ConstEvent event) -> MapResult
    {
        std::string query {};
        bool messageSent {false};

        if (rightParameter->isReference())
        {
            auto reference = event->getString(std::static_pointer_cast<Reference>(rightParameter)->jsonPath());
            if (!reference)
            {
                return base::result::makeFailure(json::Json {}, failureTrace1);
            }
            query = std::move(reference.value());
        }
        else
        {
            query = std::static_pointer_cast<Value>(rightParameter)->value().getString().value();
        }

        if (query.empty())
        {
            return base::result::makeFailure(json::Json {}, failureTrace2);
        }

        try
        {
            if (SendRetval::SUCCESS == socketAR->sendMsg(query))
            {
                json::Json result("true");
                return base::result::makeSuccess(std::move(result), success);
            }
            else
            {
                return base::result::makeFailure(json::Json {}, failureTrace3);
            }
        }
        catch (const std::exception& e)
        {
            return base::result::makeFailure(json::Json {}, failureTrace4 + e.what());
        }
    };
}

MapBuilder getOpBuilderSendAr(std::shared_ptr<sockiface::ISockFactory> sockFactory)
{
    if (!sockFactory)
    {
        throw std::runtime_error("sockFactory is nullptr");
    }

    return [sockFactory](const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        return SendAR(sockFactory, opArgs, buildCtx);
    };
}

} // namespace builder::builders
