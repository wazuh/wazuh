#ifndef _API_EVENT_NDJSONPARSER_HPP
#define _API_EVENT_NDJSONPARSER_HPP

#include <functional>
#include <list>
#include <queue>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include <base/baseTypes.hpp>
#include <base/logging.hpp>

namespace api::event::protocol
{
using ProtocolHandler = std::function<std::queue<base::Event>(std::string&&)>;

inline ProtocolHandler getNDJsonParser(bool prodMode = true)
{
    return [prodMode,
            lambdaName = logging::getLambdaName(__FUNCTION__, fmt::format("getNDJsonParser(prodMode={})", prodMode))](
               std::string&& batch) -> std::queue<base::Event>
    {
        const std::size_t headerSize = 2;
        const std::size_t min_size = headerSize + 1;

        const auto isSubHeader = [](const base::Event& event) -> bool
        {
            return event->isString("/module") && event->isString("/collector");
        }; // '/module' and '/collector' are mandatory fields and not present in wazuh common schema

        const auto invalidSubHeaderError =
            "NDJson parser error, invalid subheader, json must contain '/module' and '/collector' fields only";

        if (batch.empty())
        {
            LOG_DEBUG_L(lambdaName.c_str(), "Ignored empty event batch");
            throw std::runtime_error {"NDJson parser error, empty batch"};
        }

        // Extract each json raw from ndjson
        std::list<std::string_view> rawJson {};
        {
            std::replace(batch.begin(), batch.end(), '\n', '\0'); // Use string as buffer
            const char* start = batch.data();
            const char* end = start + batch.size();
            while (start < end)
            {
                const char* next = std::find(start, end, '\0');
                if (start != next)
                {
                    rawJson.emplace_back(start, next - start);
                }
                start = next + 1;
            }
        }

        // Validate the batch
        if (rawJson.size() < min_size)
        {
            LOG_DEBUG_L(lambdaName.c_str(),
                        "Ignored event batch: {}, reason: invalid size {} < {}",
                        batch,
                        rawJson.size(),
                        min_size);
            throw std::runtime_error {"NDJson parser error, invalid size"};
        }

        // Extract the header for futher merge with the events.
        json::Json agentInfo {};
        try
        {
            agentInfo = std::move(json::Json(rawJson.front().data()));
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG_L(lambdaName.c_str(), "Error parsing agent info: '{}'", e.what());
            throw std::runtime_error {"NDJson parser error, invalid header, discarting ndjson"};
        }

        // Extract the subheader for futher merge with the events.
        base::Event subHeader;
        try
        {
            subHeader = std::make_shared<json::Json>(std::next(rawJson.begin(), 1)->data());
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG_L(lambdaName.c_str(), "Error parsing subheader: '{}'", e.what());
            throw std::runtime_error {"NDJson parser error, invalid subheader, discarting ndjson"};
        }

        if (!isSubHeader(subHeader))
        {
            LOG_DEBUG_L(lambdaName.c_str(), invalidSubHeaderError);
            throw std::runtime_error {"Invalid subheader, discarting ndjson"};
        }

        // Merge the header and subheaders with the events
        std::queue<base::Event> events;

        for (auto it = std::next(rawJson.begin(), headerSize); it != rawJson.end(); ++it)
        {
            try
            {
                auto event = std::make_shared<json::Json>(it->data());
                if (isSubHeader(event))
                {
                    subHeader = event;
                    continue;
                }

                event->merge(true, agentInfo);
                event->set("/event/module", subHeader->getJson("/module").value());
                event->set("/event/collector", subHeader->getJson("/collector").value());
                events.push(std::move(event));
            }
            catch (const std::exception& e)
            {
                // Ignore invalid events
                LOG_DEBUG_L(lambdaName.c_str(), "Ignored event: {}, reason: {}", it->data(), e.what());
                if (prodMode)
                {
                    continue;
                }
                else
                {
                    throw std::runtime_error {fmt::format("NDJson parser error, invalid event: {}", e.what())};
                }
            }
        }

        return events;
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
