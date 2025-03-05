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

namespace api::event::protocol
{
using ProtocolHandler = std::function<std::queue<base::Event>(std::string&&)>;

namespace
{
void throwErrorMsg(const std::string& msg)
{
    throw std::runtime_error {fmt::format("NDJson parser error, {}", msg)};
}
} // namespace

inline ProtocolHandler getNDJsonParser()
{
    return [](std::string&& batch) -> std::queue<base::Event>
    {
        const std::size_t headerSize = 2;
        const std::size_t min_size = headerSize + 1;

        const auto isSubHeader = [](const base::Event& event) -> bool
        {
            return event->isString("/module") && event->isString("/collector");
        }; // '/module' and '/collector' are mandatory fields and not present in wazuh common schema

        if (batch.empty())
        {
            throwErrorMsg("empty batch");
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
                else
                {
                    throwErrorMsg("empty line");
                }
                start = next + 1;
            }
        }

        // Validate the batch
        if (rawJson.size() < min_size)
        {
            throwErrorMsg(fmt::format("invalid batch, expected at least {} lines", min_size));
        }

        // Extract the header for futher merge with the events.
        json::Json agentInfo {};
        try
        {
            agentInfo = std::move(json::Json(rawJson.front().data()));
        }
        catch (const std::exception& e)
        {
            throwErrorMsg(fmt::format("invalid header: '{}'", e.what()));
        }

        // Extract the subheader for futher merge with the events.
        base::Event subHeader;
        try
        {
            subHeader = std::make_shared<json::Json>(std::next(rawJson.begin(), 1)->data());
        }
        catch (const std::exception& e)
        {
            throwErrorMsg(fmt::format("invalid subheader: '{}'", e.what()));
        }

        if (!isSubHeader(subHeader))
        {
            throwErrorMsg("invalid subheader, expected '/module' and '/collector' fields");
        }

        // Merge the header and subheaders with the events
        std::queue<base::Event> events;

        base::Event currentLine;
        for (auto it = std::next(rawJson.begin(), headerSize); it != rawJson.end(); ++it)
        {
            try
            {
                currentLine = std::make_shared<json::Json>(it->data());
            }
            catch (const std::exception& e)
            {
                throwErrorMsg(fmt::format("invalid ndjson line: '{}'", e.what()));
            }

            if (isSubHeader(currentLine))
            {
                subHeader = currentLine;
                continue;
            }

            try
            {
                currentLine->merge(true, agentInfo);
                currentLine->set("/event/module", subHeader->getJson("/module").value());
                currentLine->set("/event/collector", subHeader->getJson("/collector").value());
                events.push(std::move(currentLine));
            }
            catch (const std::exception& e)
            {
                throwErrorMsg(fmt::format("invalid event: '{}'", e.what()));
            }
        }

        return events;
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
