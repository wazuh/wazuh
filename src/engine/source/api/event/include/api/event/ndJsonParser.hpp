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

inline ProtocolHandler getNDJsonParser()
{
    return [](std::string&& batch) -> std::queue<base::Event>
    {
        const std::size_t headerSize = 2; // Header + subheader
        const std::size_t min_size = headerSize + 1;

        if (batch.empty())
        {
            throw std::runtime_error {"NDJson parser error: Received empty data"};
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
            throw std::runtime_error {
                fmt::format("NDJson parser error: Received ndjson with less than '{}' lines", min_size)};
        }

        // Extract the header for futher merge with the events.
        json::Json agentInfo {};
        try
        {
            agentInfo = std::move(json::Json(rawJson.front().data()));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error {fmt::format("NDJson parser error, invalid header: {}", e.what())};
        }

        // Extract first subheader
        json::Json subheader {};
        try
        {
            subheader = std::move(json::Json(std::next(rawJson.begin())->data()));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error {fmt::format("NDJson parser error, invalid subheader: {}", e.what())};
        }

        // Merge the header with the events
        std::queue<base::Event> events;

        for (auto it = std::next(rawJson.begin(), headerSize); it != rawJson.end(); ++it)
        {
            try
            {
                auto event = std::make_shared<json::Json>(it->data());
                // Ignore subheader events
                if (event->isString("/module"))
                {
                    continue;
                }
                event->merge(true, agentInfo);
                events.push(std::move(event));
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error {
                    fmt::format("NDJson parser error, invalid event at line {}: {}", *it, e.what())};
            }
        }

        return events;
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
