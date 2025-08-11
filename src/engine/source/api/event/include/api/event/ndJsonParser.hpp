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

        // Process all lines as events
        std::queue<base::Event> events;

        for (auto it = rawJson.begin(); it != rawJson.end(); ++it)
        {
            try
            {
                base::Event currentLine = std::make_shared<json::Json>(it->data());
                events.push(std::move(currentLine));
            }
            catch (const std::exception& e)
            {
                throwErrorMsg(fmt::format("invalid ndjson line or event: '{}'", e.what()));
            }
        }

        return events;
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
