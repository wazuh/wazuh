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
#include <base/eventParser.hpp>

namespace api::event::protocol
{
using ProtocolHandler = std::function<std::queue<base::Event>(std::string&&)>;
constexpr auto HEADER_ERROR_MSG = "NDJson parser error, {}";

inline ProtocolHandler getNDJsonParser()
{
    return [](std::string&& batch) -> std::queue<base::Event>
    {
        try
        {
            // ---- In-place line tokenization (zero-copy) ----
            // Reserve approximate number of lines to reduce reallocations.
            std::vector<std::string_view> lines;
            {
                const std::size_t approx_lines =
                    1u + static_cast<std::size_t>(std::count(batch.begin(), batch.end(), '\n'));
                lines.reserve(approx_lines);

                // Replace '\n' with '\0' to create C-style segments inside the same buffer.
                std::replace(batch.begin(), batch.end(), '\n', '\0');

                // Walk the buffer and produce views for each line segment.
                const char* p = batch.data();
                const char* e = p + batch.size();
                while (p < e)
                {
                    const char* q = std::find(p, e, '\0');
                    if (q > p)
                    {
                        lines.emplace_back(p, static_cast<std::size_t>(q - p));
                    }
                    p = q + 1;
                }
            }

            // Helper: require exact "<tag>\t..."
            auto is_tag_tab = [](std::string_view s, char tag) noexcept -> bool
            {
                return s.size() >= 2 && s[0] == tag && s[1] == '\t';
            };

            // ---- Single header at the start: "H\t{json}" (assumed valid) ----
            // We assume there's always JSON after "H\t"; no length checks here.
            json::Json header(lines.front().substr(2).data());

            // ---- Event collection (supports multi-line payloads) ----
            std::queue<base::Event> out;
            std::string currentRaw; // re-used buffer for each event
            bool inEvent = false;

            auto flush_event = [&]()
            {
                if (!inEvent)
                    return;

                // No CR stripping: preserve payload as-is, avoid extra memory moves.
                // Delegate validation to the legacy event parser.
                base::Event ev = base::eventParsers::parseLegacyEvent(std::string_view {currentRaw}, header);

                out.push(std::move(ev));
                inEvent = false;
                currentRaw.clear();
            };

            // Parse from the second line onwards: "E\t..." starts an event;
            // any other line is a continuation if an event is open, else ignored.
            for (std::size_t li = 1; li < lines.size(); ++li)
            {
                std::string_view ln = lines[li];
                if (ln.empty())
                    continue;

                if (is_tag_tab(ln, 'E'))
                {
                    if (inEvent)
                        flush_event();

                    currentRaw.assign((ln.size() > 2) ? ln.substr(2) : std::string_view{});
                    inEvent = true;
                    continue;
                }

                // Multi-line continuation: only valid if an event is open.
                if (inEvent)
                {
                    if (!currentRaw.empty())
                        currentRaw.push_back('\n');
                    currentRaw.append(ln.data(), ln.size());
                    continue;
                }

                // STRICT mode: any non-empty, non-"E\t" line outside an event is a protocol error.
                throw std::runtime_error{"unexpected line outside of an event"};
            }

            // Finalize last open event, if any.
            if (inEvent)
                flush_event();

            return out;
        }
        catch (const std::exception& ex)
        {
            // Normalize error message format for the caller.
            throw std::runtime_error {fmt::format(HEADER_ERROR_MSG, ex.what())};
        }
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
