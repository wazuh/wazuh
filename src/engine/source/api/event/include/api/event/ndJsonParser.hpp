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
        auto throwError = [](const std::string& msg){ throw std::runtime_error(msg); };

        if (batch.empty())
        {
            throwError("empty batch");
        }

        // --- Split input into lines, preserving content ---
        std::vector<std::string_view> lines;
        {
            // Replace '\n' with '\0' so we can tokenize using the same buffer (no copies)
            std::replace(batch.begin(), batch.end(), '\n', '\0');
            const char* p = batch.data();
            const char* e = p + batch.size();
            while (p < e)
            {
                const char* q = std::find(p, e, '\0');
                if (q > p) { lines.emplace_back(p, static_cast<size_t>(q - p)); }
                p = q + 1;
            }
        }
        if (lines.empty())
        {
            throwError("no lines in batch");
        }

        auto starts_with = [](std::string_view s, char tag)
        {
            // Accepts 'H ' / 'H\t' / 'E ' / 'E\t' prefixes
            return !s.empty() && s.front() == tag;
        };

        // --- Parse first header line: "H\t{json}" ---
        json::Json header;
        {
            std::string_view h = lines.front();
            if (!starts_with(h, 'H'))
            {
                throwError("invalid batch: first line must start with 'H\\t{json}'");
            }
            // Skip leading spaces/tabs after 'H'
            size_t i = 1;
            while (i < h.size() && (h[i] == ' ' || h[i] == '\t')) ++i;
            if (i >= h.size())
            {
                throwError("invalid header: missing JSON");
            }
            try
            {
                header = json::Json(h.substr(i).data());
            }
            catch (const std::exception& ex)
            {
                throwError(std::string("invalid header json: ") + ex.what());
            }
        }

        // --- Event collector (supports multi-line events) ---
        std::queue<base::Event> out;
        std::string currentRaw;  // buffer reused for each event
        bool inEvent = false;

        auto flush_event = [&](bool final_flush)
        {
            if (!inEvent) return;
            // Remove residual CRs
            currentRaw.erase(std::remove(currentRaw.begin(), currentRaw.end(), '\r'), currentRaw.end());
            if (currentRaw.empty())
            {
                throwError("empty event payload");
            }

            // Step 1: legacy parse of event payload
            base::Event ev;
            try
            {
                ev = base::eventParsers::parseLegacyEvent(std::string_view{currentRaw});
            }
            catch (const std::exception& ex)
            {
                throwError(std::string("invalid legacy event: ") + ex.what());
            }

            // Step 2: merge with current header metadata
            try
            {
                ev->merge(true, header);
            }
            catch (const std::exception& ex)
            {
                throwError(std::string("merge failed: ") + ex.what());
            }

            // Debug/log output of event
            std::cout << ev->str() << std::endl;

            out.push(std::move(ev));
            inEvent = false;
            currentRaw.clear();
        };

        // --- Iterate through lines starting from the second one ---
        for (size_t li = 1; li < lines.size(); ++li)
        {
            std::string_view ln = lines[li];
            if (ln.empty()) continue;

            if (starts_with(ln, 'H'))
            {
                // New header inside the same batch (rare but supported)
                flush_event(/*final*/false);

                size_t i = 1;
                while (i < ln.size() && (ln[i] == ' ' || ln[i] == '\t')) ++i;
                if (i >= ln.size()) throwError("invalid header: missing JSON");
                try
                {
                    header = json::Json(ln.substr(i).data());
                }
                catch (const std::exception& ex)
                {
                    throwError(std::string("invalid header json: ") + ex.what());
                }
                continue;
            }

            if (starts_with(ln, 'E'))
            {
                // If an event was already open, flush it before starting a new one
                if (inEvent) flush_event(/*final*/false);

                size_t i = 1;
                while (i < ln.size() && (ln[i] == ' ' || ln[i] == '\t')) ++i;
                currentRaw.assign( (i < ln.size()) ? ln.substr(i) : std::string_view{} );
                inEvent = true;
                continue;
            }

            // Continuation of a multi-line event payload
            if (inEvent)
            {
                if (!currentRaw.empty()) currentRaw.push_back('\n');
                currentRaw.append(ln.data(), ln.size());
                continue;
            }

            // Unexpected line: neither header nor event
            throwError("unexpected line (neither H nor E) before any event start");
        }

        // Flush last event if still open
        if (inEvent) flush_event(/*final*/true);

        return out;
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_NDJSONPARSER_HPP
