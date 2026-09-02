#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_instances
{

    /// Reassembles newline-delimited JSON lines from arbitrary byte chunks.
    /// Pure value type: no I/O, no allocation surprises, trivially testable.
    class NdjsonFramer final
    {
    public:
        /// Feed one received chunk; returns every line completed by it (without
        /// the trailing newline; a trailing '\r' is stripped too).
        [[nodiscard]] std::vector<std::string> push(std::string_view chunk)
        {
            std::vector<std::string> lines;
            std::size_t start = 0;

            while (true)
            {
                const auto newline = chunk.find('\n', start);
                if (newline == std::string_view::npos)
                {
                    m_partial.append(chunk.substr(start));
                    break;
                }

                std::string line = std::move(m_partial);
                m_partial.clear();
                line.append(chunk.substr(start, newline - start));
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }
                if (!line.empty())
                {
                    lines.push_back(std::move(line));
                }
                start = newline + 1;
            }

            return lines;
        }

        /// Returns and clears any dangling partial line (stream ended mid-line).
        [[nodiscard]] std::string reset()
        {
            std::string dangling = std::move(m_partial);
            m_partial.clear();
            return dangling;
        }

    private:
        std::string m_partial;
    };

} // namespace wazuh::container_instances
