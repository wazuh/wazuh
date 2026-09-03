#include "id_map.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace wazuh::container_baseline {

namespace {

constexpr uint32_t kFullRange = 4294967295U; // 2^32 - 1, the identity-map length.

} // namespace

IdMap IdMap::Parse(const std::string& contents)
{
    IdMap map;

    std::istringstream stream{contents};
    std::string        line;

    while (std::getline(stream, line))
    {
        std::istringstream fields{line};
        uint64_t           inside = 0;
        uint64_t           outside = 0;
        uint64_t           length = 0;

        if (!(fields >> inside >> outside >> length)) continue;
        if (length == 0) continue;

        // Values above 2^32-1 are not valid ids; ignore a malformed line rather
        // than truncating it into a wrong mapping.
        if (inside > kFullRange || outside > kFullRange || length > kFullRange) continue;

        map.m_ranges.push_back(Range{static_cast<uint32_t>(inside),
                                     static_cast<uint32_t>(outside),
                                     static_cast<uint32_t>(length)});
    }

    // The identity map ("0 0 4294967295") is what a container WITHOUT a user
    // namespace reports. Collapsing it to "no ranges" makes toContainer() a
    // cheap no-op for the common case.
    if (map.m_ranges.size() == 1 && map.m_ranges[0].inside == 0 && map.m_ranges[0].outside == 0 &&
        map.m_ranges[0].length == kFullRange)
    {
        map.m_ranges.clear();
    }

    return map;
}

IdMap IdMap::FromProc(pid_t pid, const char* map_file)
{
    std::ifstream file{"/proc/" + std::to_string(pid) + "/" + map_file};
    if (!file) return IdMap{}; // unreadable -> identity, i.e. report host ids as today.

    std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return Parse(contents);
}

uint32_t IdMap::toContainer(uint32_t host_id) const
{
    if (m_ranges.empty()) return host_id;

    for (const auto& range : m_ranges)
    {
        // Guard the addition: outside + length can exceed 2^32 on a malformed map.
        const uint64_t begin = range.outside;
        const uint64_t end   = begin + range.length;

        if (host_id >= begin && host_id < end)
        {
            return static_cast<uint32_t>(range.inside + (host_id - begin));
        }
    }

    // No covering range: the id has no meaning inside the namespace. The kernel
    // surfaces this as overflowuid (65534/nobody); passing the host value
    // through unchanged keeps it at least traceable.
    return host_id;
}

} // namespace wazuh::container_baseline
