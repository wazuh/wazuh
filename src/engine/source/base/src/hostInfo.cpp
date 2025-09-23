#include "base/hostInfo.hpp"

using base::utils::string::trim;

constexpr char DEFAULT_MANAGER_ID[] = "000"; // Default manager ID if not specified in the event.

namespace
{
/**
 * @brief Remove a single leading and trailing double quote if both are present.
 *        Example: "\"Ubuntu\"" → "Ubuntu".
 */
void unquoteEdges(std::string& s)
{
    if (s.size() >= 2 && s.front() == '\"' && s.back() == '\"')
    {
        s = s.substr(1, s.size() - 2);
    }
}

/**
 * @brief Retrieve and cache the local hostname.
 *
 * Uses gethostname(2) once and caches the result in a function-local static.
 * This is thread-safe since C++11 guarantees thread-safe initialization of
 * function-local statics.
 *
 * @return const std::string& Reference to the cached hostname.
 * @throws std::runtime_error if gethostname fails.
 */
const std::string& getHostName()
{
    static const std::string hostname = []()
    {
        constexpr size_t BUF_SIZE = 256;
        char buf[BUF_SIZE] = {};
        if (::gethostname(buf, BUF_SIZE) != 0)
        {
            throw std::runtime_error {std::string {"gethostname failed: "} + std::strerror(errno)};
        }
        buf[BUF_SIZE - 1] = '\0';
        return std::string {buf, std::strlen(buf)};
    }();

    return hostname;
}

/**
 * @brief Parse /etc/os-release into a key/value map.
 *
 * Lines starting with '#' are ignored. Values surrounded by quotes will be unquoted.
 *
 * @return std::unordered_map<std::string, std::string> with fields like NAME, VERSION, ID, VERSION_CODENAME.
 *         Missing file or parse errors are treated as empty results.
 */
std::unordered_map<std::string, std::string> parseOsRelease()
{
    std::unordered_map<std::string, std::string> kv;
    std::ifstream f("/etc/os-release");
    std::string line;

    while (std::getline(f, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        auto pos = line.find('=');
        if (pos == std::string::npos)
            continue;

        std::string key = trim(line.substr(0, pos), " \t\r\n");
        std::string val = trim(line.substr(pos + 1), " \t\r\n");
        unquoteEdges(val);
        kv[key] = val;
    }
    return kv;
}

/**
 * @brief Return a de-duplicated list of IPv4 addresses resolved from the local hostname.
 *
 * Resolution is based on gethostname() + getaddrinfo(AF_INET). If resolution fails,
 * an empty list is returned. This intentionally does not enumerate every interface; it
 * focuses on addresses associated with the primary hostname. Extend if you need all NICs.
 */
std::vector<std::string> getIpv4List()
{
    std::vector<std::string> ips;
    char hostname[256] {};
    if (gethostname(hostname, sizeof(hostname)) != 0)
        return ips;

    addrinfo hints {};
    hints.ai_family = AF_INET; // IPv4 only
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0 || !res)
        return ips;

    for (auto* p = res; p; p = p->ai_next)
    {
        char buf[INET_ADDRSTRLEN] {};
        auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)))
        {
            ips.emplace_back(buf);
        }
    }
    freeaddrinfo(res);

    std::sort(ips.begin(), ips.end());
    ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
    return ips;
}

/**
 * @brief Fill OS metadata fields from /etc/os-release if present.
 *
 * @param[out] name      NAME
 * @param[out] version   VERSION
 * @param[out] codename  VERSION_CODENAME
 * @param[out] platform  ID
 */
void fillOsRelease(std::string& name, std::string& version, std::string& codename, std::string& platform)
{
    auto kv = parseOsRelease();
    if (auto it = kv.find("NAME"); it != kv.end())
        name = it->second;
    if (auto it = kv.find("VERSION"); it != kv.end())
        version = it->second;
    if (auto it = kv.find("VERSION_CODENAME"); it != kv.end())
        codename = it->second;
    if (auto it = kv.find("ID"); it != kv.end())
        platform = it->second;
}

/**
 * @brief Build a human-friendly kernel description string.
 *
 * Format: "<sysname> |<agentName> |<release> |<version> |<machine>"
 * Example: "Linux |worker |5.4.0-169-generic |#187-Ubuntu SMP ... |x86_64"
 *
 * @param agentName The hostname/agent name to embed in the string.
 * @return std::string The formatted kernel string (or "unknown" if uname fails).
 */
std::string buildKernelString(const std::string& agentName)
{
    struct utsname uts {};
    if (uname(&uts) != 0)
        return "unknown";

    std::string s =
        std::string(uts.sysname) + " |" + agentName + " |" + uts.release + " |" + uts.version + " |" + uts.machine;
    return s;
}
} // namespace

namespace base::hostInfo
{
/**
 * @brief Collect host/agent information and return it as a json::Json.
 *
 * See header documentation for the full list of populated paths.
 */
json::Json toJson()
{
    // Extract OS information from /etc/os-release
    std::string os_name, os_version, os_codename, os_platform;
    fillOsRelease(os_name, os_version, os_codename, os_platform);

    // Agent/host name
    const auto hostName = getHostName();

    // Architecture (uname)
    struct utsname uts {};
    std::string arch = "unknown";
    if (uname(&uts) == 0)
        arch = uts.machine;

    // Kernel descriptor string
    const auto kernel_str = buildKernelString(hostName);

    // IPv4 addresses resolved from hostname
    auto ips = getIpv4List();

    // Build JSON
    json::Json j;

    j.setString(hostName, EVENT_AGENT_NAME);
    j.setString(DEFAULT_MANAGER_ID, EVENT_AGENT_ID);

    if (!os_name.empty())
        j.setString(os_name, EVENT_HOST_OS_NAME);
    if (!os_version.empty())
        j.setString(os_version, EVENT_HOST_OS_VERSION);
    if (!os_codename.empty())
        j.setString(os_codename, EVENT_HOST_OS_FULL);
    if (!os_platform.empty())
        j.setString(os_platform, EVENT_HOST_OS_PLATFORM);

    j.setString(kernel_str, EVENT_HOST_OS_KERNEL);

    for (const auto& ip : ips)
    {
        j.appendString(ip, EVENT_HOST_IP);
    }

    j.setString(arch, EVENT_HOST_ARCHITECTURE);

    return j;
}

} // namespace base::hostInfo
