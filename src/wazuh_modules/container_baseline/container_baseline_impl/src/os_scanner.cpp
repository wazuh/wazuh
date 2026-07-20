#include "os_scanner.hpp"

#include <sys/utsname.h>

#include <fstream>
#include <string>
#include <unordered_map>

namespace wazuh::container_baseline {

namespace {

std::string Unquote(std::string_view value)
{
    if (value.size() >= 2 && (value.front() == '"' || value.front() == '\''))
    {
        const char quote = value.front();
        if (value.back() == quote)
        {
            value.remove_prefix(1);
            value.remove_suffix(1);
            if (quote == '\'') return std::string{value};

            std::string out;
            out.reserve(value.size());
            for (size_t i = 0; i < value.size(); ++i)
            {
                if (value[i] == '\\' && i + 1 < value.size()) ++i;
                out.push_back(value[i]);
            }
            return out;
        }
    }
    return std::string{value};
}

std::string FirstToken(const std::string& space_separated)
{
    const auto pos = space_separated.find(' ');
    return pos == std::string::npos ? space_separated : space_separated.substr(0, pos);
}

} // namespace

bool ParseOsReleaseLine(std::string_view line, std::string& key, std::string& value)
{
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    if (line.empty() || line.front() == '#') return false;

    const auto eq = line.find('=');
    if (eq == std::string_view::npos || eq == 0) return false;

    key   = std::string{line.substr(0, eq)};
    value = Unquote(line.substr(eq + 1));
    return true;
}

std::vector<OsBaselineRow> ScanContainerOs(pid_t pid)
{
    std::vector<OsBaselineRow> out;
    const std::string rootfs = "/proc/" + std::to_string(pid) + "/root";

    // os-release(5) precedence: /etc/os-release, then /usr/lib/os-release.
    std::ifstream file{rootfs + "/etc/os-release"};
    if (!file) file = std::ifstream{rootfs + "/usr/lib/os-release"};
    if (!file) return out; // scratch image — nothing to report.

    std::unordered_map<std::string, std::string> kv;
    std::string line, key, value;
    while (std::getline(file, line))
    {
        if (ParseOsReleaseLine(line, key, value)) kv[key] = value;
    }
    if (kv.empty()) return out;

    OsBaselineRow row;
    row.name     = kv["NAME"];
    row.full     = kv["PRETTY_NAME"];
    row.version  = kv["VERSION_ID"];
    row.codename = kv["VERSION_CODENAME"];
    row.platform = kv["ID"];
    row.family   = FirstToken(kv["ID_LIKE"]);

    struct utsname u;
    if (uname(&u) == 0) row.kernel = u.release;

    out.push_back(std::move(row));
    return out;
}

} // namespace wazuh::container_baseline
