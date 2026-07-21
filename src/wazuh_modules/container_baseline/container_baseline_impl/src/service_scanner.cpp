#include "service_scanner.hpp"

#include <dirent.h>

#include <fstream>
#include <set>
#include <sstream>

namespace wazuh::container_baseline {

namespace {

// systemd unit search path, highest precedence first (etc overrides usr/lib).
constexpr const char* kUnitDirs[] = {
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
};

std::string Trim(const std::string& s)
{
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool EndsWith(const std::string& s, const std::string& suffix)
{
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Units symlinked under any <rootfs>/etc/systemd/system/*.wants directory are the
// enabled ones — `systemctl enable` creates exactly those links.
std::set<std::string> EnabledUnits(const std::string& rootfs)
{
    std::set<std::string> enabled;
    const std::string base = rootfs + "/etc/systemd/system";

    DIR* d = ::opendir(base.c_str());
    if (!d) return enabled;

    while (auto* ent = ::readdir(d))
    {
        const std::string name = ent->d_name;
        if (!EndsWith(name, ".wants")) continue;

        DIR* wd = ::opendir((base + "/" + name).c_str());
        if (!wd) continue;
        while (auto* went = ::readdir(wd))
        {
            const std::string unit = went->d_name;
            if (unit == "." || unit == "..") continue;
            enabled.insert(unit);
        }
        ::closedir(wd);
    }
    ::closedir(d);
    return enabled;
}

} // namespace

void ParseUnitFile(const std::string& contents, std::string& description, std::string& executable)
{
    std::istringstream iss(contents);
    std::string line;
    while (std::getline(iss, line))
    {
        const std::string t = Trim(line);
        if (description.empty() && t.rfind("Description=", 0) == 0)
        {
            description = Trim(t.substr(12));
        }
        else if (executable.empty() && t.rfind("ExecStart=", 0) == 0)
        {
            std::string cmd = Trim(t.substr(10));
            size_t p = 0; // strip systemd exec prefixes (- @ + ! :).
            while (p < cmd.size() &&
                   (cmd[p] == '-' || cmd[p] == '@' || cmd[p] == '+' || cmd[p] == '!' || cmd[p] == ':'))
            {
                ++p;
            }
            cmd = cmd.substr(p);
            const auto sp = cmd.find(' ');
            executable = (sp == std::string::npos) ? cmd : cmd.substr(0, sp);
        }
    }
}

std::vector<ServiceBaselineRow> ScanContainerServices(pid_t pid)
{
    std::vector<ServiceBaselineRow> out;
    const std::string rootfs = "/proc/" + std::to_string(pid) + "/root";
    const auto enabled = EnabledUnits(rootfs);

    std::set<std::string> seen; // a unit may appear in several dirs — highest precedence wins.

    for (const char* dir : kUnitDirs)
    {
        const std::string path = rootfs + dir;
        DIR* d = ::opendir(path.c_str());
        if (!d) continue;

        while (auto* ent = ::readdir(d))
        {
            const std::string fname = ent->d_name;
            if (!EndsWith(fname, ".service") || fname.size() <= 8) continue;
            if (!seen.insert(fname).second) continue;

            std::ifstream f{path + "/" + fname};
            if (!f) continue;
            std::stringstream buf;
            buf << f.rdbuf();

            ServiceBaselineRow row;
            row.name = fname.substr(0, fname.size() - 8);
            ParseUnitFile(buf.str(), row.description, row.executable);
            row.state     = "unknown";
            row.enabled   = enabled.count(fname) ? "enabled" : "disabled";
            row.type      = "systemd";
            row.file_path = std::string(dir) + "/" + fname;
            out.push_back(std::move(row));
        }
        ::closedir(d);
    }
    return out;
}

} // namespace wazuh::container_baseline
