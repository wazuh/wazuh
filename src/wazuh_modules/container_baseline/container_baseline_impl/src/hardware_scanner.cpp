#include "hardware_scanner.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace wazuh::container_baseline {

namespace {

std::string ReadTrimmedLine(const std::string& path)
{
    std::ifstream f{path};
    std::string s;
    if (f) std::getline(f, s);
    return s;
}

// cgroup v2 unified path from /proc/<pid>/cgroup (the "0::<path>" line). The
// agent runs in the host's root cgroup namespace, so the kernel renders this
// path host-absolute even for a containerized pid. Empty on a v1-only host.
std::string CgroupV2Path(pid_t pid)
{
    std::ifstream f{"/proc/" + std::to_string(pid) + "/cgroup"};
    std::string line;
    while (std::getline(f, line))
    {
        if (line.rfind("0::", 0) == 0) return line.substr(3);
    }
    return {};
}

int64_t HostMemTotalBytes()
{
    std::ifstream f{"/proc/meminfo"};
    std::string key, unit;
    int64_t kb = 0;
    while (f >> key >> kb >> unit)
    {
        if (key == "MemTotal:") return kb * 1024; // /proc/meminfo reports KB.
    }
    return 0;
}

// CPU is the shared host silicon: model/speed from /proc/cpuinfo, plus a logical
// core count for the unlimited-quota fallback.
void HostCpuInfo(std::string& name, double& mhz, int64_t& logical_cores)
{
    std::ifstream f{"/proc/cpuinfo"};
    std::string line;
    while (std::getline(f, line))
    {
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = line.substr(0, colon);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
        std::string val = line.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());

        if (key == "model name" && name.empty()) name = val;
        else if (key == "cpu MHz" && mhz == 0) mhz = std::strtod(val.c_str(), nullptr);
        else if (key == "processor") ++logical_cores;
    }
}

} // namespace

int64_t CoresFromCpuMax(const std::string& cpu_max)
{
    std::istringstream iss(cpu_max);
    std::string quota, period;
    iss >> quota >> period;
    if (quota.empty() || quota == "max") return 0; // unlimited.

    const double q = std::strtod(quota.c_str(), nullptr);
    const double p = period.empty() ? 100000.0 : std::strtod(period.c_str(), nullptr);
    if (p <= 0 || q <= 0) return 0;

    const auto cores = static_cast<int64_t>(q / p + 0.999); // round a partial quota up to a whole core.
    return cores > 0 ? cores : 1;
}

int64_t ParseCgroupBytes(const std::string& value)
{
    if (value.empty() || value == "max") return 0; // unlimited.
    return std::strtoll(value.c_str(), nullptr, 10);
}

std::vector<HardwareBaselineRow> ScanContainerHardware(pid_t pid)
{
    std::vector<HardwareBaselineRow> out;

    // ponytail: cgroup v2 unified only (Docker 20.10+/modern hosts). Add the v1
    // memory/cpu controller paths if a v1 target needs coverage.
    const std::string v2 = CgroupV2Path(pid);
    if (v2.empty()) return out;

    const std::string base = "/sys/fs/cgroup" + v2;
    const std::string mem_max = ReadTrimmedLine(base + "/memory.max");
    if (mem_max.empty()) return out; // cgroup not visible from host — nothing to report.

    HardwareBaselineRow row;

    int64_t mem_total = ParseCgroupBytes(mem_max);
    const int64_t mem_used = ParseCgroupBytes(ReadTrimmedLine(base + "/memory.current"));
    if (mem_total == 0) mem_total = HostMemTotalBytes(); // "max" → container sees all host RAM.
    row.memory_total = mem_total;
    row.memory_used  = mem_used;
    row.memory_free  = (mem_total > mem_used) ? mem_total - mem_used : 0;

    int64_t host_cores = 0;
    HostCpuInfo(row.cpu_name, row.cpu_speed, host_cores);
    const int64_t quota_cores = CoresFromCpuMax(ReadTrimmedLine(base + "/cpu.max"));
    row.cpu_cores = (quota_cores > 0) ? quota_cores : host_cores; // unlimited → host logical count.

    out.push_back(std::move(row));
    return out;
}

} // namespace wazuh::container_baseline
