#include "process_scanner.hpp"

#include "pid_resolver.hpp"
#include "timeHelper.h"

#include <unistd.h>

#include <fstream>
#include <sstream>

namespace wazuh::container_baseline {

namespace {

// Fields of /proc/<pid>/stat that this scanner cares about (1-indexed per proc(5)).
struct ProcStat
{
    std::string comm;
    char        state{'?'};
    int64_t     ppid{0};
    int64_t     utime{0};
    int64_t     stime{0};
    int64_t     starttime_ticks{0};
    bool        ok{false};
};

ProcStat ReadProcStat(pid_t pid)
{
    ProcStat out;
    std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
    if (!f) return out;

    std::string line;
    if (!std::getline(f, line)) return out;

    // comm is whatever is between the FIRST '(' and the LAST ')' — it may itself
    // contain spaces or parens, so we cannot just split on whitespace.
    const auto open_paren  = line.find('(');
    const auto close_paren = line.rfind(')');
    if (open_paren == std::string::npos || close_paren == std::string::npos ||
        close_paren < open_paren) {
        return out;
    }
    out.comm = line.substr(open_paren + 1, close_paren - open_paren - 1);

    // Everything after "<pid> (comm) " is space-separated fields starting at
    // field 3 (state).
    std::istringstream rest(line.substr(close_paren + 2));
    std::vector<std::string> fields;
    std::string              tok;
    while (rest >> tok) fields.push_back(tok);

    // fields[0] = state (field 3), fields[1] = ppid (field 4), ...
    // utime = field 14 -> fields[11], stime = field 15 -> fields[12],
    // starttime = field 22 -> fields[19].
    if (fields.size() <= 19) return out;

    out.state           = fields[0].empty() ? '?' : fields[0][0];
    out.ppid            = std::stoll(fields[1]);
    out.utime           = std::stoll(fields[11]);
    out.stime           = std::stoll(fields[12]);
    out.starttime_ticks = std::stoll(fields[19]);
    out.ok              = true;
    return out;
}

std::vector<std::string> ReadCmdline(pid_t pid)
{
    std::vector<std::string> args;
    std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!f) return args;

    std::string blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t start = 0;
    for (size_t i = 0; i < blob.size(); ++i) {
        if (blob[i] == '\0') {
            if (i > start) args.push_back(blob.substr(start, i - start));
            start = i + 1;
        }
    }
    if (start < blob.size()) args.push_back(blob.substr(start));
    return args;
}

// Boot time (seconds since epoch) read from /proc/stat's "btime" line, plus the
// kernel clock tick rate, are what's needed to turn a starttime-in-ticks-since-
// boot into a wall-clock Unix timestamp.
int64_t BootTimeEpochSeconds()
{
    std::ifstream f("/proc/stat");
    if (!f) return 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("btime ", 0) == 0) {
            return std::stoll(line.substr(6));
        }
    }
    return 0;
}

std::string ProcessStateToString(char state)
{
    switch (state) {
        case 'R': return "running";
        case 'S': return "sleeping";
        case 'D': return "disk_sleep";
        case 'Z': return "zombie";
        case 'T': return "stopped";
        case 't': return "tracing_stop";
        case 'X':
        case 'x': return "dead";
        case 'I': return "idle";
        default:  return "unknown";
    }
}

} // namespace

std::vector<ProcessBaselineRow> ScanContainerProcesses(const std::string& container_id)
{
    std::vector<ProcessBaselineRow> rows;
    if (container_id.empty()) return rows;

    const auto pids       = ResolvePidsForContainer(container_id);
    const auto clk_tck     = ::sysconf(_SC_CLK_TCK);
    const auto boot_epoch  = BootTimeEpochSeconds();

    for (const auto pid : pids) {
        const auto stat = ReadProcStat(pid);
        if (!stat.ok) continue; // process exited between resolve and read — skip.

        ProcessBaselineRow row;
        row.pid         = std::to_string(pid);
        row.name        = stat.comm;
        row.state       = ProcessStateToString(stat.state);
        row.parent_pid  = stat.ppid;
        row.utime       = stat.utime;
        row.stime       = stat.stime;

        const auto argv = ReadCmdline(pid);
        row.args_count  = static_cast<int64_t>(argv.size());
        if (!argv.empty()) {
            row.command_line = argv[0];
            for (size_t i = 1; i < argv.size(); ++i) {
                if (i > 1) row.args += ' ';
                row.args += argv[i];
            }
        } else {
            // No cmdline (kernel thread or zero-page process) — fall back to comm.
            row.command_line = stat.comm;
        }

        if (clk_tck > 0 && boot_epoch > 0) {
            // Schema expects process.start as ISO8601 (or an epoch number, but this
            // TEXT column already holds ISO8601 strings for host rows — match that).
            row.start = Utils::rawTimestampToISO8601(
                static_cast<uint32_t>(boot_epoch + stat.starttime_ticks / clk_tck));
        }

        row.container_id = container_id;
        rows.push_back(std::move(row));
    }

    return rows;
}

} // namespace wazuh::container_baseline
