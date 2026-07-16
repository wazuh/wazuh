#include "user_scanner.hpp"

#include <charconv>
#include <fstream>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

namespace {

std::vector<std::string_view> SplitFields(std::string_view line, char sep)
{
    std::vector<std::string_view> out;
    size_t start = 0;
    while (true) {
        const auto pos = line.find(sep, start);
        if (pos == std::string_view::npos) {
            out.push_back(line.substr(start));
            return out;
        }
        out.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
}

[[nodiscard]] bool ParseId(std::string_view field, int64_t& out)
{
    const auto* end = field.data() + field.size();
    const auto [ptr, ec] = std::from_chars(field.data(), end, out);
    return ec == std::errc{} && ptr == end;
}

[[nodiscard]] bool IsSkippable(std::string_view line)
{
    return line.empty() || line.front() == '#';
}

} // namespace

bool ParsePasswdLine(std::string_view line, UserBaselineRow& row)
{
    if (IsSkippable(line)) return false;

    const auto fields = SplitFields(line, ':');
    if (fields.size() != 7) return false;

    int64_t uid = 0;
    int64_t gid = 0;
    if (!ParseId(fields[2], uid) || !ParseId(fields[3], gid)) return false;
    if (fields[0].empty()) return false;

    row.name        = std::string{fields[0]};
    row.uid         = uid;
    row.gid         = gid;
    row.description = std::string{fields[4]};
    row.home        = std::string{fields[5]};
    row.shell       = std::string{fields[6]};
    return true;
}

bool ParseGroupLine(std::string_view line, GroupBaselineRow& row)
{
    if (IsSkippable(line)) return false;

    const auto fields = SplitFields(line, ':');
    if (fields.size() != 4) return false;

    int64_t gid = 0;
    if (!ParseId(fields[2], gid)) return false;
    if (fields[0].empty()) return false;

    row.name = std::string{fields[0]};
    row.gid  = gid;
    row.members.clear();
    if (!fields[3].empty()) {
        for (const auto member : SplitFields(fields[3], ',')) {
            if (!member.empty()) row.members.emplace_back(member);
        }
    }
    return true;
}

namespace {

template <typename Row, typename Parser>
std::vector<Row> ScanRootfsAccountFile(pid_t pid, const char* rel_path, Parser parse)
{
    std::vector<Row> out;

    // ENOENT here is the distroless case; EACCES/ESRCH means the PID died or
    // the rootfs is unreadable — all yield the same empty (not error) result,
    // and the caller decides whether to retry with another PID.
    std::ifstream file{"/proc/" + std::to_string(pid) + "/root" + rel_path};
    if (!file) return out;

    std::string line;
    while (std::getline(file, line)) {
        Row row;
        if (parse(line, row)) out.push_back(std::move(row));
    }
    return out;
}

} // namespace

std::vector<UserBaselineRow> ScanContainerUsers(pid_t pid)
{
    return ScanRootfsAccountFile<UserBaselineRow>(pid, "/etc/passwd", ParsePasswdLine);
}

std::vector<GroupBaselineRow> ScanContainerGroups(pid_t pid)
{
    return ScanRootfsAccountFile<GroupBaselineRow>(pid, "/etc/group", ParseGroupLine);
}

} // namespace wazuh::container_baseline
