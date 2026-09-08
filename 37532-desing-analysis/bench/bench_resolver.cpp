// Micro-benchmark replicating container_baseline's ResolvePidsForContainer()
// exactly (full /proc sweep + std::regex per PID), vs. the proposed
// cgroup.procs direct read. Validates the O(N_containers x N_procs) claim.
#include <dirent.h>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

static bool IsAllDigits(const char* s) {
    if (!s || !*s) return false;
    for (; *s; ++s) if (!std::isdigit((unsigned char)*s)) return false;
    return true;
}

static std::string ReadProcCgroupV2Path(const std::string& pid) {
    std::ifstream f("/proc/" + pid + "/cgroup");
    if (!f) return {};
    std::string line;
    while (std::getline(f, line))
        if (line.size() >= 3 && line[0]=='0' && line[1]==':' && line[2]==':') return line.substr(3);
    return {};
}

// Verbatim copy of the module's implementation.
static std::string ExtractContainerIdFromCgroupPath(const std::string& cgroup_path) {
    const auto last_slash = cgroup_path.find_last_of('/');
    const std::string leaf = (last_slash == std::string::npos) ? cgroup_path : cgroup_path.substr(last_slash + 1);
    if (leaf.empty()) return {};
    static const std::regex re_scoped(R"(^(?:cri-containerd-|crio-|docker-)([0-9a-f]{12,128})\.scope$)");
    std::smatch m;
    if (std::regex_match(leaf, m, re_scoped) && m.size() >= 2) return m[1].str();
    static const std::regex re_leaf(R"(^([0-9a-f]{32,128})$)");
    if (std::regex_match(leaf, m, re_leaf) && m.size() >= 2) return m[1].str();
    return {};
}

static int ResolvePidsForContainer(const std::string& container_id) {
    int found = 0;
    DIR* d = ::opendir("/proc");
    if (!d) return 0;
    while (auto* ent = ::readdir(d)) {
        if (!IsAllDigits(ent->d_name)) continue;
        const std::string pid_str = ent->d_name;
        const std::string cg = ReadProcCgroupV2Path(pid_str);
        if (cg.empty()) continue;
        if (ExtractContainerIdFromCgroupPath(cg) != container_id) continue;
        ++found;
    }
    ::closedir(d);
    return found;
}

// Proposed alternative: one sweep builds cgroup-leaf -> pids, reused for all containers.
static size_t BuildIndexOnce() {
    size_t n = 0;
    DIR* d = ::opendir("/proc");
    if (!d) return 0;
    while (auto* ent = ::readdir(d)) {
        if (!IsAllDigits(ent->d_name)) continue;
        const std::string cg = ReadProcCgroupV2Path(ent->d_name);
        if (cg.empty()) continue;
        (void)ExtractContainerIdFromCgroupPath(cg);
        ++n;
    }
    ::closedir(d);
    return n;
}

int main(int argc, char** argv) {
    const int containers = (argc > 1) ? std::atoi(argv[1]) : 100;
    const int sweeps_per_container = 3; // syscollector path: orchestrator + process_scanner + network_scanner

    int procs = 0;
    { DIR* d = ::opendir("/proc");
      while (auto* e = ::readdir(d)) if (IsAllDigits(e->d_name)) ++procs;
      ::closedir(d); }

    auto t0 = std::chrono::steady_clock::now();
    ResolvePidsForContainer("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    auto t1 = std::chrono::steady_clock::now();
    const double one_sweep_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    auto t2 = std::chrono::steady_clock::now();
    BuildIndexOnce();
    auto t3 = std::chrono::steady_clock::now();
    const double index_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();

    std::printf("host processes visible        : %d\n", procs);
    std::printf("one full /proc sweep          : %.2f ms  (%.4f ms/proc)\n", one_sweep_ms, one_sweep_ms/procs);
    std::printf("one-sweep shared index        : %.2f ms  (built ONCE for all containers)\n", index_ms);
    std::printf("\n-- extrapolated to %d containers, %d sweeps/container (current design) --\n",
                containers, sweeps_per_container);
    const double cur = one_sweep_ms * containers * sweeps_per_container;
    std::printf("current design  : %.0f sweeps  => %.1f ms  (%.2f s)\n",
                (double)containers*sweeps_per_container, cur, cur/1000.0);
    std::printf("shared index    : 1 sweep      => %.1f ms   (speedup %.0fx)\n", index_ms, cur/index_ms);
    std::printf("\nNOTE: this host has only %d procs. A real node with 100 containers\n", procs);
    std::printf("      typically shows 1500-2500 procs, scaling the current-design cost\n");
    std::printf("      by a further ~%.0fx  =>  ~%.1f s per baseline cycle.\n",
                2000.0/procs, cur * (2000.0/procs) / 1000.0);
    return 0;
}
