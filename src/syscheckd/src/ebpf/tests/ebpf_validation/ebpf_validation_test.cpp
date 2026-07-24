#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace fs = std::filesystem;

constexpr int TASK_COMM_LEN = 32;
constexpr int MAX_PATH_LEN = 4096;
constexpr std::string_view LSM_LIST_FILE = "/sys/kernel/security/lsm";
constexpr std::string_view DEFAULT_BPF_OBJ = "/var/ossec/lib/modern.bpf.o";
constexpr int POLL_TIMEOUT_MS = 100;
constexpr int SETTLE_US = 150000;
constexpr int INIT_SETTLE_US = 300000;
constexpr int EXTRA_POLLS = 5;
constexpr size_t MIN_EXPECTED_EVENTS = 3;
/* Distinct non-root credentials for the trigger process: with uid == gid
 * (e.g. root) a uid/gid swap on the BPF side would go unnoticed. */
constexpr uid_t TEST_UID = 1234;
constexpr gid_t TEST_GID = 4321;

// Must match modern.bpf.c layout
struct file_event {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint64_t inode;
    uint64_t dev;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char cwd[MAX_PATH_LEN];
    char parent_cwd[MAX_PATH_LEN];
    char parent_name[TASK_COMM_LEN];
};

struct test_context {
    std::vector<file_event> events;
    std::string target_path;
    std::string target_name;
    bool use_lsm = false;
    bool is_btrfs = false;
    bool abi_mismatch = false;
    int pass = 0;
    int fail = 0;
    int warn = 0;
};

static test_context g_ctx;

static bool is_bpf_lsm_active() {
    std::ifstream f{std::string{LSM_LIST_FILE}};
    if (!f) return false;
    std::string line;
    if (!std::getline(f, line)) return false;
    std::istringstream ss{line};
    for (std::string tok; std::getline(ss, tok, ',');) {
        if (tok == "bpf") return true;
    }
    return false;
}

static bool bpf_link_is_err(const struct bpf_link *l) {
    return !l || reinterpret_cast<uintptr_t>(l) >= static_cast<uintptr_t>(-4095UL);
}

static int on_event(void *, void *data, size_t sz) {
    /* Fail loudly on layout drift between this struct and modern.bpf.c
     * (e.g. fields added to file_event) instead of parsing misaligned data. */
    if (sz != sizeof(file_event)) {
        if (!g_ctx.abi_mismatch) {
            g_ctx.abi_mismatch = true;
            std::cerr << "[FAIL] Event size mismatch: BPF object sends " << sz
                      << " bytes, test expects " << sizeof(file_event)
                      << ". Update struct file_event to match modern.bpf.c\n";
        }
        return 0;
    }
    const auto *e = static_cast<const file_event *>(data);
    /* Match by basename: hooks that reconstruct the path relative to the
     * filesystem root (instead of the mount namespace) must still be
     * captured so the path mismatch is reported instead of hidden. */
    if (std::string_view{e->filename}.find(g_ctx.target_name) != std::string_view::npos)
        g_ctx.events.push_back(*e);
    return 0;
}

static bool check(std::string_view name, bool ok, std::string_view detail = {}) {
    if (ok) {
        std::cout << "  [PASS] " << name << '\n';
        g_ctx.pass++;
    } else {
        std::cerr << "  [FAIL] " << name;
        if (!detail.empty()) std::cerr << " (" << detail << ')';
        std::cerr << '\n';
        g_ctx.fail++;
    }
    return ok;
}

static void warn(std::string_view name, std::string_view detail) {
    std::cout << "  [WARN] " << name << " (" << detail << ")\n";
    g_ctx.warn++;
}

static bool validate_event(const file_event &e, pid_t child, pid_t parent,
                           uid_t uid, gid_t gid, uint64_t dev,
                           std::string_view comm, std::string_view cwd) {
    auto m = [](std::string_view f, auto exp, auto got) {
        return std::string{f} + ": expected " + std::to_string(exp) + " got " + std::to_string(got);
    };
    bool ok = true;

    /* Known limitation: on non-root mounts, some hooks report the path
     * relative to the filesystem root instead of the mount namespace.
     * This affects the kprobe path walkers and, on recent kernels, the
     * lsm/path_unlink bpf_d_path variant. lsm/file_open (bpf_d_path)
     * resolves the full mount-namespace path correctly. */
    const std::string fs_relative = "/" + g_ctx.target_name;
    if (g_ctx.target_path == e.filename) {
        check("path", true);
    } else if (fs_relative == e.filename) {
        warn("path", std::string{"hook reports fs-relative path (no mount prefix): got '"} +
                     e.filename + "' expected '" + g_ctx.target_path + "'");
    } else {
        ok &= check("path", false,
                    std::string{"expected '"} + g_ctx.target_path + "' got '" + e.filename + "'");
    }

    ok &= check("PID",  e.pid  == static_cast<uint32_t>(child),  m("pid",  child,  e.pid));
    ok &= check("PPID", e.ppid == static_cast<uint32_t>(parent), m("ppid", parent, e.ppid));
    ok &= check("UID",  e.uid  == uid, m("uid", uid, e.uid));
    ok &= check("GID",  e.gid  == gid, m("gid", gid, e.gid));
    ok &= check("comm", comm == e.comm,
                std::string{"expected '"} + std::string{comm} + "' got '" + e.comm + "'");
    ok &= check("parent_name", comm == e.parent_name,
                std::string{"expected '"} + std::string{comm} + "' got '" + e.parent_name + "'");
    ok &= check("cwd", cwd == e.cwd,
                std::string{"expected '"} + std::string{cwd} + "' got '" + e.cwd + "'");
    /* Known btrfs semantics: stat() returns the per-subvolume anonymous
     * device while the BPF side reports the superblock device. */
    if (e.dev == dev) {
        check("dev", true);
    } else if (g_ctx.is_btrfs) {
        warn("dev", m("btrfs superblock dev differs from subvolume dev", dev, e.dev));
    } else {
        ok &= check("dev", false, m("dev", dev, e.dev));
    }

    ok &= check("inode", e.inode != 0,   "got 0");
    return ok;
}

// Mirrors select_programs from ebpf_whodata.cpp
static struct bpf_object *load_bpf(const fs::path &obj_path, bool use_lsm) {
    bool prefer_dpath = use_lsm;

    for (;;) {
        auto *obj = bpf_object__open_file(obj_path.c_str(), nullptr);
        if (!obj) {
            std::cerr << "[ERROR] Cannot open " << obj_path << ": " << std::strerror(errno) << '\n';
            return nullptr;
        }

        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj) {
            auto sec = bpf_program__section_name(prog);
            auto name = bpf_program__name(prog);
            if (!sec) continue;

            std::string_view sv_sec{sec};
            std::string_view sv_name{name ? name : ""};
            bool is_lsm = sv_sec.substr(0, 4) == "lsm/";
            bool is_kp_create_unlink = sv_sec.substr(0, 7) == "kprobe/" &&
                (sv_sec.find("vfs_open") != sv_sec.npos || sv_sec.find("vfs_unlink") != sv_sec.npos ||
                 sv_sec.find("vfs_rename") != sv_sec.npos);

            bool keep = true;
            if (use_lsm) {
                if (is_kp_create_unlink) keep = false;
                else if (is_lsm && sv_name.find("_dpath") != sv_name.npos && !prefer_dpath) keep = false;
                else if (is_lsm && sv_name.find("_walk")  != sv_name.npos &&  prefer_dpath) keep = false;
            } else {
                if (is_lsm) keep = false;
            }
            bpf_program__set_autoload(prog, keep);
        }

        if (bpf_object__load(obj) == 0) return obj;
        bpf_object__close(obj);

        if (use_lsm && prefer_dpath) {
            std::cout << "[*] Fallback: retrying without _dpath...\n";
            prefer_dpath = false;
            continue;
        }
        std::cerr << "[ERROR] Failed to load BPF object\n";
        return nullptr;
    }
}

static void drain(struct ring_buffer *rb, pid_t child) {
    bool exited = false;
    int remaining = EXTRA_POLLS;
    int status;

    for (;;) {
        ring_buffer__poll(rb, POLL_TIMEOUT_MS);
        if (!exited) {
            if (waitpid(child, &status, WNOHANG) == child) exited = true;
        } else if (--remaining <= 0) {
            break;
        }
    }
}

int main(int argc, char **argv) {
    fs::path bpf_obj{std::string{DEFAULT_BPF_OBJ}};
    fs::path test_dir = "/tmp/ebpf_validation_test";

    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg == "--bpf-obj" && i + 1 < argc) bpf_obj = argv[++i];
        else if (arg == "--test-dir" && i + 1 < argc) test_dir = argv[++i];
        else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [--bpf-obj <path>] [--test-dir <path>]\n";
            return 0;
        }
    }

    if (getuid() != 0) {
        std::cerr << "[ERROR] Must run as root.\n";
        return 1;
    }

    if (!fs::exists(bpf_obj)) {
        std::cerr << "[ERROR] BPF object not found: " << bpf_obj << '\n';
        return 1;
    }

    const bool use_lsm = is_bpf_lsm_active();
    g_ctx.use_lsm = use_lsm;
    std::cout << "[*] Hook mode: " << (use_lsm ? "LSM" : "Kprobes") << '\n';
    std::cout << "[*] BPF object: " << bpf_obj.string() << '\n';
    std::cout << "[*] Test dir:   " << test_dir.string() << '\n';

    fs::create_directories(test_dir);
    /* The trigger child runs as TEST_UID:TEST_GID, so the directory must be
     * writable by non-root (loop mounts are root-owned by default). */
    fs::permissions(test_dir, fs::perms::all, fs::perm_options::replace);
    const auto resolved = fs::canonical(test_dir);
    g_ctx.target_name = "ebpf_test_file.txt";
    g_ctx.target_path = (resolved / g_ctx.target_name).string();
    fs::remove(g_ctx.target_path);

    struct statfs sfs{};
    g_ctx.is_btrfs = (statfs(test_dir.c_str(), &sfs) == 0 &&
                      static_cast<uint64_t>(sfs.f_type) == 0x9123683E /* BTRFS_SUPER_MAGIC */);

    auto *obj = load_bpf(bpf_obj, use_lsm);
    if (!obj) return 1;

    std::vector<struct bpf_link *> links;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__autoload(prog)) continue;
        auto *link = bpf_program__attach(prog);
        if (bpf_link_is_err(link)) {
            std::cerr << "[ERROR] Attach failed: " << bpf_program__name(prog) << '\n';
            for (auto *l : links) bpf_link__destroy(l);
            bpf_object__close(obj);
            return 1;
        }
        links.push_back(link);
    }

    int rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        std::cerr << "[ERROR] Ring buffer map not found\n";
        for (auto *l : links) bpf_link__destroy(l);
        bpf_object__close(obj);
        return 1;
    }

    auto *rb = ring_buffer__new(rb_fd, on_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "[ERROR] Failed to create ring buffer\n";
        for (auto *l : links) bpf_link__destroy(l);
        bpf_object__close(obj);
        return 1;
    }

    const pid_t parent_pid = getpid();
    char parent_comm[TASK_COMM_LEN]{};
    if (std::ifstream f{"/proc/self/comm"}; f) f.getline(parent_comm, sizeof(parent_comm));

    const pid_t child_pid = fork();
    if (child_pid < 0) {
        std::cerr << "[ERROR] Fork failed\n";
        ring_buffer__free(rb);
        for (auto *l : links) bpf_link__destroy(l);
        bpf_object__close(obj);
        return 1;
    }

    if (child_pid == 0) {
        const auto &path = g_ctx.target_path;
        usleep(INIT_SETTLE_US);

        /* Drop to distinct non-root credentials so uid/gid validation is
         * meaningful (a uid/gid swap is invisible when uid == gid == 0). */
        if (setgroups(0, nullptr) != 0 || setgid(TEST_GID) != 0 || setuid(TEST_UID) != 0) {
            perror("drop privileges");
            _exit(1);
        }

        int fd = open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (fd < 0) { perror("open"); _exit(1); }
        if (write(fd, "test\n", 5) != 5) { perror("write"); close(fd); _exit(1); }
        close(fd);
        usleep(SETTLE_US);

        if (chmod(path.c_str(), 0644) != 0) { perror("chmod"); _exit(1); }
        usleep(SETTLE_US);

        if (chown(path.c_str(), getuid(), getgid()) != 0) { perror("chown"); _exit(1); }
        usleep(SETTLE_US);

        if (truncate(path.c_str(), 0) != 0) { perror("truncate"); _exit(1); }
        usleep(SETTLE_US);

        if (unlink(path.c_str()) != 0) { perror("unlink"); _exit(1); }
        usleep(SETTLE_US);

        _exit(0);
    }

    drain(rb, child_pid);

    ring_buffer__free(rb);
    for (auto *l : links) bpf_link__destroy(l);
    bpf_object__close(obj);

    /* The BPF side reports the kernel-internal dev_t encoding
     * (major << 20 | minor), not the userspace stat encoding. */
    struct stat dir_stat{};
    uint64_t expected_dev = 0;
    if (stat(test_dir.c_str(), &dir_stat) == 0)
        expected_dev = (static_cast<uint64_t>(major(dir_stat.st_dev)) << 20) | minor(dir_stat.st_dev);
    const auto expected_cwd = fs::current_path().string();

    std::cout << "\n[*] Events caught: " << g_ctx.events.size() << '\n';

    bool failed = false;
    for (size_t i = 0; i < g_ctx.events.size(); ++i) {
        std::cout << "\n[Event #" << i + 1 << "] " << g_ctx.events[i].filename << '\n';
        if (!validate_event(g_ctx.events[i], child_pid, parent_pid,
                           TEST_UID, TEST_GID, expected_dev,
                           parent_comm, expected_cwd))
            failed = true;
    }

    std::cout << "\n================ SUMMARY ================\n\n";
    check("Minimum " + std::to_string(MIN_EXPECTED_EVENTS) + " events (create + modify + delete)",
          g_ctx.events.size() >= MIN_EXPECTED_EVENTS,
          "got " + std::to_string(g_ctx.events.size()));

    if (g_ctx.abi_mismatch) failed = true;
    if (g_ctx.events.empty()) failed = true;

    std::cout << "\nTotal: " << g_ctx.pass << " passed, " << g_ctx.fail << " failed, "
              << g_ctx.warn << " warnings (known limitations)\n";

    if (failed || g_ctx.events.size() < MIN_EXPECTED_EVENTS) {
        std::cerr << "\n[RESULT] FAILED\n";
        return 1;
    }
    std::cout << "\n[RESULT] PASSED\n";
    return 0;
}
