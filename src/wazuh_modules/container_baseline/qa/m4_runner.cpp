/* Throw-away spike harness for #37532 M4 (users/groups + packages baseline).
 *
 * Mirrors the ipc-test-evidence.md approach: a tiny runner around the real
 * scanner code, no mocks. Takes a container id, resolves a live PID exactly
 * like RunSyscollectorBaseline() does (pid_resolver), then runs the real M4
 * scanners against /proc/<pid>/root and prints each row as
 *
 *     <row-id> | <index> | <json>
 *
 * — the same triple the RowSink hands to the sync protocol. The container-
 * connector IPC lookup is deliberately skipped (identity fields stay empty):
 * that seam is already proven in the process/network evidence; this harness
 * isolates the M4 data classes.
 *
 * Build (from src/wazuh_modules/container_baseline):
 *   g++ -std=c++17 -Icontainer_baseline_impl/include \
 *       -I../../data_provider/src -I../../data_provider/src/packages \
 *       -I../../shared_modules/utils -I../../external/nlohmann \
 *       -I../../external/libdb/build_unix -I../../external/sqlite \
 *       qa/m4_runner.cpp container_baseline_impl/src/{user_scanner,package_scanner,pid_resolver,baseline_rows}.cpp \
 *       ../../external/libdb/build_unix/libdb.a ../../external/sqlite/libsqlite3.a \
 *       -lpthread -ldl -o m4_runner
 *
 * Usage:  m4_runner <container-id> [users|groups|packages|all]
 */

#include "baseline_rows.hpp"
#include "package_scanner.hpp"
#include "pid_resolver.hpp"
#include "user_scanner.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv)
{
    using namespace wazuh::container_baseline;

    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <container-id> [users|groups|packages|all]\n", argv[0]);
        return 1;
    }

    const std::string container_id = argv[1];
    const std::string what = (argc > 2) ? argv[2] : "all";

    const auto pids = ResolvePidsForContainer(container_id);
    if (pids.empty()) {
        std::fprintf(stderr, "no live PID found for container '%s'\n", container_id.c_str());
        return 2;
    }
    const auto pid = pids.front();
    std::fprintf(stderr, "container %s -> pid %d (%zu candidate PIDs)\n", container_id.c_str(),
                 static_cast<int>(pid), pids.size());

    ContainerIdentity identity;
    identity.container_id = container_id;

    size_t users = 0, groups = 0, packages = 0;

    if (what == "all" || what == "users") {
        for (auto row : ScanContainerUsers(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildUserJson(row);
            std::printf("%s | wazuh-states-inventory-users | %s\n", id.c_str(), json.c_str());
            ++users;
        }
    }
    if (what == "all" || what == "groups") {
        for (auto row : ScanContainerGroups(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildGroupJson(row);
            std::printf("%s | wazuh-states-inventory-groups | %s\n", id.c_str(), json.c_str());
            ++groups;
        }
    }
    if (what == "all" || what == "packages") {
        for (auto row : ScanContainerPackages(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildPackageJson(row);
            std::printf("%s | wazuh-states-inventory-packages | %s\n", id.c_str(), json.c_str());
            ++packages;
        }
    }

    std::fprintf(stderr, "summary: %zu users, %zu groups, %zu packages\n", users, groups, packages);
    return 0;
}
