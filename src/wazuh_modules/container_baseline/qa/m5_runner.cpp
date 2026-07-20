/* Throw-away spike harness for #37532 remaining collectors (OS identity +
 * network interfaces/addresses baseline).
 *
 * Same shape as m4_runner: a tiny runner around the real scanner code, no
 * mocks. Takes a container id, resolves a live PID exactly like
 * RunSyscollectorBaseline() does (pid_resolver), then runs the real scanners
 * and prints each row as
 *
 *     <row-id> | <index> | <json>
 *
 * — the same triple the RowSink hands to the sync protocol. The container-
 * connector IPC lookup is deliberately skipped (identity fields stay empty):
 * that seam is already proven in the process/network evidence; this harness
 * isolates the OS and interface data classes.
 *
 * Build (from src/wazuh_modules/container_baseline):
 *   g++ -std=c++17 -Icontainer_baseline_impl/include \
 *       -I../../data_provider/src -I../../data_provider/src/packages \
 *       -I../../shared_modules/utils -I../../external/nlohmann \
 *       -I../../external/libdb/build_unix -I../../external/sqlite \
 *       qa/m5_runner.cpp container_baseline_impl/src/{os_scanner,interface_scanner,pid_resolver,baseline_rows}.cpp \
 *       -lpthread -ldl -o m5_runner
 *
 * Usage:  m5_runner <container-id> [os|interfaces|networks|all]
 */

#include "baseline_rows.hpp"
#include "interface_scanner.hpp"
#include "os_scanner.hpp"
#include "pid_resolver.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv)
{
    using namespace wazuh::container_baseline;

    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <container-id> [os|interfaces|networks|all]\n", argv[0]);
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

    size_t os_rows = 0, ifaces = 0, addrs = 0;

    if (what == "all" || what == "os") {
        for (auto row : ScanContainerOs(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildOsJson(row);
            std::printf("%s | wazuh-states-inventory-system | %s\n", id.c_str(), json.c_str());
            ++os_rows;
        }
    }

    if (what != "os") {
        const auto scan = ScanContainerInterfaces(pid);
        if (what == "all" || what == "interfaces") {
            for (auto row : scan.interfaces) {
                ApplyIdentity(row, identity);
                const auto [id, json] = BuildInterfaceJson(row);
                std::printf("%s | wazuh-states-inventory-interfaces | %s\n", id.c_str(), json.c_str());
                ++ifaces;
            }
        }
        if (what == "all" || what == "networks") {
            for (auto row : scan.addresses) {
                ApplyIdentity(row, identity);
                const auto [id, json] = BuildNetworkAddressJson(row);
                std::printf("%s | wazuh-states-inventory-networks | %s\n", id.c_str(), json.c_str());
                ++addrs;
            }
        }
    }

    std::fprintf(stderr, "summary: %zu os, %zu interfaces, %zu addresses\n", os_rows, ifaces, addrs);
    return 0;
}
