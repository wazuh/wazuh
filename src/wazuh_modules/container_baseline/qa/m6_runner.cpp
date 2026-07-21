/* Throw-away spike harness for #37532 remaining collectors round 2 (protocols +
 * services + virtual hardware), driven by the #37532 review: replicate what host
 * syscollector collects, but from the container.
 *
 * Same shape as m5_runner: a tiny runner around the real scanner code, no mocks.
 * Resolves a live PID exactly like RunSyscollectorBaseline() (pid_resolver), runs
 * the real scanners, prints each row as
 *
 *     <row-id> | <index> | <json>
 *
 * Build (from src/wazuh_modules/container_baseline):
 *   g++ -std=c++17 -Icontainer_baseline_impl/include \
 *       -I../../data_provider/src -I../../data_provider/src/packages \
 *       -I../../shared_modules/utils -I../../external/nlohmann \
 *       -I../../external/libdb/build_unix -I../../external/sqlite \
 *       qa/m6_runner.cpp \
 *       container_baseline_impl/src/{protocol_scanner,service_scanner,hardware_scanner,pid_resolver,baseline_rows}.cpp \
 *       -lpthread -ldl -o m6_runner
 *
 * Usage:  m6_runner <container-id> [protocols|services|hardware|all]
 */

#include "baseline_rows.hpp"
#include "hardware_scanner.hpp"
#include "pid_resolver.hpp"
#include "protocol_scanner.hpp"
#include "service_scanner.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv)
{
    using namespace wazuh::container_baseline;

    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <container-id> [protocols|services|hardware|all]\n", argv[0]);
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

    size_t protos = 0, svcs = 0, hws = 0;

    if (what == "all" || what == "protocols") {
        for (auto row : ScanContainerProtocols(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildProtocolJson(row);
            std::printf("%s | wazuh-states-inventory-protocols | %s\n", id.c_str(), json.c_str());
            ++protos;
        }
    }

    if (what == "all" || what == "services") {
        for (auto row : ScanContainerServices(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildServiceJson(row);
            std::printf("%s | wazuh-states-inventory-services | %s\n", id.c_str(), json.c_str());
            ++svcs;
        }
    }

    if (what == "all" || what == "hardware") {
        for (auto row : ScanContainerHardware(pid)) {
            ApplyIdentity(row, identity);
            const auto [id, json] = BuildHardwareJson(row);
            std::printf("%s | wazuh-states-inventory-hardware | %s\n", id.c_str(), json.c_str());
            ++hws;
        }
    }

    std::fprintf(stderr, "summary: %zu protocols, %zu services, %zu hardware\n", protos, svcs, hws);
    return 0;
}
