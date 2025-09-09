#pragma once

#include "types.h"
#include "agent_config.h"
#include "statistics.h"

#include <string>
#include <vector>
#include <set>
#include <random>
#include <mutex>
#include <atomic>
#include <thread>
#include <netinet/in.h>
#include <openssl/ssl.h>

class WazuhAuthSimulator {
private:
    std::string host;
    int port;
    struct sockaddr_in server_addr;  // Pre-resolved address
    std::string correct_password;
    std::set<std::string> registered_agents;
    StatisticsManager stats_manager;
    std::mutex mutex;
    std::atomic<int> progress_counter;

    // Available groups
    std::vector<std::string> groups = {"default"};

    // Random number generators
    std::mt19937 gen;
    std::uniform_real_distribution<> dis_ratio;
    std::uniform_int_distribution<> dis_char;
    std::uniform_int_distribution<> dis_group;

    // SSL context
    SSL_CTX* ssl_ctx;

    // Private methods
    bool resolve_hostname();
    std::string generate_random_name(int length = 12);
    std::string generate_agent_name(bool is_new);
    AgentConfig create_agent_config(double new_ratio, double incorrect_pass_ratio,
                                   double modern_version_ratio, double group_ratio);
    std::string build_request(const AgentConfig& config);
    bool parse_response(const std::string& response);
    RegistrationResult register_agent(const AgentConfig& config, const DelayRange& connect_delay,
                                     const DelayRange& send_delay);
    void worker(int num_registrations, double new_ratio, double incorrect_pass_ratio,
                double modern_version_ratio, double group_ratio,
                const DelayRange& connect_delay, const DelayRange& send_delay);

public:
    WazuhAuthSimulator(const std::string& host_addr = "localhost", int port_num = 1515,
                      const std::string& password = "topsecret");
    ~WazuhAuthSimulator();

    void run_simulation(int num_threads, int total_registrations, double new_ratio,
                       double incorrect_pass_ratio, double modern_version_ratio,
                       double group_ratio, const DelayRange& connect_delay,
                       const DelayRange& send_delay, const std::string& csv_file = "");
};
