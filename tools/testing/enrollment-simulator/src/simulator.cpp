#include "simulator.h"
#include "network_utils.h"
#include "csv_exporter.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <cerrno>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

WazuhAuthSimulator::WazuhAuthSimulator(const std::string& host_addr, int port_num,
                                      const std::string& password)
    : host(host_addr), port(port_num), correct_password(password),
      progress_counter(0), gen(std::random_device{}()),
      dis_ratio(0.0, 1.0), dis_char(0, 35), dis_group(0, groups.size() - 1) {

    // Initialize OpenSSL (OpenSSL 1.1.0+ auto-initializes, but we keep for compatibility)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    // Create SSL context
    const SSL_METHOD* method = TLS_client_method();
    ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Don't verify certificates (for testing)
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);

    // Resolve hostname once at initialization
    if (!resolve_hostname()) {
        std::cerr << "Failed to resolve hostname: " << host << std::endl;
        exit(EXIT_FAILURE);
    }
}

WazuhAuthSimulator::~WazuhAuthSimulator() {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
}

bool WazuhAuthSimulator::resolve_hostname() {
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Try to interpret as IP address first
    if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) > 0) {
        return true;  // It's already an IP address
    }

    // If not an IP, resolve hostname using getaddrinfo (thread-safe)
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai_result = getaddrinfo(host.c_str(), nullptr, &hints, &res);

    if (gai_result != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(gai_result) << std::endl;
        return false;
    }

    // Copy only the IP address, preserve the port we already set
    struct sockaddr_in* addr_in = (struct sockaddr_in*)res->ai_addr;
    server_addr.sin_addr = addr_in->sin_addr;
    // server_addr.sin_port already set correctly above
    freeaddrinfo(res);

    // Print resolved address
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    std::cout << "Resolved " << host << " to " << ip_str << std::endl;

    return true;
}

std::string WazuhAuthSimulator::generate_random_name(int length) {
    std::string name;
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < length; ++i) {
        name += charset[dis_char(gen)];
    }
    return name;
}

std::string WazuhAuthSimulator::generate_agent_name(bool is_new) {
    std::lock_guard<std::mutex> lock(mutex);

    if (is_new || registered_agents.empty()) {
        std::string name = generate_random_name();
        registered_agents.insert(name);
        return name;
    } else {
        auto it = registered_agents.begin();
        std::advance(it, std::uniform_int_distribution<>(0, registered_agents.size() - 1)(gen));
        return *it;
    }
}

AgentConfig WazuhAuthSimulator::create_agent_config(double new_ratio, double incorrect_pass_ratio,
                                                   double modern_version_ratio, double group_ratio) {
    AgentConfig config;

    config.is_new = dis_ratio(gen) < new_ratio;
    config.name = generate_agent_name(config.is_new);

    config.has_correct_password = dis_ratio(gen) >= incorrect_pass_ratio;
    config.password = config.has_correct_password ? correct_password : "wrongpass";

    config.is_modern_version = dis_ratio(gen) < modern_version_ratio;
    config.version = config.is_modern_version ? "v4.15.0" : "v4.12.0";

    config.has_group = dis_ratio(gen) < group_ratio;
    if (config.has_group) {
        config.group = groups[dis_group(gen)];
    }

    return config;
}

std::string WazuhAuthSimulator::build_request(const AgentConfig& config) {
    std::stringstream ss;
    ss << "OSSEC PASS: " << config.password
       << " OSSEC A:'" << config.name
       << "' V:'" << config.version << "'";

    if (config.has_group) {
        ss << " G:'" << config.group << "'";
    }
    ss << "\n";

    return ss.str();
}

bool WazuhAuthSimulator::parse_response(const std::string& response) {
    return response.find("OSSEC K:") == 0;
}

RegistrationResult WazuhAuthSimulator::register_agent(const AgentConfig& config, const DelayRange& connect_delay,
                                                     const DelayRange& send_delay) {
    auto start = std::chrono::high_resolution_clock::now();
    RegistrationResult result;
    result.config = config;
    result.success = false;

    // Get random delays for this connection
    int actual_connect_delay = connect_delay.get_random_value(gen);
    int actual_send_delay = send_delay.get_random_value(gen);

    // Create socket with RAII management
    SocketRAII sock(AF_INET, SOCK_STREAM, 0);
    if (!sock.valid()) {
        result.response = "ERROR: Failed to create socket";
        result.response_time = calculate_elapsed_time(start);
        return result;
    }

    // Set socket options to prevent SIGPIPE on socket operations
    #ifdef SO_NOSIGPIPE
    int set = 1;
    setsockopt(sock.get(), SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
    #endif

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = SSL_CONNECT_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(sock.get(), SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(sock.get(), SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    // Connect to server using pre-resolved address
    if (connect(sock.get(), (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        result.response = "ERROR: Failed to connect to server";
        result.response_time = calculate_elapsed_time(start);
        return result;
    }

    // Delay before TLS handshake
    if (actual_connect_delay > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(actual_connect_delay));
    }

    // Create SSL connection with RAII management
    SSLRAII ssl(ssl_ctx);
    if (!ssl.valid()) {
        result.response = "ERROR: Failed to create SSL context";
        result.response_time = calculate_elapsed_time(start);
        return result;
    }

    SSL_set_fd(ssl.get(), sock.get());

    if (SSL_connect(ssl.get()) <= 0) {
        result.response = "ERROR: SSL handshake failed";
        result.response_time = calculate_elapsed_time(start);
        return result;
    }

    // Delay before sending request
    if (actual_send_delay > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(actual_send_delay));
    }

    // Send request
    std::string request = build_request(config);
    int write_result = SSL_write(ssl.get(), request.c_str(), request.length());
    if (write_result <= 0) {
        int ssl_error = SSL_get_error(ssl.get(), write_result);
        if (ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL) {
            result.response = "ERROR: Connection closed during write";
        } else {
            result.response = "ERROR: Failed to send request";
        }
        result.response_time = calculate_elapsed_time(start);
        return result;
    }

    // Receive response
    char buffer[BUFFER_SIZE] = {0};
    int bytes = SSL_read(ssl.get(), buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        result.response = std::string(buffer, bytes);
        result.success = parse_response(result.response);
    } else if (bytes == 0) {
        result.response = "ERROR: Connection closed by server";
    } else {
        int ssl_error = SSL_get_error(ssl.get(), bytes);
        if (ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL) {
            result.response = "ERROR: Connection closed during read";
        } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            result.response = "ERROR: SSL connection closed";
        } else {
            result.response = "ERROR: Failed to receive response";
        }
    }

    // RAII will automatically clean up SSL and socket
    result.response_time = calculate_elapsed_time(start);

    return result;
}

void WazuhAuthSimulator::worker(int num_registrations, double new_ratio, double incorrect_pass_ratio,
                               double modern_version_ratio, double group_ratio,
                               const DelayRange& connect_delay, const DelayRange& send_delay) {

    for (int i = 0; i < num_registrations; ++i) {
        if (stop_simulation) break;

        AgentConfig config = create_agent_config(new_ratio, incorrect_pass_ratio,
                                                modern_version_ratio, group_ratio);
        RegistrationResult result = register_agent(config, connect_delay, send_delay);

        stats_manager.add_result(result);

        // Update progress
        int count = ++progress_counter;
        if (count % PROGRESS_INTERVAL == 0) {
            std::cout << "  Progress: " << count << " registrations completed...\r" << std::flush;
        }
    }
}

void WazuhAuthSimulator::run_simulation(int num_threads, int total_registrations, double new_ratio,
                                       double incorrect_pass_ratio, double modern_version_ratio,
                                       double group_ratio, const DelayRange& connect_delay,
                                       const DelayRange& send_delay, const std::string& csv_file) {

    std::cout << "Starting simulation with " << num_threads << " threads..." << std::endl;
    std::cout << "Total registrations: " << total_registrations << std::endl;
    std::cout << "Target server: " << host << ":" << port << std::endl;
    std::cout << "Connect delay: " << connect_delay.to_string() << " ms" << std::endl;
    std::cout << "Send delay: " << send_delay.to_string() << " ms" << std::endl;
    if (!csv_file.empty()) {
        std::cout << "CSV output: " << csv_file << std::endl;
    }
    std::cout << "Press Ctrl+C to stop early and see partial results" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    // Calculate registrations per thread
    int per_thread = total_registrations / num_threads;
    int remainder = total_registrations % num_threads;

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        int thread_registrations = per_thread + (i < remainder ? 1 : 0);
        threads.emplace_back(&WazuhAuthSimulator::worker, this,
                           thread_registrations, new_ratio, incorrect_pass_ratio,
                           modern_version_ratio, group_ratio, connect_delay, send_delay);
    }

    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    double total_time = std::chrono::duration<double>(end_time - start_time).count();

    // Clear progress line
    std::cout << std::string(80, ' ') << "\r";

    stats_manager.print_statistics(total_time, total_registrations);

    // Write CSV if requested
    if (!csv_file.empty()) {
        CSVExporter::write_csv_results(stats_manager.get_results(), csv_file, total_time, total_registrations);
    }
}
